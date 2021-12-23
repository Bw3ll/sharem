from capstone import *
import re
import pefile
import sys
import binascii
import copy
import os
from collections import OrderedDict
from lists import *
import assemblyx86
from assemblyx86 import *
import win32api
import win32con
import ctypes
from ctypes import windll
from ctypes import wintypes
import win32file
from sorting import *
import timeit
import string
import csv
import json
import datetime
from selfModify import *
from ui import *
import colorama
from parseconf import Configuration
import ast
import argparse



colorama.init()
# readRegs()
# testingAssembly()


red ='\u001b[31;1m'
gre = '\u001b[32;1m'
yel = '\u001b[33;1m'
blu = '\u001b[34;1m'
mag = '\u001b[35;1m'
cya = '\u001b[36;1m'
whi = '\u001b[37m'
res = '\u001b[0m'

# print(red + "Hello there. I'm Tarek, testing colors.")
# print(gre + "Hello there. I'm Tarek, testing colors.")

# print(yel + "Hello there. I'm Tarek, testing colors.")
# print(blu + "Hello there. I'm Tarek, testing colors.")
# print(mag + "Hello there. I'm Tarek, testing colors.")
# print(cya + "Hello there. I'm Tarek, testing colors.")
# print(whi + "Hello there. I'm Tarek, testing colors.")
# print(res)
# input()



list_of_files = []
elapsed_time = 0
pebPresent = False
doneAlready1 = []
syscallString = ''
chMode = False
shellEntry = 0
tempDisassembly=[]
tempAddresses=[]
tempMnemonic=[]
tempOp_str=[]
sections = []
numArgs = len(sys.argv)
peName = ''
modName = peName
PEsList = []
PE_path =""
PEsList_Index = 0
skipZero = False
numPE = 1
skipPath = False
FoundApisAddress = []
FoundApisName = []
saveAPI=0x00
shellEntry=0
decodedBytes=b''
VP = 0
VA=""
MA=""
GPA=""
pe=""
MemCpyAddress=""
VPl = []
VAl=[]
GPAl=[]
MAl=[]
Remove=[]
badChars = ["zz"]
fname=""
entryPoint = 0 
VirtualAdd= 0 
ImageBase= 0 
vSize= 0 
startAddress= 0 
endAddy= 0 
o=0
t=0
sectionName=""
cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs64 = Cs(CS_ARCH_X86, CS_MODE_64)
directory =""
newpath =""
PEtemp=""
PE_DLL = []
PE_DLLS = []
PE_DLLS2 = []
paths=[]
DLL_Protect = []
bit32 = True
PE_Protect=""
index=0
CheckallModules = False
present=[]
new=[]
new2=[]
deeperLevel=[]
asciiMode="ascii"
stringsTemp=[]
stringsTempWide=[]
pushStringsTemp=[]
filename=""
filenameRaw=""
skipExtraction=False
rawHex = False
rawData2 = b''

numArgs = len(sys.argv)
rawBin=False  # only if .bin, not .txt
isPe=False
pointsLimit = 3
maxDistance = 15
gDisassemblyText=""
useStringsFile = False
mEAX = ''
mEBX = ''
mEDX = ''
mECX = ''
mEBP = ''
mESP = ''


gDisassemblyText=""
# Moved from Andy's work area
linesForward = 40
bUI = True
bPushRet = True
bFstenv = True
bSyscall = True
bHeaven = True
bEm = True
bCallPop = True
bPushRet = True
bHeaven = True
bUI= True
bCheck = True
bDisassembly = True
bPushRetFound = False
bDisassemblyFound = False
bFstenvFound = False
bSyscallFound = False
bHeavenFound = False
bPEBFound = False
bCallPopFound = False
bEvilImportsFound = False
bModulesFound = False
deobfShell = True
fastMode=False
pebPoints = 2
p2screen = True
configOptions = {}
print_style = "left"
stubFile = "stub.txt"
sameFile = True
stubEntry = 0
stubEnd = 0
ignoreDisDiscovery=False
conFile = "config.cfg" 
workDir = False
bit32_argparse = False
FindStringsStatus=True
save_bin_file = True
linesForward = 7
linesBack = 10
bytesForward = 15
bytesBack = 15
# FindStringsStatus=False


GoodStrings=["cmd",  "net","add", "win", "http", "dll", "sub", "calc"]
toggList = {'findString':True, 
			'deobfCode':False,
			'findShell':False,
			'comments':True}

brawHex = ''
bstrLit = ''
bfindString = True
bfindStringFound = False
bdeobfCode = False
bdeobfCodeFound = False

bfindShell = False
bfindShellFound = False
bComments = True
shellBit=32

#####SAME AS FROM SHAREM
filename=""

# if numArgs > 1:			# to get full functionality, need to put file location for binary that is installed (may need to find some DLLs in that directory)
# 	txtDoc= re.search( r'\.txt', sys.argv[1], re.M|re.I)
# 	binFile= re.search( r'\.bin', sys.argv[1], re.M|re.I)
# 	if binFile:
# 		# filenameRaw=sys.argv[1]
# 		filename=sys.argv[1]
# 	if txtDoc:
# 		filename= sys.argv[1]
# 		# filenameRaw=sys.argv[1]
# 		skipExtraction=True
# 		rawHex=True
# 		# print("set rawHEx")
# 		try: 
# 			if(re.match( "^r", sys.argv[2], re.M|re.I)):
# 				if(re.match( "(r32)|(raw32)|(raw)|(r$)", sys.argv[2], re.M|re.I)):
# 					bit32 = True
# 				if(re.match( "(r64)|(raw64)", sys.argv[2], re.M|re.I)):
# 					bit32 = False
# 		except Exception as e:
# 			print("Invalid path to hex file.")
# 			print(e)
# 			quit()
# 		# print("bits", bit32)
# 	# if binFile:
# 	# 	rawBin=True


# 	# if binFile:
# 	# 	rawHex = True
# 	# 	rawBin=True  # only if .bin, not .txt
# 	# 	print("set raw2", (sys.argv[2]), (sys.argv[1]), peName)
# 	# 	try:
# 	# 		f = open(peName, "rb")
# 	# 		# global rawData2
# 	# 		rawData2 = f.read()
# 	# 		f.close()
# 	# 		# print ("rawData2", len(rawData2))
# 	# 	except Exception as e:
# 	# 		print("Invalid path to hex file.")
# 	# 		print(e)
# 	# 		quit()
# # print("bits", bit32)

# if len(filename) > 1:
# 	testing=filename

# # print("NUMARGS")
# # print(numArgs)

# if numArgs==1:
# 	skipExtraction=True
# 	rawHex=True
# 	filename= sys.argv[1]
# 	print("numargs")
# if not skipExtraction:
# 	if numArgs > 1:			# to get full functionality, need to put file location for binary that is installed (may need to find some DLLs in that directory)
# 		peName= sys.argv[1] 
# 		matchObj = re.match( r'^[a-z]+:[\\|/]+', peName, re.M|re.I)
# 		if matchObj:
# 			isPe=True
# 			head, tail = os.path.split(peName)
# 			peName = tail
# 			PE_path = head
# 			skipPath = True
# 		if not matchObj:
# 			skipPath = False
# 		matchObj = re.match( r'^[a-z0-9]+.txt', peName, re.M|re.I)
# 		if matchObj:
# 			rawBin=False  # only if .bin, not .txt
# 			head, tail = os.path.split(peName)
# 			with open(tail, "r") as ins:
# 				for line in ins:
# 					line2 = line.rstrip('\n')
# 					PEsList.append(line2)
# 			peName = PEsList[0]
# 			# print "name"
# 			print (peName)
# 			head, tail = os.path.split(peName)
# 			peName = tail
# 			PE_path = head
# 			numPE = len(PEsList)
# 			skipPath = True
# 			# print PEsList
# 	PEtemp = PE_path + "/"+ peName

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--pe', '-pe', type=str)
group.add_argument('--r', '-r',type=str)
group.add_argument('-r64', '--r64',  type=str)
group.add_argument('-r32', '--r32',  type=str)
group.add_argument('--d', '-d', type=str, required=False)


parser.add_argument('--c', '-c', '--config', type=str, required=False)


args = parser.parse_args()
# print(args)
# print("Args ------> ", args)

if args.r or args.r64 or args.r32:
	if args.r:
		file2Check = args.r
		bit32 = True
		# bit32_argparse = True
		shellBit = 32
	if args.r32:
		file2Check = args.r32
		bit32 = True
		bit32_argparse = True
		shellBit = 32
		
	elif args.r64:
		# print("64 bit <---")
		file2Check = args.r64
		bit32 = False
		bit32_argparse = True
		shellBit = 64


	if os.path.isfile(file2Check):
		shellFile = os.path.basename(file2Check)
		if(len(shellFile) > 3):
			ext = shellFile[-3:]
			if ext == "txt":
				rawHex = True
				filename = file2Check

			else:
				f = open(file2Check, "rb")
				filename = file2Check
				rawData2 = f.read()
				f.close()
				rawHex = True
				rawBin = True

		print("Shellcode file: ", shellFile)
	else:
		print(args.r, "file doesn't exist")
		sys.exit()


if args.pe:
	if os.path.isfile(args.pe):

		peFile = os.path.basename(args.pe)
		peName = args.pe
		print("PE path is: ", args.pe)
		if win32file.GetBinaryType(args.pe) == 6:
			# print("64 bit file", args.pe)
			bit32 = False
		else:
			# print("32 bit")
			bit32 = True
	else:
		print(args.pe, "file doesn't exist")
		sys.exit()


if args.c:
	if os.path.isfile(args.c):
		conFile = args.c
		# conFile = os.path.basename(args.c)
		print("Config path is: ", conFile)
	else:
		print(args.c, "file doesn't exist")
		sys.exit()


if args.d:
	if os.path.isdir(args.d):

		workingDir = args.d
		workDir = True
		for path in os.listdir(workingDir):
			full_path = os.path.join(workingDir, path)
			if os.path.isfile(full_path):
				list_of_files.append(full_path)
		# list_of_files = os.listdir(workingDir)
		print("Directory path is: ", workingDir, list_of_files)

	else:
		print(args.d, "directory doesn't exist")
		sys.exit()


# print(peFile)
# print(args.pe, args.r, args.d, args.c)
# input()




# if numArgs > 1:			# to get full functionality, need to put file location for binary that is installed (may need to find some DLLs in that directory)
# 	txtDoc= re.search( r'\.txt', sys.argv[1], re.M|re.I)
# 	binFile= re.search( r'\.bin', sys.argv[1], re.M|re.I)
# 	if binFile:
# 		# filenameRaw=sys.argv[1]
# 		filename=sys.argv[1]
# 	if txtDoc:
# 		# print("txt------------>", txtDoc)
# 		# input()
# 		filename= sys.argv[1]
# 		# filenameRaw=sys.argv[1]
# 		skipExtraction=True
# 		rawHex=True
# 		# print("set rawHEx")
# 		try: 
# 			if(re.match( "^r", sys.argv[2], re.M|re.I)):
# 				if(re.match( "(r32)|(raw32)|(raw)|(r$)", sys.argv[2], re.M|re.I)):
# 					bit32 = True
# 				if(re.match( "(r64)|(raw64)", sys.argv[2], re.M|re.I)):
# 					bit32 = False
# 		except Exception as e:
# 			print("Invalid path to hex file.")
# 			print(e)
# 			quit()
# 		# print("bits", bit32)
# 	# if binFile:
# 	# 	rawBin=True


# 	# if binFile:
# 	# 	rawHex = True
# 	# 	rawBin=True  # only if .bin, not .txt
# 	# 	print("set raw2", (sys.argv[2]), (sys.argv[1]), peName)
# 	# 	try:
# 	# 		f = open(peName, "rb")
# 	# 		# global rawData2
# 	# 		rawData2 = f.read()
# 	# 		f.close()
# 	# 		# print ("rawData2", len(rawData2))
# 	# 	except Exception as e:
# 	# 		print("Invalid path to hex file.")
# 	# 		print(e)
# 	# 		quit()
# print("bits", bit32)

# if len(filename) > 1:
# 	testing=filename

# # print("NUMARGS")
# # print(numArgs)

# if numArgs==1:
# 	skipExtraction=True
# 	rawHex=True
# 	filename= sys.argv[1]
# 	print("numargs")
# if not skipExtraction:
# 	if numArgs > 1:			# to get full functionality, need to put file location for binary that is installed (may need to find some DLLs in that directory)
# 		peName= sys.argv[1] 
# 		matchObj = re.match( r'^[a-z]+:[\\|/]+', peName, re.M|re.I)
# 		if matchObj:
# 			isPe=True
# 			head, tail = os.path.split(peName)
# 			peName = tail

# 			PE_path = head
# 			skipPath = True
# 		if not matchObj:
# 			skipPath = False
# 		matchObj = re.match( r'^[a-z0-9]+.dat', peName, re.M|re.I)
# 		if matchObj:
# 			rawBin=False  # only if .bin, not .txt
# 			head, tail = os.path.split(peName)

# 			with open(tail, "r") as ins:
# 				for line in ins:
# 					line2 = line.rstrip('\n')
# 					# print("=======> ", line2)
# 					PEsList.append(line2)
# 			peName = PEsList[0]
# 			# print(peName)
# 			# print "name"
# 			print (peName)
# 			input()
# 			head, tail = os.path.split(peName)
# 			peName = tail

# 			PE_path = head
# 			numPE = len(PEsList)
# 			skipPath = True
# 			# print PEsList
# 	PEtemp = PE_path + "/"+ peName


# 	############### AUSTIN ####################
# 	# print ("entering Austin")
# 	rawHex = False
# 	# global rawData2

# 	# print ("0", sys.argv[0])
# 	# print ("1", sys.argv[1])

# 	# print ("2", sys.argv[2])
# 	if(numArgs > 2):
# 		if binFile and (re.match( "^r", sys.argv[2], re.M|re.I)):
# 			if(re.match( "(r32)|(raw32)|(raw)|(r$)", sys.argv[2], re.M|re.I)):
# 				bit32 = True
# 			if(re.match( "(r64)|(raw64)", sys.argv[2], re.M|re.I)):
# 				bit32= False

# 			# if(sys.argv[2] == "raw"):
# 			rawHex = True
# 			rawBin=True  # only if .bin, not .txt
# 			# dprint("set raw", (sys.argv[2]), (sys.argv[1]), peName)
# 			try:
# 				print("Bin------------>", peName)
# 				input()
# 				f = open(peName, "rb")
# 				# global rawData2
# 				rawData2 = f.read()
# 				f.close()
# 				# print ("rawData2", len(rawData2))
# 			except Exception as e:
# 				print("Invalid path to hex file.")
# 				print(e)
# 				quit()
# 	############### AUSTIN ####################

# 	if skipPath == False:
# 		PEtemp = peName
# 	if skipPath == True:
# 		PEtemp = PE_path + "/"+ peName

# 	if(rawHex):
# 		# bit32 = True #### ADD UI SELECTION LATER #####
# 		pe = peName

# if not rawHex:
# 	if win32file.GetBinaryType(PEtemp) == 6:
# 		bit32 = False
# 	else:
# 		bit32 = True


class OSVersion:
	#Used for list of OSVersions to print for syscall
	def _init_(self, name, category, toggle, code):
		self.name = name 			#Version, e.g. SP1
		self.category = category 	#OS, e.g. Windows 10
		self.toggle = toggle 		#To print or not
		self.code = code 			#The opcode, e.g. xp1
									#^Used for selection

class MyBytes:

	def _init_(self): #, name):
		"""Initializes the data."""
		self.peName = 'peName'
		self.modName ='modName'
		self.pe = pe #pefile.PE(self.peName)
		self.data2 = 0
		self.VirtualAdd = 0
		self.ImageBase = 0
		self.vSize = 0
		self.SizeOfRawData = 0
		self.startLoc = 0
		self.endAddy = 0
		self.entryPoint = 0
		self.sectionName = 'sectionName'
		self.protect =""
		self.depStatus=""
		self.aslrStatus=""
		self.sehSTATUS=""
		self.CFGstatus=""
		self.Imports=[]
		self.Hash_sha256_section=""
		self.Hash_md5_section=""
		self.Strings = []	# tuple - strings, starting offset
		self.pushStrings=[]
		self.wideStrings = []	# tuple - strings, starting offset
		self.save_PEB_info = []
		self.save_PushRet_info = []
		# self.sectionStart =0 ### image base + virtual address
		self.save_FSTENV_info = [] #tuple - addr, NumOps, modSecName, secNum
		self.save_Egg_info = [] #tuple - addr, NumOps, modSecName, secNum
		self.save_Callpop_info = [] #tuple - addr, NumOps, modSecName, secNum, pop_offset
		self.save_Heaven_info = []
# end classs 

class IATS:
	def _init_(self): #, name):
		"""Initializes the data."""
		self.name=""
		self.entries=[]
		self.SearchedFully = False
		self.path = []

class FoundIATs:
	def _init_(self): #, name):
		"""Initializes the data."""
		self.found=[]
		self.foundDll=[]
		self.path = []
		self.originate=[]
iatList=[]
m = []   # start modules
s = []  # start sections

def newModule():
	global m
	obj = MyBytes()
	obj._init_()
	m.append(obj)


if __name__ == "__main__":
	newModule()

def newSection():
	global s
	obj = MyBytes()
	obj._init_()
	s.append(obj)

def newIAT():
	global iatList
	obj = IATS()
	obj._init_()
	iatList.append(obj)

if __name__ == '__main__':
	IATs = FoundIATs()
	IATs._init_()

class DisassByt:
	def _init_(self): #, name):
		"""Initializes the data."""
		self.offsets = []   # starting offsets of bytes - may not always be 0 or 1
		self.values = [] # the hex value
		# self.instructions =[]  # t/f - is it instructions--intinialized as instructions first
		# self.data =[] # t/f is data bytes
		self.ranges=[] # does it identify ranges?
		self.bytesType=[]
		self.strings=[] # TRUE if strings, false if not
		self.stringsStart=[] #offset the strings starts @
		self.stringsValue=[]
		self.pushStringEnd=[]
		self.pushStringValue=[]
		self.boolPushString=[]
		self.specialVal=[] # align, FF
		self.boolspecial=[]
		# self.specialType=[]
		self.specialStart=[]
		self.specialEnd=[]
		self.comments=[]
			


def clearDisassBytClass():
	shBy.offsets.clear()
	shBy.values.clear()
	# shBy.instructions.clear()
	# shBy.data.clear()
	shBy.ranges.clear()
	shBy.bytesType.clear()
	shBy.strings.clear()
	shBy.stringsStart.clear()
	shBy.stringsValue.clear()
	shBy.pushStringEnd.clear()
	shBy.pushStringValue.clear()
	shBy.boolPushString.clear()
	shBy.specialVal.clear()
	shBy.boolspecial.clear()
	# shBy.specialType.clear()
	shBy.specialStart.clear()
	shBy.specialEnd.clear()
	shBy.comments.clear()

if __name__ == '__main__':
	shBy=DisassByt()
	shBy._init_()

def stripWhite(str1):


	str1=str1.lstrip('\x00')
	str1=str1.lstrip('\x0a')
	str1=str1.lstrip('\x0d')
	str1=str1.rstrip('\x00')
	str1=str1.rstrip('\x0a')
	str1=str1.rstrip('\x0d')
	return str1

def stripWhite1(str1):


	str1=str1.lstrip(b'\x00')
	str1=str1.lstrip(b'\x0a')
	str1=str1.lstrip(b'\x0d')
	str1=str1.rstrip(b'\x00')
	str1=str1.rstrip(b'\x0a')
	str1=str1.rstrip(b'\x0d')
	return str1

def stripSpec(str1):

	str1=str1.lstrip('\x17')
	str1=str1.rstrip('\x17')
	return str1

def getLast(absoluteAddress):

	try:
		absoluteAddress = absoluteAddress.decode()
	except:
		pass

	absoluteAddress = str(absoluteAddress)
	array = absoluteAddress.split("\\")
	new = ""
	for word in array:
		new =  word
	last=len(array)-1
	return array[last].lower()

def addIAT(dll, org):
	global peName
	global paths
	tempPaths=[]
	truePath=" "
	# print("ADDIAT CALLED")
	try:
		dll = dll.decode()
	except:
		pass
	try:
		org = org.decode()
	except:
		pass
	# print(dll)
	# print(org)
	# input("enter...")
	# input("enter")
	# print "ADDING " + dll + " "  + org
	for y in paths:
		tempPaths.append(getLast(y))

	# print "*****addIAT"
	properName=""
	for x in iatList:
		try:
			x.name = x.name.decode()
		except:
			pass
		if x.name.lower() == dll.lower():
			properName=x.name
			t=0
			# print "got name"
			for w in tempPaths:
				# print "-- " + w   + "   x.name: "  + x.name
				if w == x.name.lower():
					# print(paths[t])
					# input("paths[t]")
					truePath = paths[t]
				t+=1
	
	# print "peName "  + peName + " " + dll
	if ((dll.lower() ==getLast(peName).lower()) or (dll.lower() ==peName.lower())):
		# print "got it"
		truePath=" "

	dllLower=dll.lower()
	# print(IATs.found)
	# input("IATS.found")
	if dll not in IATs.found:

		if(properName == ""):
			properName = dll

		IATs.found.append(dllLower)
		IATs.foundDll.append(properName)
		IATs.originate.append(org)
		if ((dll.lower() ==getLast(peName).lower()) or (dll.lower() ==peName.lower())):
			pass
		else:
			IATs.path.append(truePath)
		if dllLower=="msvcrt.dll":
			IATs.found.append("sechost.dll")   ### not sure how/why sechost gets on? hardcoding
			IATs.foundDll.append("sechost.dll")
			if bit32:
				IATs.path.append("C:\Windows\SysWOW64\sechost.dll")
			else:
				IATs.path.append("C:\Windows\System32\sechost.dll")
			IATs.originate.append("advapi32.dll")

def checkDllInCurrentIAT(dll):
	dllLower=dll.lower()
	if dll in IATs.found:
		return False
	else:
		return True

def dep():	
	global pe
	return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100)
def aslr():
   return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040)
def seh():
   return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400)
def CFG():
   return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000)

def Extraction():
	global entryPoint
	global VirtualAdd
	global ImageBase
	global vSize
	global startAddress
	global endAddy
	global o
	global modName
	global peName
	global index

	modName = peName
	try:
		head, tail = os.path.split(peName)
		modName = tail
	except:
		pass
	PEtemp = PE_path + "/"+ peName
	if skipPath == False:
		pe = pefile.PE(peName)
	if skipPath == True:
		pe = pefile.PE(PEtemp)
	
	o = 0
	m[o].modName=peName
	m[o].entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	m[o].VirtualAdd = pe.sections[0].VirtualAddress
	m[o].ImageBase = pe.OPTIONAL_HEADER.ImageBase
	m[o].vSize = pe.sections[0].Misc_VirtualSize
	m[o].startLoc = m[o].VirtualAdd + m[o].ImageBase
	m[o].endAddy = m[o].startLoc + m[o].vSize
	m[o].endAddy2 = m[o].startLoc + m[o].vSize
	m[o].sectionName = pe.sections[0].Name
	m[o].SizeOfRawData  =pe.sections[o].SizeOfRawData
	m[o].Hash_sha256_section=	 pe.sections[0].get_hash_md5()
	m[o].Hash_md5_section =   pe.sections[0].get_hash_sha256()

	tem =0
	m[o].data2  = pe.sections[0].get_data()[0:]
	global DLL_Protect

	m[o].protect = str(peName) + "\t"
	m[o].depStatus =  str(dep())
	m[o].aslrStatus =  str(aslr())
	m[o].sehSTATUS =  str(seh())
	m[o].CFGstatus =  str(CFG())
	m[o].protect = m[o].protect + m[o].depStatus + m[o].aslrStatus + m[o].sehSTATUS + m[o].CFGstatus
	DLL_Protect.append(m[o].protect)

def findEvilImports():
	global FoundApisAddress
	for item in pe.DIRECTORY_ENTRY_IMPORT:
		# print item.dll
		for i in item.imports:
			FoundApisName.append(tuple((item.dll, i.name, hex(i.address))))

def showImports():
	cat=""
	for dll, api, offset in FoundApisName:
		
		try:
			cat += api.decode() + "\t" + dll.decode() + "\t"+ str(offset)+"\n"
		except:
			pass
	return cat
def listReducer(dlls):	
	fun2=  list(OrderedDict.fromkeys(dlls))
	return fun2

def curIAT():
	ans = len(iatList)
	return ans-1

def ord2(x):
	return x

def searchIATName(term):
	# input("in searchname")
	# print "searchIatname " + term 
	z=0
	try:
		term = term.decode()
	except:
		pass

	for x in iatList:
		try:
			x.name = x.name.decode()
		except:
			pass
		if term.lower() == x.name.lower():
			# input("name match")
			return True
	return False

def searchIATTerm(name, entry):
	input("in searchterm")
	z=0

	try:
		name = name.decode()
	except: 
		pass
	for iat in iatList:
		try:
			iat.name = iat.name.decode()
		except: 
			pass
		# print iat.name
		if name.lower() == iat.name.lower():
			# print "match1"
			for each in iat.entries:
				try:
					each = each.decode()
				except:
					pass
				# print each
				if each.lower() == entry.lower():
					# print "match2"
					return True
	return False

def searchIATforOldpre(old):
	input("in searchforoldpre")
	z=0
	try:
		old = old.decode()
	except: 
		pass
	for x in iatList:
		try:
			x.name = x.name.decode()
		except: 
			pass
		if old.lower() == x.name.lower():
			# print "found it " + old + " " + str(z)
			return z
		z+=1
	# print "did not find it"
	return 666

def searchIATforOld(old, existing):
	input("in searchforold")

	try:
		old = old.decode()
	except: 
		pass
	index=searchIATforOldpre(old)
	if index < 666:
		# print "ok " + old
		for dll in iatList[index].entries:
			try:
				dll = dll.decode()
			except:
				pass
			# print dll
			if dll not in existing:
				print(existing)
				input("existing")
			# if dll.lower() == old.lower():
			# 	print "found old dll: " + dll
				return True, dll
	return False, ""

def printAllIATs():
	for x in iatList:
		print( "dll:" + x.name)
		for y in x.entries:
			print( y)
		print( "* * *  *  * *  *  * *  * *  * * \n")

def addDeeper(dll):
	global deeperLevel
	dll=dll.lower()
	# print "add " + dll
	if dll not in deeperLevel:
		deeperLevel.append(dll)
	# print "\tdeeperLevel:"
	# for x in deeperLevel:
	# 	print "\t--"+x

def removeDeeper():
	global deeperLevel
	# print "rem "  + deeperLevel[len(deeperLevel)-1]
	if deeperLevel[len(deeperLevel)-1].lower()=="iat":
		deeperLevel.append("IAT")
	del deeperLevel[-1]

	# print "\tdeeperLevel:"
	# for x in deeperLevel:
	# 	print "\t--"+x
	return deeperLevel[len(deeperLevel)-1]

def InMem2():
	global peName
	dprint2(len(IATs.foundDll))
	IATs.found.append(peName.lower())
	IATs.foundDll.append(peName)
	IATs.path.append("")
	IATs.originate.append("")
	addIAT(b"NTDLL.dll",b"IAT") # 2
	addIAT(b"KERNEL32.dll", b"IAT")  # 3
	addIAT(b"KERNELBASE.dll", b"IAT") # 4
	t=0
	for dll in iatList[0].entries:
		try:
			dll = dll.decode()
		except:
			pass
		if dll.lower() not in IATs.found:
			# print "  got: " + dll + " " +  iatList[t].name
			try:
				addDeeper(iatList[t].name)
				# print("\n\nFROM INMEM2")
				addIAT(dll, iatList[t].name)
			except: 
				pass
			old=dll
			# print(dll)
			# input("dll going to searchold")
			truth=searchOld(old)
			if truth==False:
				truth=searchOld(old)
		t+=1
	printInMemoryOrderModuleList()

def printInMemoryOrderModuleList():
	print ("InMemoryOrderModuleList:")
	t=0

	for x in IATs.foundDll:
		try:
			x = x.decode()
		except:
			pass
		try:
			IATs.path[t] = IATs.path[t].decode()
		except:
			pass
		try:
			IATs.originate[t] = IATs.originate[t].decode()
		except:
			pass

		# print(type(x))
		# print(type(IATs.path[t]))
		# print(type(IATs.originate[t]))

		print (x +  "\t" + IATs.path[t] + " from " + IATs.originate[t])

		t+=1

def findOldIAT(dll):
	try:
		dll = dll.decode()
	except:
		pass
	dll=dll.lower()
	# print "findoldIAT --->  "  + dll
	if dll not in IATs.found:
		return True, dll
	else:
		return False, ""
def searchOld(old):
	try:
		old = old.decode()
	except:
		pass
	old=old.lower()
	# print "\tsearchold " + old
	t=0
	GotOne=False
	for x in iatList:
		try:
			x.name = x.name.decode()
		except:
			pass
		# print "	  s_old--@? " + x.name.lower()  +  " old " + old
		if x.name.lower() == old:
			# print "  - matching on NAME: " + " " +  x.name.lower()
			for dll in iatList[t].entries:
				try:
					dll = dll.decode()
				except:
					pass
				# if dll.lower() not in IATs.found:
				truth, foundDll = findOldIAT(dll)
				if truth:
					# print "GOT: " + foundDll + " " + x.name.lower()
					GotOne=True
					# print("\n\nFROM SEARCHOLD")
					addIAT(foundDll, x.name)
					addDeeper(x.name)
					while (truth==True):
						truth=searchOld(foundDll)
						if truth == False:							
							GotOne=False
					if truth==False:
						# print "truth = False " + old

						# newOld=removeDeeper()
						# print "newOld " + newOld
						t2=goInsidePreviouslySearched(x.name.lower())
						if t2==False:
							# print "breaking " + foundDll + " " + x.name   + " OLD: " + old
							return False
		t+=1
	# removeDeeper()
	return GotOne

def goInsidePreviouslySearched(old):
	# print "\tentering goInsidePreviouslySearched " + old
	t=0
	GotOne=False
	for x in iatList:
		if x.name.lower() == old.lower():
			for dll in x.entries:
				# print "\t\tgoinside--> " + dll 
				truth, foundDll = findOldIAT(dll)
				if truth:
					# print "GOT3: " + foundDll + " " + x.name + " \tgoInsidePreviouslySearched"
					GotOne=True
					# print("\n\nFROM GOINSIDEPREV")
					addIAT(foundDll, x.name)
					addDeeper(x.name)
					while (truth==True):
						truth=searchOld(foundDll)
						if truth == False:
							GotOne=False
					if truth==False:
						# print "entering searchold t4 " + old
						# old=removeDeeper()
						# print "newold: " + old
						t2=searchOld(old)
						if t2==False:
							# print "breaking4 " + foundDll + " " + x.name   + " OLD: " + old
							if checkSearchedFully2(dll)==False:
								# print "first one"
								t3 = lookInsideDeeper(dll)
							return False
				# if truth==False:
				# 	# s= checkSearchedFully()
				if truth==False:
					
					if checkSearchedFully2(dll)==False:
						# print "second one"
						t3=lookInsideDeeper(dll)
						# print "completed second one"
					else:
						# print "return true"
						return True   # FALSE???

def checkSearchedFully():
	for x in iatList:
		notIn=0
		for dll in x.entries:
			if dll.lower() not in IATs.found:
				notIn+=1
		if notIn==0:		
			x.SearchedFully==True

def checkSearchedFully2(dll):
	# print "search2 --> " + dll
	checkSearchedFully()
	for x in iatList:
		if dll ==x.name:
			if x.SearchedFully==False:
				# print x.name + " searchedfully False "
				return False
			else:
				return True
def lookInsideDeeper(currentDll):
	# print "\t\tlookInsideDeeper "  + currentDll
	for x in iatList:
		if x.name == currentDll:
			# if x.SearchedFully == False:
			# print "\t\t*** " + x.name
			for dll in x.entries:
				# print "\t\t--> " + dll
				truth, foundDll = findOldIAT(dll)
				if truth:
					# print "GOT5: " + foundDll + " " + x.name + " \tdeeper"
					GotOne=True
					# print("\n\nFROM LOOKINSIDEDEEPER")
					addIAT(foundDll, x.name)
					addDeeper(x.name)
					### do search old
					# if search old fails
					t=searchOld(foundDll)
					if t==False:
						# removeDeeper()
						if checkSearchedFully2(currentDll)==False:
							truth=lookInsideDeeper(currentDll)
				# 	break
				# if truth ==False:
				# 	return False
			# if x.SearchedFully:
	# removeDeeper()				

def getDLLs():
	global PE_DLLS
	name = ""
	newIAT()
	iatList[0].name="IAT"

	try:
		for entry in pe.DIRECTORY_ENTRY_IMPORT:			
			iatList[0].entries.append(entry.dll)
			# print entry.dll
			name = entry.dll
			name = name.decode()
			PE_DLLS.append(name)
	except:
		pass

deeper = 0




def digDeeper(PE_DLL):
	# print("One deep call")
	global PE_DLLS
	global paths
	global deeper
	doneAlready0=[]
	c=0
	cont=False
	
	for dll in PE_DLL:
		# print("PEDLL IS")
		# print(PE_DLL)
		try:
			dll = dll.decode()
		except:
			pass

		#if(dll == "CRYPTBASE.dll"):
		#	input("on crypt")
		newpath = ""
		# print("############### DLL #################")
		# print("DLL = " + dll)
		if dll not in doneAlready0:
			# print("done already conditional")
			# print("#########################################")
			# print("APPENDING SOMETHING NEW: " + dll)
			#input("enter...")
			peFound=True
			newpath = extractDLLNew(dll)
			# print("Newpath", newpath)
			# input()
			# print(newpath)
			# input("newpath")
			doneAlready0.append(dll)
			paths.append(newpath)
			try:
				pe = pefile.PE(newpath)
			except:
				print ("Invalid path found for " + newpath + "\nResults, thus, will be inaccurate.")
				peFound=False
				name = "Invalid path for " + newpath
				iatList[c].entries.append(name)
				PE_DLLS.append(name)
		name = ""
		name = ""
		try:
			if peFound:
				cont=False
				if not searchIATName(dll):
					newIAT()
					c=curIAT()
					iatList[c].name=dll
					cont=True

				# print(dll)
				# print(type(pe))
				for entry in pe.DIRECTORY_ENTRY_IMPORT:
					name = entry.dll
					try:
						name = name.decode()
					except:
						# input("enter...")
						pass

					# print(name)
					if cont:
						apiMSWIN = re.match( r'\bAPI-MS-WIN\b', name, re.M|re.I)
						if not apiMSWIN:
							# print(iatList[c].entries)
							# print("not match")
							# input("iatlist")
							# if(iatList[c].entries[-1] not == "name")
							iatList[c].entries.append(name)
					apiMSWIN = re.match( r'\bAPI-MS-WIN\b', name, re.M|re.I)
					if not apiMSWIN:			
						# print("not match")	
						if name not in PE_DLLS:
							PE_DLLS.append(name)# + " " + dll)
		except Exception as e:
		 	pass
		 	# print(e)
		 	# input("EXCPETED")

def digDeeper2():
	global PE_DLLS
	global paths
	doneAlready =[]
	for dll in PE_DLLS:
		try:
			dll = dll.decode()
		except:
			pass
		newpath = ""
		if dll not in doneAlready:
			newpath = extractDLLNew(dll)
			# print(newpath)
			# input("newpath")
			doneAlready.append(dll)
			paths.append(newpath)
			pe = pefile.PE(newpath)
		name = ""
		try:
			cont=False
			if not searchIATName(dll):
				newIAT()
				c=curIAT()
				iatList[c].name=dll
				cont=True
			for entry in pe.DIRECTORY_ENTRY_IMPORT:

				name = entry.dll
				try:
					name = name.decode()
				except:
					pass
				if cont:
					apiMSWIN = re.match( r'\bAPI-MS-WIN\b', name, re.M|re.I)
					if not apiMSWIN:
						iatList[c].entries.append(name)
				apiMSWIN = re.match( r'\bAPI-MS-WIN\b', name, re.M|re.I)
				if not apiMSWIN:
					doneAlready.append(dll)
					if name not in PE_DLLS:
						PE_DLLS.append(name)# + " " + dll)
		except Exception as e:
			# print(e)
			# input("deeper2")
			pass

def ObtainAndExtractDlls():
	getDLLs()
	global peName
	global PE_DLLS
	global o
	global modName

	test = ""
	i = 0
	for dll in PE_DLLS:
		test = extractDLLNew(PE_DLLS[i])
		head, tail = os.path.split(test)
		modName = tail
		i +=1
	PE_DLLS = listReducer(PE_DLLS)
	# moreDLLs()
	# noApi_MS(PE_DLLS)
	Answer	= set(PE_DLLS) - set(Remove)
	PE_DLLS = list(Answer)
	display = ""
	for r in PE_DLLS:
		display = display + r + ", "
	print( "DLLs: " + display)
	print (len(PE_DLLS))
	o = 0
	
	modName = peName

def ObtainAndExtractSections():

	getDLLs()
	global peName
	global PE_DLLS
	global o
	global t
	global modName
	global sections
	global pe


	test = ""
	i = 0
	# print ("pename " + peName)
	pe = pefile.PE(peName)
	# print (pe.OPTIONAL_HEADER.AddressOfEntryPoint)


	for sec in pe.sections:
		sections.append(sec.Name)
	# print (sections)

	# print pe.sections[0].get_data()[0:]

	# print "t " + str(t)
	# print "m " + str(len(m))
	# print "s " + str(len(s))
	t=0
	# print("Length of pe sections", len(pe.sections))
	for x in pe.sections:
		newSection()
		# print(red + "S: after --> " + res, s)
		s[t].modName=peName
		s[t].entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
		
		s[t].VirtualAdd = pe.sections[t].VirtualAddress
		# print pe.sections[t].VirtualAddress
		s[t].ImageBase = pe.OPTIONAL_HEADER.ImageBase
		s[t].vSize = pe.sections[t].Misc_VirtualSize
		s[t].startLoc = s[t].VirtualAdd + s[t].ImageBase
		s[t].endAddy = s[t].startLoc + s[t].vSize
		s[t].endAddy2 = s[t].startLoc + s[t].vSize
		s[t].sectionName = stripWhite1(pe.sections[t].Name)
		s[t].SizeOfRawData = pe.sections[t].SizeOfRawData

		s[t].Hash_sha256_section=	 pe.sections[t].get_hash_md5()
		s[t].Hash_md5_section =   pe.sections[t].get_hash_sha256()
		tem =0
		# print("Extraction: ", t, type(pe.sections[t].get_data()[0:]))
		s[t].data2  = pe.sections[t].get_data()[0:]
		# print("Checking", type(s[t].data2))
		s[t].protect = str(peName) + "\t"
		s[t].depStatus =  str(dep())
		s[t].aslrStatus =  str(aslr())
		s[t].sehSTATUS =  str(seh())
		s[t].CFGstatus =  str(CFG())
		s[t].protect = s[t].protect + s[t].depStatus + s[t].aslrStatus + s[t].sehSTATUS + s[t].CFGstatus
		DLL_Protect.append(s[t].protect)
		t+=1


	# print("check: ", s, len(s))
	# for section in s:
		# print("Type: ", type(section.data2), section.sectionName)

	# input()
		# print "did it" + str(t)
		# print sect.get_hash_md5()
		# print sect.get_hash_sha256()

	# print pe.sections[0].get_hash_md5()
	# print pe.sections[0].get_hash_sha256()
	# print pe.sections[0].Name


	# for dll in PE_DLLS:
	# 	test = extractDLLNew(PE_DLLS[i])
	# 	head, tail = os.path.split(test)
	# 	modName = tail
	# 	i +=1
	# PE_DLLS = listReducer(PE_DLLS)
	# # moreDLLs()
	# # noApi_MS(PE_DLLS)
	# Answer	= set(PE_DLLS) - set(Remove)
	# PE_DLLS = list(Answer)
	display = ""
	for r in sections:
	#	print(str(r))
		r=stripWhite1(r)
		display = display +str(r) + ", "
	# print ("Sections: " + display)
	# print len(PE_DLLS)
	o = 0
	t=0
	# modName = peName
def f(dllName):
	global o
	global index
	global  newpath
	global ans
	global PE_Protect
	global PE_path


		# A very small portin of this loadlibrary comes from: https://www.programcreek.com/python/example/53932/ctypes.wintypes.HANDLE
		# All of the elaborate loading through alternate means is entirely original
	#index = 0
	# print dllName
#remove if could not be found
	# print("INDEX = " + str(index))
	try:
		dllName = dllName.decode()
	except:
		pass

	try:
		
		dllHandle = win32api.LoadLibraryEx(dllName, 0, win32con.LOAD_LIBRARY_AS_DATAFILE)
		windll.kernel32.GetModuleHandleW.restype = wintypes.HMODULE
		windll.kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
		windll.kernel32.GetModuleFileNameW.restype = wintypes.DWORD
		windll.kernel32.GetModuleFileNameW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD]
		h_module_base = windll.kernel32.GetModuleHandleW(dllName)
		module_path = ctypes.create_unicode_buffer(255)
		windll.kernel32.GetModuleFileNameW(h_module_base, module_path, 255)
		pe = pefile.PE(module_path.value)
		win32api.FreeLibrary(dllHandle)

		if h_module_base is None:
			directory = r'C:\Program Files\testing'  
			directory = PE_path
			newpath = os.path.abspath(os.path.join(directory, dllName))
			if os.path.exists(newpath):
				module_path.value = newpath
				ans = newpath
			else:
				if bit32:
					directory = r'C:\Windows\SysWOW64'
					newpath = os.path.abspath(os.path.join(directory, dllName))
					if os.path.exists(newpath):
						module_path.value = newpath
						ans = newpath
					else:
						# print "\t\tNote: " + dllName + " will be excluded. Please scan this manually if needed."
						Remove.append(dllName)
				if not bit32:
					directory = r'C:\Windows\System32'
					newpath = os.path.abspath(os.path.join(directory, dllName))
					if os.path.exists(newpath):
						module_path.value = newpath
						ans = newpath
					else:
						# print "\t\tNote: " + dllName + " will be excluded. Please scan this manually if needed."
						Remove.append(dllName)
		head, tail = os.path.split(module_path.value)
		if tail != dllName:
			# print "\tNote: " + str(tail) + " is being searched instead of " + dllName + "."
			PE_DLLS[index] = tail
			Remove.append(dllName)
		ans = module_path.value

		m[o].protect = str(dllName) + "\t"
		m[o].depStatus = str(dep())
		m[o].aslrStatus =  str(aslr())
		m[o].sehSTATUS = str(seh())
		m[o].CFGstatus =  str(CFG())
		m[o].protect = m[o].protect + m[o].depStatus + m[o].aslrStatus + m[o].sehSTATUS + m[o].CFGstatus
		DLL_Protect.append(m[o].protect)
		PE_Protect = PE_Protect + str(m[o].protect)
	# print m[o].protect

		index += 1
	except Exception as e:
		directory = r'C:\Program Files\testing'  #hardcoded testing, made irrelevant by next line
		directory = PE_path
		newpath = os.path.abspath(os.path.join(directory, dllName))
		if os.path.exists(newpath):
			ans = os.path.abspath(os.path.join(directory, dllName))
		else:
			if bit32:
				directory = r'C:\Windows\SysWOW64'
				newpath = os.path.abspath(os.path.join(directory, dllName))
				if os.path.exists(newpath):
					ans = os.path.abspath(os.path.join(directory, dllName))
				else:
					# print "\t\tNote: " + dllName + " will be excluded. Please scan this manually if needed."
					Remove.append(dllName)
			if not bit32:
				directory = r'C:\Windows\System32'
				newpath = os.path.abspath(os.path.join(directory, dllName))
				if os.path.exists(newpath):
					ans = os.path.abspath(os.path.join(directory, dllName))
				else:
					# print "\t\tNote: " + dllName + " will be excluded. Please scan this manually if needed."
					Remove.append(dllName)

		m[o].protect = dllName + "\t"
		m[o].depStatus = str(dep())
		m[o].aslrStatus =  str(aslr())
		m[o].sehSTATUS =  str(seh())
		m[o].CFGstatus =  str(CFG())
		m[o].protect = m[o].protect + m[o].depStatus + m[o].aslrStatus + m[o].sehSTATUS + m[o].CFGstatus
		DLL_Protect.append(m[o].protect)
		PE_Protect = PE_Protect + str(m[o].protect)
		# print m[o].protect

		index += 1
			# print(e)
			# input("EXCEPTED NEWDLL")
			# pass

		# print  "\t* " + str(ans)
		# print(type(dllName))
		# print("CALLED")
	try:
		ans = ans.decode()
	except:
		pass
	return ans

def extractDLL_MinNew(dll):
	print ("NEW: extracting enter ", dll)
	global pe
	global modName
	global o
	global index
	dllName = dll
	modName = dll
	
	newModule()
	#o = o + 1
	# print "o = " + str(o)
	#initMods(dll)
	m[o].modName=dll
	newpath = extractDLLNew(dll)
	# print newpath
	pe = pefile.PE(newpath)
	global PE_Protect
	m[o].sectionName = pe.sections[0].Name
	m[o].Hash_sha256_section=	 pe.sections[0].get_hash_md5()
	m[o].Hash_md5_section =   pe.sections[0].get_hash_sha256()
	m[o].entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	m[o].VirtualAdd = pe.sections[0].VirtualAddress
	m[o].ImageBase = pe.OPTIONAL_HEADER.ImageBase
	m[o].vSize = pe.sections[0].Misc_VirtualSize
	m[o].endAddy = m[o].startLoc + m[o].vSize
	m[o].data2  = pe.sections[0].get_data()[m[o].VirtualAdd:m[o].VirtualAdd+m[o].vSize]

def showBasicInfo():
	cat=""
	o=0
	dprint2 ("# m: " + str(len(m)))
	for each in m:
		if rawHex:
			try:
				cat+="Entry point: " + str(hex(shellEntry)) +"\n"
			except:
				cat+="Entry point: " + str(shellEntry) +"\n"

		else:
			cat +=m[o].modName.decode()+"\n"
			cat +="Section: " + str(m[0].sectionName) +"\n"
			cat+="Entry point: " + str(hex(m[o].entryPoint)) +"\n"
			cat+="Virtual Address: " + str(hex(m[o].VirtualAdd))+"\n"
			cat+="ImageBase: " + str(hex(m[o].ImageBase))+"\n"
			cat+="VirtualSize: " + str(hex(m[o].vSize))+"\n"
			cat+="Size of section: " + str(hex(m[o].data2))+"\n"
			cat+= "DEP: " + str(m[o].depStatus)+"\n"
			cat+="ASLR: " + str(m[o].aslrStatus)+"\n"
			cat+="SEH: " + str(m[o].sehSTATUS)+"\n"
			cat+="CFG: " + str(m[o].CFGstatus)+"\n"
			cat+="\n"
			cat+=""
		o+=1
	o=0
	return cat

def showBasicInfoSections():
	dprint2("showBasicInfoSections")
	cat=""
	t=0
	dprint2 ("# s: " + str(len(s)))

	for each in s:	
		cat +=s[t].sectionName.decode()+"\n"
		# cat +="Section: " + str(m[0].sectionName) +"\n"
		cat+="Entry point: " + str(hex(s[t].entryPoint)) +"\n"
		cat+="Virtual Address: " + str(hex(s[t].VirtualAdd))+"\n"
		cat+="ImageBase: " + str(hex(s[t].ImageBase))+"\n"
		cat+="VirtualSize: " + str(hex(s[t].vSize))+"\n"
		cat +="SizeOfRawData: " + str(hex(s[t].SizeOfRawData)) +"\n"
		cat +="VirtualAddress: " + str(hex(s[t].VirtualAdd)) +"\n"
		cat +="ImageBase + sec. virtual address: " + str(hex(s[t].startLoc)) +"\n"
		cat+="Actual size of section: " + str(hex(len(s[t].data2)))+"\n"
		cat+= "DEP: " + str(s[t].depStatus)+"\n"
		cat+="ASLR: " + str(s[t].aslrStatus)+"\n"
		cat+="SEH: " + str(s[t].sehSTATUS)+"\n"
		cat+="CFG: " + str(s[t].CFGstatus)+"\n"

		cat+="Sha256: "+s[t].Hash_sha256_section+"\n"
		cat+="md5: "+s[t].Hash_md5_section+"\n"
		cat+="\n"
		cat+=""
		t+=1
	t=0
	return cat
	
def show1(int):
		show = "{0:02x}".format(int) #
		return show

def binaryToStr(binary):
	# OP_SPECIAL = b"\x8d\x4c\xff\xe2\x01\xd8\x81\xc6\x34\x12\x00\x00"
	newop=""
	# newAscii=""
	try:
		for v in binary:
			i = ord2(v) 
			newop += "\\x"+show1(i)
			# newAscii += "\\x"+chr(i)
		# print newop
		# print newAscii
		return newop
	except Exception as e:
		print ("*Not valid format")
		print(e)

def Text2Json(shell, json=None):
	#print(shell)
	#text = binaryToText(shell)
	global filename
	
	inputFile = filename
	time = datetime.datetime.now()
	filetime = time.strftime("%Y%m%d_%H%M%S")

	raw_shellcode = shell
	raw_hex = raw_shellcode[0]
	raw_hex = raw_hex.replace("\n", "")		# remove new lines
	raw_hex = raw_hex.replace('"', "")		# remove double quotes
	raw_hex = raw_hex.split(":")[1]			# read only shellcode and ignore "Raw Hex:"

	str_lit = raw_shellcode[1]
	str_lit = str_lit.replace("\n", "").replace('"', "") # remove new lines and double quotes
	str_lit = str_lit.split(":")[1]
	shellcode_dict = {"rawhex":raw_hex,
					"strlit":str_lit}

	if json != None:
		return shellcode_dict
	fileName = "rawhex" + "_" + inputFile + "_" + filetime + ".json"
	outDir = os.getcwd() + "\\outputs\\" 
	fullPath = outDir + fileName

	try:
		with open(fullPath, 'w') as outfile:
			json.dump(shellcode_dict, outfile, indent=4)
		
		print("\n" + fileName + "\n")
	except Exception as e:
		print(e)
	# ArrayLit = "{ "
	# StrLit = ""
	# rawHex = ""
	# jsonRawH = {"shellcode":""}
	# jsonStrLit = {"shellcode":""}
	# try:
	# 	for i in shell:
	# 		z = hex(i)
	# 		ArrayLit += z + ", "
	# 	ArrayLit += " }"				# Convert to {0xab, 0xcd, 0xff, 0x12}
	# 	rawHex = shell.hex()			# Convert to abcdff12

	# 	for i in shell:
	# 		StrLit += "\\x" + format(i, 'x')	# Convert shellcode to \xab\xcd\xff\x1a...
	
	# 	jsonRawH['shellcode'] = rawHex
	# 	jsonStrLit['shellcode'] = StrLit


	# except Exception as e:
	# 	print("Invalid shellcode format")
	# 	print(e)



def binaryToText(binary, json=None):
	global brawHex
	global bstrLit
	strLit=""
	rawH=""
	arrayLit=""
	returnVal=""
	try:
		for v in binary:
			i = ord2(v) 
			strLit += "\\x"+show1(i)
			rawH+=show1(i)
			arrayLit+="0x"+show1(i)+", "
		brawHex = rawH
		bstrLit = strLit

		rawHwColor=yel+'\nRaw Hex:\n'+res+'"'+gre + rawH+res+'"\n'
		rawH='\nRaw Hex:\n'+'"'+ rawH+'"\n'

		strLitwColor=yel+'\nString Literal:\n'+res+'"'+gre + strLit+res+'"\n'
		strLit='\nString Literal:\n'+'"'+ strLit+'"\n'

		# strLit = "\nString Literal:\n\""+strLit+"\"\n"
		arrayLit=arrayLit[:-2]

		arrayLitwColor =yel + "\nArray Literal:\n"+res+"{"+gre + arrayLit+res + "}\n"
		arrayLit ="\nArray Literal:\n"+"{" + arrayLit+ "}\n"

		if json==None:
			print (strLitwColor)
			print (rawHwColor)
			print (arrayLitwColor)
		returnVal=rawH+strLit+arrayLit
	except Exception as e:
		print ("*Not valid format")
		print(e)
	if json == None:
		return returnVal
	elif json =="json":
		
		return rawH, strLit

def binaryToStrSp(binary):
	
	newop="\t 00 01 02 03 04 06 07 08 09 0a 0b 0c 0d 0e 0f\n"
	newop+=" 0x00\t"
	newAscii=""
	# newUnicode=""
	old=0
	try:
		x=0
		y=1
		for v in binary:
			i = ord2(v) 
			newop += " "+show1(i)
			if (i > 31) & (i < 127):
				newAscii += ""+chr(i)
			else:
				newAscii += "."

			#unicode
			# if (y % 2 ==0):
			# 	newUnicode = int(str(old) + str(i))
			# 	print hex(newUnicode)
			# 	print unichr(hex(newUnicode))
			x+=1
			y+=1
			if x ==15:

				# newop +=  "\n " + str(hex(y)) + "\t"
				newop += "  "+  newAscii + "\n " + str(hex(y)) + "\t"
				y+=1
				x=0
				newAscii=""
			old = i

		# print newop
		return newop
	except:
		print ("*Not valid format")



def get_PEB_walk_start(mode, NumOpsDis ,bytesToMatch, secNum, data2): 
	#change to work off of data2 - add param - get rid of secNum

	global o
	foundCount = 0
	numOps = NumOpsDis
	t=0
	len_data2 = len(data2)
	len_bytesToMatch = len(bytesToMatch)
	found = False
	for v in data2:
		found = True #reset flag
		#replace with bytesToMatch list if desired
		#for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
		i = 0
		for x in bytesToMatch:
			if(found == False):
				break
			# elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
			# 	found = False # out of range
			try:
				#print(data2[t+i])
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				pass
			i += 1

		if(found):
			# print("hit a found")
			# input("enter..")
			ans = disHerePEB(mode, t, numOps, secNum, data2)
			if mode=="decrypt" and ans is not None:
				print ("got disherepeb", ans)
				return ans


		t=t+1


# def get_PEB_walk_start(mode, NumOpsDis ,bytesToMatch, secNum, data2): 
# 	#change to work off of data2 - add param - get rid of secNum

# 	global o
# 	foundCount = 0
# 	numOps = NumOpsDis


# 	t=0;

# 	for v in data2:
# 		found = True #reset flag
# 		#replace with bytesToMatch list if desired
# 		# for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
# 		i = 0
# 		for x in bytesToMatch:
# 			if(found == False):
# 				break
# 			elif ((i+t) >= len(data2) or i >= len(bytesToMatch)):
# 				found = False # out of range
# 			elif (ord2(data2[t+i]) != ord2(bytesToMatch[i])):
# 				found = False #no match
# 			i += 1

# 		if(found):
# 			# print('got one -- SecNum = ' + str(secNum) + ' NumOpsDis = ' + str(numOps))
# 			# print("calling with addres: " + str(t))
# 			# raw_input("enter..")
# 			disHerePEB(mode, t, numOps, secNum)

			

# 		t=t+1



#CHANGED: works based off of all sections in pefile now (rather than just .text). unused 'Reg' param changed to secNum to indicate where data came from.


#h1
def get_PEB_walk_start_64(NumOpsDis ,bytesToMatch, secNum, data2): ############### AUSTIN ######################
	#change to work off of data2 - add param - get rid of secNum
	#bytesToMatch 'RAX_OFFSET_NONE': b"\x65\x48\x8B\x04\x25\x60\x00\x00\x00",
	global o
	foundCount = 0
	numOps = NumOpsDis

	t=0
	len_data2 = len(data2)
	len_bytesToMatch = len(bytesToMatch)

	# print("Data2 type: ", type(data2), "bytes to match type", type(bytesToMatch),"Data2 Length: ", len(data2), "bytes to match len", len(bytesToMatch))
	# input()

	t = 0
	found=False
	
	# print("Type of lists dict", type(bytesToMatch))
	# print("Type", type(data2))

	# for i in bytesToMatch:
	# 	i = str(i)
	# 	for k in data2:
	# 		k = str(k)
	# 		print("Type ", type(i), type(k), i, k)
	# 		input()





	for v in data2:
		found = True #reset flag
		#replace with bytesToMatch list if desired
		#for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
		i = 0
		for x in bytesToMatch:
			if(found == False):
				break
			# elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
			# 	found = False # out of range
			try:
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				print(e)
				# input(e)
				pass
			i += 1

		if(found):
			# print("offset", t, "Section", secNum)
			# print("dis Here ", t, numOps, secNum)
			# print (found)
			# print (binaryToStr(data2[t:t+10]))

			disHerePEB_64(t, numOps, secNum, data2)

			

		t=t+1

#CHANGED: works based off of all sections in pefile now (rather than just .text). unused 'Reg' param changed to secNum to indicate where data came from.

total1 = 0
total2 = 0
def disHerePEB(mode, address, NumOpsDis, secNum, data): ############ AUSTIN ##############
	dprint2 ("disHerePEB", mode)
	global o
	global pebPoints
	w=0

	start = timeit.default_timer()
	foundAdv = False
	foundPEB = False
	foundLDR = False
	listEntryText = ""
	## Capstone does not seem to allow me to start disassemblying at a given point, so I copy out a chunk to  disassemble. I append a 0x00 because it does not always disassemble correctly (or at all) if just two bytes. I cause it not to be displayed through other means. It simply take the starting address of the jmp [reg], disassembles backwards, and copies it to a variable that I examine more closely.
	#lGoBack = linesGoBackFindOP

	# print("disHere")
	# print(hex(address))
	# print(secNum)
	#input("addy")

	CODED2 = ""
	x = NumOpsDis
	# start = timeit.default_timer()
	if(secNum != "noSec"):
		section = s[secNum]

	CODED3 = data[address:(address+NumOpsDis)]
		#print("########################")
	#	print(type(CODED2))
	#	print("########################")
	#
	# stop = timeit.default_timer()
	# total1 += (stop - start)
	# print("Time 1 PEB: " + str(stop - start))

	# I create the individual lines of code that will appear>
	# print(len(CODED2))
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]

	loadTIB_offset = -1
	loadLDR_offset = -1
	loadModList_offset = -1
	advanceDLL_Offset = [-1]
	points = 0
	# start = timeit.default_timer()
	#CODED3 = CODED2.encode()
	# print("BINARY2STR")
	# print(binaryToStr(CODED3))
	for i in cs.disasm(CODED3, address):
		#print('address in for = ' + str(address))
		if(secNum == "noSec"):

		#	print("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
			# add = hex(int(i.address))
			add4 = hex(int(i.address))
			addb = hex(int(i.address))
		else:
			add = hex(int(i.address))
			addb = hex(int(i.address +  section.VirtualAdd))
			add2 = str(add)
			add3 = hex (int(i.address + section.startLoc	))
			add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		# val2.append(val)
		# val3.append(add2)


		loadPEB = re.match("^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?d?word ptr fs:\[((((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?)?0x30)|(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))))\]", val, re.IGNORECASE)

		# if(movLoadPEB or addLoadPEB or adcLoadPEB or xorLoadPEB or orLoadPEB or xchgLoadPEB or pushLoadPEB and foundPEB):
		if(loadPEB):
			loadTIB_offset = addb
			points += 1
			foundPEB = True
		elif(not foundPEB):
			return


		loadLDR = re.match("^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0x0?c)\])", val, re.IGNORECASE)

		# if(movLoadLDR or addLoadLDR or adcLoadLDR or xorLoadLDR or orLoadLDR or xchgLoadLDR):

		if(foundLDR):
			loadInLoadOrder = re.match("^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0x0?c)\])", val, re.IGNORECASE)

			# if(movLoadLDR or addLoadLDR or adcLoadLDR or xorLoadLDR or orLoadLDR or xchgLoadLDR):
			if(loadInLoadOrder):
				loadModList_offset = addb
				points += 1
				listEntryText = "LIST_ENTRY InLoadOrderModuleList"

		if(loadLDR):
			loadLDR_offset = addb
			points += 1
			foundLDR = True


		loadInMemOrder = re.match("^((mov)|(add)|(adc)|(xor)|(or)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x14))\])", val, re.IGNORECASE)

		# if(movLoadInMemOrder or addLoadInMemOrder or adcLoadInMemOrder or xorLoadInMemOrder or orLoadInMemOrder or xchgLoadInMemOrder):
		if(loadInMemOrder):
			loadModList_offset = addb
			points += 1
			listEntryText = "LIST_ENTRY InMemoryOrderModuleList"	




		loadInInitOrder = re.match("^((mov)|(add)|(adc)|(xor)|(or)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x1c))\])", val, re.IGNORECASE)

		if(loadInInitOrder):
		# if(movLoadInInitOrder or addLoadInInitOrder or adcLoadInInitOrder or xorLoadInInitOrder or orLoadInInitOrder or xchgLoadInInitOrder):
			loadModList_offset = addb
			points += 1
			listEntryText = "LIST_ENTRY InInitializationOrderModuleList"




		dereference = re.match("^((mov)|(add)|(adc)|(xor)|(or)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))\])", val, re.IGNORECASE)

		# if(movDereference or addDereference or adcDereference or orDereference or xorDereference or xchgDereference):
		if(dereference):
			advanceDLL_Offset_temp = addb
			if(not foundAdv):
				advanceDLL_Offset[0] = advanceDLL_Offset_temp
				foundAdv = True
				points += 1
			else:
				advanceDLL_Offset.append(advanceDLL_Offset_temp)



		lodsd = re.match("^(lodsd)", val, re.IGNORECASE) 

		if(lodsd):
			advanceDLL_Offset_temp = addb
			if(not foundAdv):
				advanceDLL_Offset[0] = advanceDLL_Offset_temp
				foundAdv = True
				points += 1
			else:
				advanceDLL_Offset.append(advanceDLL_Offset_temp)

		val5.append(val)
		# print (val)
	#return val5
	# stop = timeit.default_timer()
	# total2 += (stop - start)
	# print("Time 2 PEB: " + str(stop - start))


	
	disString = val5


	stop = timeit.default_timer()
	dprint2("Time PEB: " + str(stop - start))

	if(points >= pebPoints):
		if(rawHex):
			modSecName = peName
		else:
			modSecName = section.sectionName

		if mode=="decrypt":
			dprint2 ("decrypt returning")
			dprint2 (address, NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, loadModList_offset, advanceDLL_Offset)
			return address , NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, loadModList_offset, advanceDLL_Offset
		#print("Adding item #" + str(len(m[o].save_PEB_info)))
		# print("saving at sec num = " + str(secNum))
		saveBasePEBWalk(address, NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, (loadModList_offset, listEntryText	), advanceDLL_Offset)
		# if(rawHex):
		# 	m[o].save_PEB_info = helperListToSet(m[o].save_PEB_info)
		# else:
		# 	print("Length peb_info", len(s[secNum].save_PEB_info), s[secNum].save_PEB_info)
		# 	s[secNum].save_PEB_info =helperListToSet(s[secNum].save_PEB_info)

def disHerePEB_64(address, NumOpsDis, secNum, data): ############## AUSTIN ####################
	# print ("disHerePEB_64")
	# print("Address", address, "NumOpsDis", NumOpsDis, "SecNum", secNum)
	# input()

	global o
	global pebPresent
	global total1
	global total2
	w=0

	if shellBit == 32:
		callCS = cs
	else:
		callCS = cs64
	pebFound = False
	## Capstone does not seem to allow me to start disassemblying at a given point, so I copy out a chunk to  disassemble. I append a 0x00 because it does not always disassemble correctly (or at all) if just two bytes. I cause it not to be displayed through other means. It simply take the starting address of the jmp [reg], disassembles backwards, and copies it to a variable that I examine more closely.
	#lGoBack = linesGoBackFindOP

	CODED2 = ""
	x = NumOpsDis
	# start = timeit.default_timer()
	if(secNum != "noSec"):
		section = s[secNum]

	CODED2 = data[address:(address+NumOpsDis)]
		#print("########################")
	#	print(type(CODED2))
	#	print("########################")
	#
	# stop = timeit.default_timer()
	# total1 += (stop - start)
	# print("Time 1 PEB: " + str(stop - start))

	# I create the individual lines of code that will appear>
	# print(len(CODED2))
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]

	# start = timeit.default_timer()
	#CODED3 = CODED2.encode()
	CODED3 = CODED2

	for i in callCS.disasm(CODED3, address):

		if(secNum == "noSec"):

			dprint2("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
			# add = hex(int(i.address))
			add4 = hex(int(i.address))
			addb = hex(int(i.address))
		else:
			add = hex(int(i.address))
			addb = hex(int(i.address +  section.VirtualAdd))
			add2 = str(add)
			add3 = hex (int(i.address + section.startLoc	))
			add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		# val2.append(val)
		# val3.append(add2)
		val5.append(val)
		# print (val)
	#return val5
	# stop = timeit.default_timer()
	# total2 += (stop - start)
	# print("Time 2 PEB: " + str(stop - start))

	# for each in val5:
		# print ("\t", each)
	points = 0
	disString = val5
	for line in disString:
		# print("line", line)
		##############################################

		movLoadPEB = re.match("^(mov) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		addLoadPEB = re.match("^(add) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		adcLoadPEB = re.match("^(adc) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		xorLoadPEB = re.match("^(xor) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		orLoadPEB = re.match("^(or) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		xchgLoadPEB = re.match("^(xchg) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		pushLoadPEB = re.match("^(push) ((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))))) ?(\+ ?0x60)?\]", line, re.IGNORECASE)


		# if movLoadPEB:
			# print("FFFFFFFFFFFFFFFFFFFFFFFFFFFFOOOOOOOOOOOOOUND!!!")
		if(movLoadPEB or addLoadPEB or adcLoadPEB or xorLoadPEB or orLoadPEB or xchgLoadPEB or pushLoadPEB):
			pebFound = True
			points += 1
			

		##############################################


		movLoadLDR = re.match("^(mov) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x18)\])", line, re.IGNORECASE)
		addLoadLDR = re.match("^(add) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x18)\])", line, re.IGNORECASE)
		adcLoadLDR = re.match("^(adc) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x18)\])", line, re.IGNORECASE)
		xorLoadLDR = re.match("^(xor) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x18)\])", line, re.IGNORECASE)
		orLoadLDR = re.match("^(or) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x18)\])", line, re.IGNORECASE)
		xchgLoadLDR = re.match("^(xchg) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x18)\])", line, re.IGNORECASE)
		
		if(movLoadLDR or addLoadLDR or adcLoadLDR or xorLoadLDR or orLoadLDR or xchgLoadLDR):
			points += 1


		###############################################

		#offsets from https://www.tophertimzen.com/blog/windowsx64Shellcode/

		movLoadInMemOrder = re.match("^(mov) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x20)\])", line, re.IGNORECASE)
		addLoadInMemOrder = re.match("^(add) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x20)\])", line, re.IGNORECASE)
		adcLoadInMemOrder = re.match("^(adc) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x20)\])", line, re.IGNORECASE)
		xorLoadInMemOrder = re.match("^(xor) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x20)\])", line, re.IGNORECASE)
		orLoadInMemOrder = re.match("^(or) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x20)\])", line, re.IGNORECASE)
		xchgLoadInMemOrder = re.match("^(xchg) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x20)\])", line, re.IGNORECASE)

		if(movLoadInMemOrder or addLoadInMemOrder or adcLoadInMemOrder or xorLoadInMemOrder or orLoadInMemOrder or xchgLoadInMemOrder):
			points += 1



		###############################################

		movLoadInLoadOrder = re.match("^(mov) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x10)\])", line, re.IGNORECASE)
		addLoadInLoadOrder = re.match("^(add) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x10)\])", line, re.IGNORECASE)
		adcLoadInLoadOrder = re.match("^(adc) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x10)\])", line, re.IGNORECASE)
		xorLoadInLoadOrder = re.match("^(xor) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x10)\])", line, re.IGNORECASE)
		orLoadInLoadOrder = re.match("^(or) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x10)\])", line, re.IGNORECASE)
		xchgLoadInLoadOrder = re.match("^(xchg) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x10)\])", line, re.IGNORECASE)

		if(movLoadInLoadOrder or addLoadInLoadOrder or adcLoadInLoadOrder or xorLoadInLoadOrder or orLoadInLoadOrder or xchgLoadInLoadOrder):
			points += 1
		###############################################


		movLoadInInitOrder = re.match("^(mov) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x30)\])", line, re.IGNORECASE)
		addLoadInInitOrder = re.match("^(add) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x30)\])", line, re.IGNORECASE)
		adcLoadInInitOrder = re.match("^(adc) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x30)\])", line, re.IGNORECASE)
		xorLoadInInitOrder = re.match("^(xor) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x30)\])", line, re.IGNORECASE)
		orLoadInInitOrder = re.match("^(or) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x30)\])", line, re.IGNORECASE)
		xchgLoadInInitOrder = re.match("^(xchg) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?(0x30)\])", line, re.IGNORECASE)

		if(movLoadInInitOrder or addLoadInInitOrder or adcLoadInInitOrder or xorLoadInInitOrder or orLoadInInitOrder or xchgLoadInInitOrder):
			points += 1

		###############################################	

		movDereference = re.match("^(mov) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((d|q)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15))))\])", line, re.IGNORECASE)
		addDereference = re.match("^(add) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((d|q)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15))))\])", line, re.IGNORECASE)
		adcDereference = re.match("^(adc) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((d|q)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15))))\])", line, re.IGNORECASE)
		orDereference = re.match("^(or) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((d|q)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15))))\])", line, re.IGNORECASE)
		xorDereference = re.match("^(xor) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((d|q)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15))))\])", line, re.IGNORECASE)
		xchgDereference = re.match("^(xchg) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((d|q)word ptr ?(ds:)?\[((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15))))\])", line, re.IGNORECASE)

		if(movDereference or addDereference or adcDereference or orDereference or xorDereference or xchgDereference):
			points += 1


		###############################################

		lod = re.match("^(lodsq)|(lodsd)", line, re.IGNORECASE)

		if(lod):
			points += 1
	# pebPresent = True
	# print(pebPoints, type(pebPoints))
	# input()
	if not pebPresent:

		if(points >= pebPoints):
			if rawHex:
				modSecName = 'N/A'
			else:
				modSecName = section.sectionName
			saveBasePEBWalk_64(address, NumOpsDis, modSecName, secNum, points)
	else:

		if(points >= pebPoints and pebFound):
			if rawHex:
				modSecName = 'N/A'
			else:
				modSecName = section.sectionName
			saveBasePEBWalk_64(address, NumOpsDis, modSecName, secNum, points)


def saveBasePEBWalk_old(address, NumOpsDis,modSecName,secNum, points): 
	# print("saving")
	#save virtaul address as well
	if(secNum != "noSec"):
		s[secNum].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))
	else:
		secNum = -1
		modSecName = "rawHex"
		m[o].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))



def checkBasePEBWalk_64(address, NumOpsDis,modSecName,secNum, points): ############## AUSTIN ####################
	Good=True
	for section in s:
		for item in section.save_PEB_info:
			addy=item[0]
			nuOp=item[1]
			if address == addy and NumOpsDis==nuOp:
				print ("BADDD")
				Good=False
				return Good
	return Good


def saveBasePEBWalk_64(address, NumOpsDis,modSecName,secNum, points): ############## AUSTIN ####################
	#print "saving"
	#save virtaul address as well

	
	check = tuple((address,NumOpsDis,modSecName,secNum,points))

	if(secNum != "noSec"):
		if check not in s[secNum].save_PEB_info:
		# checkBasePEBWalk_64(address, NumOpsDis,modSecName,secNum, points)
			s[secNum].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))
	else:
		if check not in m[o].save_PEB_info:
			secNum = -1
			modSecNmae = "rawHex"
			m[o].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))
# print ("#############################################################################")


def printSavedPEB(): ######################## AUSTIN ###############################3
	#formatting
	global rawData2
	dprint2 ("printSavedPEB", len(rawData2))
	dprint2 ("m[o].save_PEB_info", len(m[o].save_PEB_info))
	dprint2 ("rawhex", rawHex)
	j = 0

	if(rawHex):
		for item in m[o].save_PEB_info:

			mods = ', '.join(item[7])
			adv = item[8]
			# input()
			if -1 in adv:
				adv = 'N/A'
			else:
				if(len(adv) > 1):
					adv = ', '.join(str(adv))
				else:
					adv = str(adv[0])
			print("OFFSETS: ")

			print("PEBWALKSTART = " + mag +str(hex(item[0])) + res)
			print("TIB = " + mag + str(item[5])+res)
			print("LDR = " + mag + str(item[6])+res)
			print("MODS = " + mag + str(mods)+res)
			print("Adv = " + mag + str(adv)+res)


			CODED2 = b""

			address = item[0]
			NumOpsDis = item[1]
			modSecName = item[2]
			secNum = item[3]
			points = item[4]

			CODED2 = rawData2[address:(address+NumOpsDis)]

			outString = "\n\nItem: " + str(j) + " | Points: " + str(points)
			if(secNum != -1):

				outString += " | Section: " + str(secNum) + " | Section name: " + str(modSecName)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName

			print ("\n******************************************************************************")
			print (yel + outString + res)
			print ("\n")
			val =""
			val2 = []
			val3 = []
			#address2 = address + section.ImageBase + section.VirtualAdd
			val5 =[]
			for i in cs.disasm(CODED2, address):
				if(rawHex):
					add4 = hex(int(i.address))
					addb = hex(int(i.address))
				else:
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	))
					add4 = str(add3)
				val = formatPrint(i, add4, addb)

				# val =  gre + i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + cya + " (offset " + addb + ")\n" + res
				print (val)
	#return val5
			print ("\n")
			j += 1
	else:
		h = 0
		for section in s:
			h += 1
			# print("PRINTING SECTION " + str(h))
			for item in section.save_PEB_info:
				mods = item[7]
				if -1 in mods:
					mods = 'N/A'
				else:
					if(len(mods) > 1):
						mods = ', '.join(item[7])
				# input()
				
				CODED2 = ""


				print("OFFSETS: ")
				print("PEBWALKSTART = " + mag +str(hex(item[0])) + res)
				print("TIB = " + mag + str(item[5])+res)
				print("LDR = " + mag +str(item[6])+res)
				print("MODS = " + mag + str(mods)+res)

				for adv in item[8]:
					if adv == -1:
							adv = 'N/A'
					print("Adv = " + mag + str(adv)+res)

				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				points = item[4]

				section = s[secNum]

				outString = "\n\nItem: " + str(j) + " | Points: " + str(points)
				if(secNum != -1):

					outString += " | Section: " + str(secNum) + " | Section name: " + modSecName.decode()
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				print ("\n******************************************************************************")
				print (yel + outString + res)
				print ("\n")
				val =""
				val2 = []
				val3 = []
				address2 = address + section.ImageBase + section.VirtualAdd
				val5 =[]

				CODED2 = section.data2[address:(address+NumOpsDis)]

				CODED3 = CODED2
				for i in cs.disasm(CODED3, address):
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	))
					add4 = str(add3)
					val = formatPrint(i, add4, addb, pe=True)

					# val =  gre + i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + cya + " (offset " + addb + ")" + res
					val2.append(val)
					val3.append(add2)
					val5.append(val)
					print (gre + val + res)
				print ("\n")
				j += 1
				# print str(type(m[o].data2))
				# trash = raw_input("enter...")


def printSavedPEB_64(): ############## AUSTIN ####################
	#formatting
	j = 0
	if(rawHex):
		for item in m[o].save_PEB_info:
			CODED2 = b""

			address = item[0]
			NumOpsDis = item[1]
			modSecName = item[2]
			secNum = item[3]
			points = item[4]

			CODED2 = rawData2[address:(address+NumOpsDis)]

			outString = yel + "\n\nItem: " + str(j) + " | Points: " + str(points) + res
			if(secNum != -1):

				outString += yel + " | Section: " + str(secNum) + " | Section name: " + modSecName + res
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
					
			else:
				outString += yel + " | Module: " + cya + modSecName + res

			print ("\n******************************************************************************")
			print ( outString )
			print ("\n")
			val =""
			val2 = []
			val3 = []
			#address2 = address + section.ImageBase + section.VirtualAdd
			val5 =[]


			for i in cs64.disasm(CODED2, address):
				if(rawHex):
					add4 = hex(int(i.address))
					addb = hex(int(i.address))
				else:
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	))
					add4 = str(add3)
				val = formatPrint(i, add4, addb)

				# val =  gre + i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + cya + " (offset " + addb + ")\n" + res
				# val2.append(val)
		# val3.append(add2)
		# val5.append(val)
				print (val)
	#return val5
			print ("\n")
			j += 1
	else:
		h = 0
		for section in s:
			h += 1
			
			# print("PRINTING SECTION " + str(h))
			w=0
			for item in section.save_PEB_info:
				CODED2 = ""

				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				points = item[4]

				section = s[secNum]

				# outString = "h: "+str(h) +"w: "+str(w)+
				outString = "\n\nItem: " + str(j) + " | Points: " + str(points)
				if(secNum != -1):

					outString += " | Section: " + str(secNum) + " | Section name: " + modSecName.decode()
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				print ("\n******************************************************************************")
				print (outString)
				print ("\n")
				val =""
				val2 = []
				val3 = []
				address2 = address + section.ImageBase + section.VirtualAdd
				val5 =[]

				CODED2 = section.data2[address:(address+NumOpsDis)]

				CODED3 = CODED2
				for i in cs64.disasm(CODED3, address):
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	))
					add4 = str(add3)
					val = formatPrint(i, add4, addb, pe=True)

					# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					val5.append(val)
					print (val)
				print ("\n")
				j += 1
				w+=1
				# print str(type(m[o].data2))
				# trash = raw_input("enter...")


def get_PushRet_start(NumOpsDis ,bytesToMatch, secNum, data2): ######################### AUSTIN #############################
	# print ("get_PushRet_start", (NumOpsDis ,bytesToMatch, secNum))
	# print (binaryToStr(data2))
	global o
	foundCount = 0
	numOps = NumOpsDis

	t=0
	len_data2 = len(data2)
	len_bytesToMatch = len(bytesToMatch)
	
	for v in data2:
		found = True #reset flag
		#replace with bytesToMatch list if desired
		#for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
		i = 0
		for x in bytesToMatch:
			if(found == False):
				break
			# elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
			# 	found = False # out of range
			try:
				#print(data2[t+i])
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				# input(e)
				# print ("ERROR")
				print (e)
				pass
			i += 1
		
		if(found):
			# print("Matched: ", hex(v))
			# input()
			disHerePushRet(t, numOps, secNum, data2)


		t=t+1


	


def disHerePushRet(address, NumOpsDis, secNum, data): ############################# AUSTIN ############################

	# print("inDisherePush")
	# print (binaryToStr(data))
	
	CODED2 = ""
	x = NumOpsDis

	if(secNum != "noSec"):
		section = s[secNum]
		# start = timeit.default_timer()

	CODED2 = data[address:(address+NumOpsDis)]
	# I create the individual lines of code that will appear>
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]
	points = 0	
	foundPush = False
	foundRet = False
	pushReg = ""
	# start = timeit.default_timer()
	CODED3 = CODED2
	for i in cs.disasm(CODED3, address):
		if(secNum == "noSec"):
			# add = hex(int(i.address))
			add4 = hex(int(i.address))
			addb = hex(int(i.address))
		else:
			add = hex(int(i.address))
			addb = hex(int(i.address +  section.VirtualAdd))
			add2 = str(add)
			add3 = hex (int(i.address + section.startLoc	))
			add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		val5.append(val)

		push = re.match("^push ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8|9|(1([0-5])))))", val, re.IGNORECASE)
		#print("-->", val)
		if(push):
			pushReg = i.op_str
			# print("Push found", pushReg)
			
			foundPush = True
			# points += 1
			pushOffset = addb
			# print("Push offset", str(pushOffset))
			# input()

		# if(pushea):
		# 	print("Found pushea")
		# print("hereismeandyhoney")

		ret = re.match("^ret", val, re.IGNORECASE)
		retf = re.match("^retf", val, re.IGNORECASE)

		if(ret and not retf and foundPush):
			# print("Found Ret: ", val, addb)
			# input()
			foundRet = True
			# points += 1
			retOffset = addb


		# print(val)
	# stop = timeit.default_timer()
	# print("Time 2: " + str(stop - start))

	#input("enter..")


	# disString = val5



	# for line in disString:

	# 	##############################################

		# push = re.match("^push ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8|9|(1[0-5]))))", line, re.IGNORECASE)
		# ret = re.match("^ret", line, re.IGNORECASE)

		# if(push):
		# 	points += 1

		# if(ret):
		# 	points += 1


		if foundPush and foundRet:
			foundPush = False
			foundRet = False
			if(rawHex):
				modSecName = peName
			else:
				modSecName = section.sectionName
			# print("Pushoffset", pushOffset, "Ret", retOffset)
			# input()

			saveBasePushRet(address, NumOpsDis, modSecName, secNum, points, (pushOffset, pushReg), retOffset)

def disHerePushRet64(address, NumOpsDis, secNum, data): ############################# AUSTIN ############################

	# print("inDisherePush ", address)
	CODED2 = ""
	x = NumOpsDis
	linesGoBack = 10
	if(secNum != "noSec"):
		section = s[secNum]
		# start = timeit.default_timer()
	CODED2 = data[address:(address+NumOpsDis)+1]

	# I create the individual lines of code that will appear>
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]

	points = 0
	foundPush = False
	foundRet = False
	pushReg = ""
	# start = timeit.default_timer()
	CODED3 = CODED2
	for i in cs64.disasm(CODED3, address):
		if(secNum == "noSec"):
			# add = hex(int(i.address))
			add4 = hex(int(i.address))
			addb = hex(int(i.address))
		else:
			# print("heree")
			add = hex(int(i.address))
			addb = hex(int(i.address +  section.VirtualAdd))
			add2 = str(add)
			add3 = hex (int(i.address + section.startLoc	))
			add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		val5.append(val)
		# if not push:
		push = re.match("^push ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8|9|(1([0-5])))))", val, re.IGNORECASE)
		if(push):
			pushReg = i.op_str
			# points += 1
			foundPush = True
			pushOffset = addb
		ret = re.match("^ret", val, re.IGNORECASE)
		if(ret):
			foundRet = True
			# points += 1
			retOffset = addb



		# print("val is",val)
	# stop = timeit.default_timer()
	# print("Time 2: " + str(stop - start))

	#input("enter..")


	# points = 0
	# disString = val5



	# for line in disString:

	# 	##############################################
	# 	push = re.match("^push ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8|9|(1([0-5])))))", line, re.IGNORECASE)
	# 	ret = re.match("^ret", line, re.IGNORECASE)


	# 	if(push):
	# 		points += 1

	# 	if(ret):
	# 		points += 1

		# if(ret):
		# 	# print("ret matches")
		# 	points += 1


	# print("Points are: ", points, push, ret)
	if(foundPush) and (foundRet):

		if(rawHex):
			modSecName = peName
		else:
			modSecName = section.sectionName
		saveBasePushRet(address, NumOpsDis, modSecName, secNum, points, (pushOffset, pushReg), retOffset)



def PushRetrawhex(address, secNum, data):
	global bit32
	global ignoreDisDiscovery
	global linesForward
	address = hex(address)
	# linesGoBack = 10
	linesGoBack = linesBack
	# print("Lines Forward", linesForward)
	# input()
	t = 0
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, 0x0, linesGoBack)  # arg: starting offset/entry point - leave 0 generally
	# print("------------>", orgListOffset,orgListDisassembly)
	# input()
	if(ignoreDisDiscovery):
		truth = False

	if (truth):
		# print ("truth2")
		for e in orgListDisassembly:
			pushReg = ""
			isPUSH = re.search("push", e, re.IGNORECASE)
			if isPUSH:
				# print ("truth3")
				# print(res)
				# print("Found push, offset=", hex(orgListOffset[t]))
				try:
					pushReg = orgListDisassembly[t].split()[1]
				except Exception as e:

					pushReg = orgListDisassembly[t].split()
					# print("Push ret function", e)
					# input()
				# print ("pushreg", pushReg)
				# input()

				push_offset = hex(orgListOffset[t])
				address = int(orgListOffset[t])
				index = 0
				chunk = orgListDisassembly[t+1:t+linesForward]
				chunkOffsets = orgListOffset[t+1:t+linesForward]
				for item in chunk:
					bad = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(db)|(hlt)|(loop)|(leave)|(int3)|(insd)|(enter)|(jns)|(call)|(retf)|(push))", item, re.M|re.I)
					if(bad):
						# print("bad")
						break
					# print("item: ",item)
					isRET = re.search("ret", item, re.IGNORECASE)
					isRETF = re.search("retf", item, re.IGNORECASE)
					if (isRET):
						if not isRETF:
							# print ("item",item)
							ret_offset = hex(orgListOffset[index + t + 1])

							# print("isret")
							# print("saved a pushret: push = ", push_offset, " ret = ", ret_offset)
							saveBasePushRet(address, linesForward, 'noSec', secNum, 2, (push_offset,pushReg), ret_offset)

							break
						# else:
							# print("item ----> ", item)
					index += 1
			t+=1	 

	else:

		for match in PUSH_RET.values():
			if bit32:
				get_PushRet_start(4, match, secNum, data)
			else:
				get_PushRet_start64(4, match, secNum, data)

	if(rawHex):
		m[o].save_PushRet_info = helperListToSet(m[o].save_PushRet_info)
	else:
		s[secNum].save_PushRet_info =helperListToSet(s[secNum].save_PushRet_info)


def PushRetrawhex2(address, secNum, data):
	global bit32
	global ignoreDisDiscovery
	global linesForward
	address = hex(address)
	linesGoBack = 10
	t = 0
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, 0x0, linesGoBack)  # arg: starting offset/entry point - leave 0 generally
	# print("------------>", orgListOffset,orgListDisassembly)
	# input()
	if(ignoreDisDiscovery):
		truth = False

	if (truth):
		t = [orgListDisassembly.index(i) for i in orgListDisassembly if "push" in i]
		if t != []:
			t = t[0]

		# print ("truth2")
		# for e in orgListDisassembly:
			pushReg = ""
			# isPUSH = re.search("push", e, re.IGNORECASE)
			# if "push" in 
			# if isPUSH:
				# print ("truth3")
				# print("ispush")
			try:
				pushReg = orgListDisassembly[t].split()[1]
			except Exception as e:

				pushReg = orgListDisassembly[t].split()
				# print("Push ret function", e)
				# input()
			# print ("pushreg", pushReg)
			# input()

			push_offset = hex(orgListOffset[t])
			address = int(orgListOffset[t])
			index = 0
			chunk = orgListDisassembly[t+1:t+linesForward]
			chunkOffsets = orgListOffset[t+1:t+linesForward]
			for item in chunk:
				bad = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(db)|(hlt)|(loop)|(leave)|(int3)|(insd)|(enter)|(jns)|(call)|(retf))", item, re.M|re.I)
				if(bad):
					# print("bad")
					break
				# print("item: ",item)
				isRET = re.search("ret", item, re.IGNORECASE)
				isRETF = re.search("retf", item, re.IGNORECASE)
				if (isRET):
					if not isRETF:
						# print ("item",item)
						ret_offset = hex(orgListOffset[index + t + 1])

						# print("isret")
						# print("saved a pushret: push = ", push_offset, " ret = ", ret_offset)
						saveBasePushRet(address, linesForward, 'noSec', secNum, 2, (push_offset,pushReg), ret_offset)

						break
					# else:
						# print("item ----> ", item)
				index += 1
			t+=1	 

	else:

		for match in PUSH_RET.values():
			if bit32:
				get_PushRet_start(4, match, secNum, data)
			else:
				get_PushRet_start64(4, match, secNum, data)

def saveBasePushRet(address, NumOpsDis,modSecName,secNum, points, pushOffset, retOffset): ################## AUSTIN ##############################
	# print ("saving", hex(address))
	#save virtaul address as well
	if(secNum != "noSec"):

		for each in s[secNum].save_PushRet_info:
			if retOffset == each[6]:
				return
		s[secNum].save_PushRet_info.append(tuple((address,NumOpsDis,modSecName,secNum,points, pushOffset, retOffset)))


	else:
		secNum = -1
		modSecName = "rawHex"
		for each in m[o].save_PushRet_info:
			if retOffset == each[6]:
				return
		# print("Saving pushoffset", pushOffset, retOffset)
		# input()

		m[o].save_PushRet_info.append(tuple((address,NumOpsDis,modSecName,secNum,points, pushOffset, retOffset)))


def printSavedPushRet(bit = 32): ############################## AUSTIN #############################
		#formatting
	j = 0
	if bit == 32:
		callCS = cs
	else:
		callCS = cs64
	if(rawHex):
		for item in m[o].save_PushRet_info:
			CODED2 = b""

			address = item[0]
			NumOpsDis = item[1]
			modSecName = item[2]
			secNum = item[3]
			points = item[4]
			pushOffset = item[5]
			retOffset = item[6]
			printEnd = int(retOffset, 16) + 15

			# CODED2 = rawData2[address:(address+NumOpsDis)]
			CODED2 = rawData2[address:(printEnd)]

			outString = "Item: " + str(j) + " | Points: " + str(points)

			if(secNum != -1):

				outString += " | Section: " + str(secNum) + " | Section name: " + str(modSecName)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName

			pushOffset = ', '.join(pushOffset)
			outString += " | PUSH Offset: " + str(pushOffset) + " | RET Offset: " + str(retOffset)

			print ("\n******************************************************************************")

			print (yel + outString + res)
			print ("\n")
			val =""
			val2 = []
			val3 = []
			#address2 = address + section.ImageBase + section.VirtualAdd
			val5 =[]

			# if bit == 32:
			for i in callCS.disasm(CODED2, address):
				if(rawHex):
					add4 = hex(int(i.address))
					addb = hex(int(i.address))
				else:
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	))
					add4 = str(add3)
				val = formatPrint(i, add4, addb)
				# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
				print (gre + val + res)
				if(addb == retOffset):
					break
			# if bit == 64:
			# 	for i in cs64.disasm(CODED2, address):
			# 		if(rawHex):
			# 			add4 = hex(int(i.address))
			# 			addb = hex(int(i.address))
			# 		else:
			# 			add = hex(int(i.address))
			# 			addb = hex(int(i.address +  section.VirtualAdd))
			# 			add2 = str(add)
			# 			add3 = hex (int(i.address + section.startLoc	))
			# 			add4 = str(add3)
			# 		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
			# 		print (gre + val + res)
			# 		if(addb == retOffset):
			# 			break
	#return val5

			# print ("\n")
			t = 0
			for each in val5:
				# if (t<2):
					# print(each)
				print(each)
				t+=1
			j += 1
	else:
		h = 0
		for section in s:
			h += 1
			for item in section.save_PushRet_info:
				CODED2 = ""
				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				points = item[4]
				pushOffset = item[5]
				retOffset = item[6]
				section = s[secNum]
				printEnd = int(retOffset, 16) + 3 - section.VirtualAdd
				outString = "Item: " + str(j) + " | Points: " + str(points)

				if(secNum != -1):

					outString += " | Section: " + str(secNum) + " | Section name: " + modSecName.decode()
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName
				pushOffset = ', '.join(pushOffset)
				outString += " | PUSH Offset: " + str(pushOffset) + " | RET Offset: " + str(retOffset)

				print ("\n******************************************************************************")

				print (yel + outString + res)
				print ("\n")
				val =""
				val2 = []
				val3 = []
				address2 = address + section.ImageBase + section.VirtualAdd
				val5 =[]

				# CODED2 = section.data2[address:(address+NumOpsDis)]
				CODED2 = section.data2[address:printEnd]


				CODED3 = CODED2
				stopRet = False
				# print("pushret print function", CODED3.hex())
				for i in callCS.disasm(CODED3, address):
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	))
					add4 = str(add3)
					val = formatPrint(i, add4, addb, pe=True)

					# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					checkRet= re.search( retOffset, val, re.M|re.I)
					if checkRet:
						if not stopRet:
							val5.append(val)
							stopRet = True
						else:
							pass
					if not stopRet:
						val5.append(val)
					# val5.append(val)
				# if bit == 64:
				# 	for i in cs64.disasm(CODED3, address):
				# 		add = hex(int(i.address))
				# 		addb = hex(int(i.address +  section.VirtualAdd))
				# 		add2 = str(add)
				# 		add3 = hex (int(i.address + section.startLoc	))
				# 		add4 = str(add3)
				# 		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
				# 		val2.append(val)
				# 		val3.append(add2)
				# 		val5.append(val)
					# print (val)
				# print ("\n")
				t = 0
				for each in val5:
					# if (t<2):
					# 	print(each)
					print(gre + each + res)
					# if(addb == retOffset):
						# break
					t+=1

				j += 1
				# print str(type(m[o].data2))
				# trash = raw_input("enter...")

def get_FSTENV(NumOpsDis, NumOpsBack, bytesToMatch, secNum, data2): 
	#change to work off of data2 - add param - get rid of secNum

	global o
	foundCount = 0
	numOps = NumOpsDis


	t=0
	len_data2 = len(data2)
	len_bytesToMatch = len(bytesToMatch)
	for v in data2:
		found = True #reset flag
		#replace with bytesToMatch list if desired
		#for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
		i = 0
		for x in bytesToMatch:
			if(found == False):
				break
			# elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
			# 	found = False # out of range
			try:
				#dprint2(data2[t+i])
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				# input(e)
				pass
			i += 1

		if(found):
			# input("enter..")

			# dprint2(hex(s[secNum].VirtualAdd + t))
			# dprint2("found1", hex(x), "t", hex(t))

			disHereFSTENV(t, numOps, NumOpsBack, secNum, data2)

			

		t=t+1


fcount = 0

def get_PushRet_start64(NumOpsDis ,bytesToMatch, secNum, data2): ######################### AUSTIN #############################

	global o
	foundCount = 0
	numOps = NumOpsDis

	t=0
	len_data2 = len(data2)
	len_bytesToMatch = len(bytesToMatch)



	for v in data2:
		found = True #reset flag
		#replace with bytesToMatch list if desired
		#for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
		i = 0
		for x in bytesToMatch:
			# print(binaryToStr(data2[t+i-3:t+i+3]))
			if(found == False):
				break
			# elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
			# 	found = False # out of range
			try:
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				# input(e)
				pass
			i += 1

		if(found):
			# input("enter..")
			# print("offset ", hex(t + s[secNum].VirtualAdd))
			# print(binaryToStr(data2[t:t+i]))
			# for match in EGGHUNT.values():
			# 	getSyscallPE(20, 20, match, secNum, data2)
			disHerePushRet64(t, numOps, secNum, data2)

		t=t+1





def findAllPushRet64(data2, secNum): ################## AUSTIN #########################
	if(secNum == 'noSec'):
		PushRetrawhex(0, 'noSec', data2)
	else:
		for match in PUSH_RET.values():
			optimized_find(4, match, secNum, data2, "disHerePushRet64")
			# get_PushRet_start64(4, match, secNum, data2)
			#disHerePushRet64(t, numOps, secNum, data2)


def findAllPushRet64_old2(data2, secNum): ################## AUSTIN #########################
	if(secNum == 'noSec'):
		PushRetrawhex(0, 'noSec', data2)
	else:
		for match in PUSH_RET.values():
			get_PushRet_start64(4, match, secNum, data2)

#NumOpsBack: how many opcodes to search back when looking for fpu instruction
def disHereFSTENV(address, NumOpsDis, NumOpsBack, secNum, data): ############ AUSTIN ##############

	global o
	global total1
	global total2
	global fcount
	w=0
	if shellBit == 32:
		callCS = cs
	else:
		callCS = cs64
	## Capstone does not seem to allow me to start disassemblying at a given point, so I copy out a chunk to  disassemble. I append a 0x00 because it does not always disassemble correctly (or at all) if just two bytes. I cause it not to be displayed through other means. It simply take the starting address of the jmp [reg], disassembles backwards, and copies it to a variable that I examine more closely.
	#lGoBack = linesGoBackFindOP

	# dprint2("disHere")
	# dprint2(hex(address))
	# dprint2(secNum)
	#input("addy")

	CODED2 = ""
	x = NumOpsDis
	# start = timeit.default_timer()
	if(secNum != "noSec"):
		section = s[secNum]


	# dprint2("------------------------------------")

	for back in range(NumOpsBack):
		# dprint2("back = " + str(back))
		CODED2 = data[(address-(NumOpsBack-back)):(address+x)]
			#dprint2("########################")
		#	dprint2(type(CODED2))
		#	dprint2("########################")
		#
		# stop = timeit.default_timer()
		# total1 += (stop - start)
		# dprint2("Time 1 PEB: " + str(stop - start))

		# I create the individual lines of code that will appear>
		# dprint2(len(CODED2))
		val =""
		val2 = []
		val3 = []
		#address2 = address + section.ImageBase + section.VirtualAdd
		val5 =[]
		valOffsets =[]
		# start = timeit.default_timer()
		#CODED3 = CODED2.encode()
		CODED3 = CODED2

		# dprint2("BINARY2STR")
		# dprint2(binaryToStr(CODED3))
		# dprint2("******************************************")

		t = 0
		for i in callCS.disasm(CODED3, (address -(NumOpsBack-back))):

			#dprint2('address in for = ' + str(address))
			if(secNum == "noSec"):

			#	dprint2("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
				# add = hex(int(i.address))
				add4 = hex(int(i.address))
				addb = hex(int(i.address))
			else:
				add = hex(int(i.address))
				# addb = hex(int(i.address +  section.VirtualAdd  - (NumOpsBack - back) ))
				addb = hex(int(i.address +  section.VirtualAdd))
				add2 = str(add)
				# add3 = hex (int(i.address + section.startLoc	- (NumOpsBack - back) ))
				add3 = hex (int(i.address + section.startLoc))
				add4 = str(add3)
			val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
			# val2.append(val)
			# val3.append(add2)
			val5.append(val)
			valOffsets.append(addb)
			# dprint2("herejsj", addb)
			# dprint2(val)


			disString = val5

			#we save when the fpu instr is the first one 
			# match instructions beginning with "f" but is not fstenv or fnstenv
			FPU_instr = re.match("^f((?!n?stenv).)*$", disString[0], re.IGNORECASE)
			fstenv = False
			if(FPU_instr):

				dprint2("matched fpu")
				dprint2(disString[0])
				FPU_offset = valOffsets[t]
				dprint2("FPU OFF3 = " + str(FPU_offset))
				FPU_offset = FPU_offset[:-1]
				test = valOffsets[0]
				FPU_offset = test
				# dprint2("FPU OFF3 = " + str(FPU_offset) + "\n\n")
				# input("fpu2")
				# print("disString = ", disString)
				# print("valOffsets = ", valOffsets)
				w = 0
				for line in disString:
					FSTENV_instr = False
					FSTENV_instr = re.match("^fn?stenv", line, re.IGNORECASE)
					#SGN_POP_instr = re.match("^pop (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
					#SGN_KEY_instr = re.match("^mov (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp))), ?0x[0-9a-f]{1,8}")

					if(FSTENV_instr):

						FSTENV_offset = valOffsets[w]
						# print("SAVING FSTENV OFFSET: ", FSTENV_offset, " AT LINE: ", line)
						# dprint2("1d: ", line,FSTENV_offset)
						# dprint2(w, len(valOffsets), len(disString))
						try:
							printEnd = valOffsets[w+1]
						except:
							dprint2("bad2")
							break
							pass

						fcount += 1
						# dprint2("CONFIRMED FSTENV -- NUMBER " + str(fcount))
						# dprint2("SAVING THIS ONE")
						if(rawHex):
							modSecName = peName
						else:
							modSecName = section.sectionName
						saveBaseFSTENV(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, FPU_offset, FSTENV_offset, printEnd)
						break
						# return   #If we return here, we might have caught one that's close by, but already exists... instead we break, because even if we catch an old one, it won't save.
					w+=1
			t+=1



def FSTENVrawhex(address, linesBack2, secNum, data):
	global bit32
	global ignoreDisDiscovery
	global linesBack
	# linesBack = 10
	linesBack = linesBack2
	# print("Lines Back --> ", linesBack)
	address = int(address)
	linesGoBack = 10

	t = 0
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, 0x0, linesGoBack)
	# truth = False
	# print("done")
	# t = 0
	# for line in orgListDisassembly:
	# 	dprint2(hex(orgListOffset[t]), "   ", orgListDisassembly[t])
	# 	t+=1
	if(ignoreDisDiscovery):
		truth = False
	t = 0
	chunk = ""
	chunkOffsets = ""
	if(truth):
		# removeAmount=len(orgListDisassembly) - linesBack
		# orgListDisassembly=orgListDisassembly[removeAmount:]
		# orgListOffset=orgListOffset[removeAmount:]

		# print("After List modification")
		# print ("removeAmount", removeAmount, "size", len(orgListDisassembly), "linesBack", linesBack)
		for e in orgListDisassembly:

			# print (e)
			# print(e)
			isFSTENV = re.search("^fn?stenv", e, re.IGNORECASE)
			if isFSTENV:
				# print("Found fst instruction")
				FSTENV_offset = hex(orgListOffset[t])
				# print("offset: ", FSTENV_offset)   #Offset of fstenv
				address = int(orgListOffset[t])
				fpuIndex = 0	

				isFPU, fpuIndex = get_FPUInstruction(orgListDisassembly, orgListOffset, linesBack, t)
				# t_temp -= 1 


				if isFPU:
					# print("Found fstenv")
					# input()
					# dprint2("hello", t_temp)
					FPU_offset = hex(orgListOffset[fpuIndex])

					try:
						printEnd = hex(orgListOffset[t+1])
						# dprint2(t - t_temp)
						if ((t - linesGoBack) < 0):
							linesGoBack = t
						saveBaseFSTENV(address, (t - fpuIndex + 1), linesGoBack, peName, secNum, FPU_offset, FSTENV_offset, printEnd)
						# break

					except Exception as e:
						print(e)
						# break
						pass
			t += 1


	else:
		for match in FSTENV_GET_BASE.values(): #iterate through all opcodes representing combinations of registers
			get_FSTENV(10, 15, match, secNum, data)


	if(rawHex):
		m[o].save_FSTENV_info = helperListToSet(m[o].save_FSTENV_info)
	else:
		s[secNum].save_FSTENV_info =helperListToSet(s[secNum].save_FSTENV_info)

def get_FPUInstruction(orgListDisassembly, orgListOffset, linesGoBack, FSTENV_offset):
	fpuIndex = FSTENV_offset - 1
	isFPU = False

	# print("FSTENV_offset", FSTENV_offset, "linesGoBack", linesGoBack)
	if((FSTENV_offset-linesGoBack)<0):
		chunk = orgListDisassembly[0:FSTENV_offset]
		chunkOffsets = orgListOffset[0:FSTENV_offset]
	else:
		chunk = orgListDisassembly[FSTENV_offset-linesGoBack:FSTENV_offset]
		chunkOffsets = orgListOffset[FSTENV_offset-linesGoBack:FSTENV_offset]
	chunk.reverse()
	for i in chunk:
		# print("current inst", i)
		isFPU = re.search("^f((?!n?stenv).)*$", i, re.IGNORECASE)
		if isFPU:
			break
		fpuIndex-=1


	return isFPU, fpuIndex



def saveBaseFSTENV(address, NumOpsDis, NumOpsBack, modSecName, secNum, FPU_offset, FSTENV_offset, printEnd):
	# dprint2("Saving FS")
	if(secNum != "noSec"):
		dprint2("FPU OFF1 = " + str(FPU_offset))
		dprint2("FPU OFF2 = " + str(FPU_offset))
		dprint2("Fstenv OFF1 = " + str(FSTENV_offset))
		dprint2("Fstenv OFF2 = " + str(FSTENV_offset))
		# input("fpu2")
		for each in s[secNum].save_FSTENV_info:
			if FSTENV_offset == each[6]:
				dprint2("not saving FSTENV_offset ", FSTENV_offset, " because of a match. FPU_offset = ", FPU_offset)
				return

		s[secNum].save_FSTENV_info.append(tuple((address,NumOpsDis,NumOpsBack,modSecName,secNum,FPU_offset,FSTENV_offset, printEnd)))
	else:

		# dprint2("Pre-Saving one raw ", FPU_offset)
		secNum = -1
		modSecName = "rawHex"
		for each in m[o].save_FSTENV_info:
			if FPU_offset == each[5]:
				return
		dprint2("Actually Saving one raw ", FPU_offset)
		dprint2("FPU OFF1 = " + str(FPU_offset))
		dprint2("FPU OFF2 = " + str(FPU_offset))
		dprint2("Fstenv OFF1 = " + str(FSTENV_offset))
		dprint2("Fstenv OFF2 = " + str(FSTENV_offset))
		m[o].save_FSTENV_info.append(tuple((address,NumOpsDis,NumOpsBack,modSecName,secNum,FPU_offset,FSTENV_offset, printEnd)))


def printSavedFSTENV(bit = 32): ######################## AUSTIN ###############################3

	if bit == 32:
		callCS = cs
	else:
		callCS = cs64
	#formatting
	j = 0
	if(rawHex):
		for item in m[o].save_FSTENV_info:
			CODED2 = b""
			
			address = item[0]
			NumOpsDis = item[1]
			NumOpsBack = item[2]
			modSecName = item[3]
			secNum = item[4]
			FPU_offset  = item[5]
			FSTENV_offset = item[6]
			printEnd = item[7]
			# print("OFFSETS: ")
			# print("FPU = " + str(FPU_offset))
			# print("FSTENV = " + str(FSTENV_offset))

			# CODED2 = rawData2[(address-NumOpsBack):(address+NumOpsDis)]
			CODED2 = rawData2[int(FPU_offset, 16):(int(printEnd, 16))]
			# CODED2 = rawData2[(address - NumOpsBack):(int(printEnd, 16))]
			dprint2("PRINT START = " + hex(address-NumOpsBack))
			dprint2("PRINTEND = " + hex(int(printEnd,16)))


			outString = "\n\nItem: " + str(j)
			if(secNum != -1):


				outString += " | Section: " + str(secNum) + " | Section name: " + str(modSecName) + " | FPU Offset: " + str(FPU_offset) + " | FSTENV Offset: " + str(FSTENV_offset)

				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:

				outString += " | Module: " + modSecName + " | FPU Offset: " + str(FPU_offset) + " | FSTENV Offset: " + str(FSTENV_offset)



			print ("\n******************************************************************************")
			print (yel + outString + res)
			print ("\n")
			val =""
			val2 = []
			val3 = []
			#address2 = address + section.ImageBase + section.VirtualAdd
			val5 =[]

			# if bit==32:
			for i in callCS.disasm(CODED2, (address - NumOpsBack)):
				if(rawHex):
					add4 = hex(int(i.address))
					addb = hex(int(i.address))
				else:
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	))
					add4 = str(add3)
				val = formatPrint(i, add4, addb)
				# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
				val5.append(val)
				print(gre + val + res)


			# print (gre + val + res)
			# if bit==64:
			# 	for i in cs64.disasm(CODED2, (address - NumOpsBack)):
			# 		if(rawHex):
			# 			add4 = hex(int(i.address))
			# 			addb = hex(int(i.address))
			# 		else:
			# 			add = hex(int(i.address))
			# 			addb = hex(int(i.address +  section.VirtualAdd))
			# 			add2 = str(add)
			# 			add3 = hex (int(i.address + section.startLoc	))
			# 			add4 = str(add3)

			# 	# if(hex(i.address) == printEnd):
			# 	# 	break
			# 		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
			# 		val5.append(val)

			# # print (gre + val + res)
			# 		print(gre + val + res)
	#return val5
			print ("\n")
			j += 1
	else:
		h = 0
		for section in s:
			h += 1
			# print("PRINTING SECTION " + str(h))
			for item in section.save_FSTENV_info:
				CODED2 = ""


				address = item[0]
				NumOpsDis = item[1]
				NumOpsBack = item[2]
				modSecName = item[3]
				secNum = item[4]
				FPU_offset  = item[5]
				FSTENV_offset = item[6]
				# print("OFFSETS: ")
				# print("FPU = " + FPU_offset)
				# print("FSTENV = " + FSTENV_offset)
				# print("NUMBACK = " + str(NumOpsBack))

				section = s[secNum]

				outString = "\n\nItem: " + str(j)
				if(secNum != -1):

					outString += " | Section: " + str(secNum) + " | Section name: " + modSecName.decode() + " | FPU Offset: " + str(FPU_offset) + " | FSTENV Offset: " + str(FSTENV_offset)
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName + " | FPU Offset: " + str(FPU_offset) + " | FSTENV Offset: " + str(FSTENV_offset)

				print ("\n******************************************************************************")
				print (yel + outString + res)
				print ("\n")
				val =""
				val2 = []
				val3 = []
				address2 = address + section.ImageBase + section.VirtualAdd
				val5 =[]

				CODED2 = section.data2[(address-NumOpsBack):(address+NumOpsDis)]

				CODED3 = CODED2
				# if bit == 32:
				for i in callCS.disasm(CODED3, address):
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd - NumOpsBack))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	- NumOpsBack))
					add4 = str(add3)
					val = formatPrint(i, add4, addb, pe=True)
					# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					val5.append(val)
					if str(FSTENV_offset) == addb: 
						print (gre + val + res)
						break
					else:
						print (gre + val + res)

				# if bit == 64:
				# 	for i in cs64.disasm(CODED3, address):
				# 		add = hex(int(i.address))
				# 		addb = hex(int(i.address +  section.VirtualAdd - NumOpsBack))
				# 		add2 = str(add)
				# 		add3 = hex (int(i.address + section.startLoc	- NumOpsBack))
				# 		add4 = str(add3)
				# 		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
				# 		val2.append(val)
				# 		val3.append(add2)
				# 		val5.append(val)
				# 		print (gre + val + res)
				print ("\n")
				j += 1
				# print str(type(m[o].data2))
				# trash = raw_input("enter...")


def get_Callpop(NumOpsDis, bytesToMatch, secNum, data2, distance): 
	#change to work off of data2 - add param - get rid of secNum

	# dprint2('in get')

	global o
	foundCount = 0
	numOps = NumOpsDis


	t=0
	len_data2 = len(data2)
	len_bytesToMatch = len(bytesToMatch)
	for v in data2:
		found = True #reset flag
		#replace with bytesToMatch list if desired
		#for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
		i = 0
		for x in bytesToMatch:
			if(found == False):
				break
			# elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
			# 	found = False # out of range
			try:
				#dprint2(data2[t+i])
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				# input(e)
				pass
			i += 1

		if(found):
			# input("enter..")
			disHereCallpop(t, numOps, secNum, data2, distance)

		t=t+1

def get_Callpop64(NumOpsDis, bytesToMatch, secNum, data2, distance): 
	#change to work off of data2 - add param - get rid of secNum
	# print ("get_Callpop64")

	global o
	foundCount = 0
	numOps = NumOpsDis


	t=0
	len_data2 = len(data2)
	len_bytesToMatch = len(bytesToMatch)
	for v in data2:
		found = True #reset flag
		#replace with bytesToMatch list if desired
		#for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
		i = 0
		for x in bytesToMatch:
			if(found == False):
				break
			# elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
			# 	found = False # out of range
			try:
				#dprint2(data2[t+i])
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				# input(e)
				pass
			i += 1

		if(found):
			# input("enter..")
			disHereCallpop64(t, numOps, secNum, data2, distance)

		t=t+1



def disHereCallpop(address, NumOpsDis, secNum, data, distance):
	# print("ENTERED DISHERECALLPOP")
	# dprint2("in dishere")
	pop = False
	CODED2 = ""
	x = NumOpsDis

	origAddr = address
	address = address + distance


	CODED2 = data[(origAddr):(address+5)]

	# I create the individual lines of code that will appear>
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]
	valOffsets = []
	
	if(secNum != "noSec"):
		section = s[secNum]
	# dprint2("HERE IS THE CALL LINE")
	# start = timeit.default_timer()
	CODED3 = CODED2
	for i in cs.disasm(CODED3, address):
		if(secNum == "noSec"):
			# add = hex(int(i.address))
			add4 = hex(int(i.address))
			addb = hex(int(i.address))
		else:
			add = hex(int(i.address))
			addb = hex(int(i.address +  section.VirtualAdd))
			add2 = str(add)
			add3 = hex (int(i.address + section.startLoc	))
			add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		val5.append(val)

		valOffsets.append(addb)
		# dprint2(val)



	disString = val5
	t = 0
	for line in disString:

		##############################################

		call = re.match("^call ", line, re.IGNORECASE)
		if(call):

			pop_addr = valOffsets[t]
			dprint2("POP ADDR = " + str(pop_addr))
		dprint2("POP OFFSET")
		t+=1



	if(secNum != "noSec"):
		section = s[secNum]
	CODED2 = data[(address):(address+NumOpsDis)]

	# I create the individual lines of code that will appear>
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]
	

	# dprint2("2ND CHUNK")
	# start = timeit.default_timer()
	CODED3 = CODED2
	for i in cs.disasm(CODED3, address):
		if(secNum == "noSec"):
			# add = hex(int(i.address))
			add4 = hex(int(i.address))
			addb = hex(int(i.address))
		else:
			add = hex(int(i.address))
			addb = hex(int(i.address +  section.VirtualAdd))
			add2 = str(add)
			add3 = hex (int(i.address + section.startLoc	))
			add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		val5.append(val)

		valOffsets.append(addb)
		# dprint2("cpprint")
		# dprint2(val)



	disString = val5



	for line in disString:

		##############################################

		jmp = re.match("^jmp", line, re.IGNORECASE)
		call = re.match("^call", line, re.IGNORECASE)
		bad = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns))", line, re.M|re.I)
		if(jmp or call or bad):
			return


		pop = re.match("^pop (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
		if(pop):
			pop_offset = line.split()[-1]
			pop_offset = pop_offset[:-1]
		# print("POP OFFSET")
		# print(pop_offset)
		if(pop):

			if(rawHex):
				modSecName = peName
			else:
				modSecName = section.sectionName

			# dprint2("saving one")
			# dprint2(binarytostr(line))

			saveBaseCallpop(origAddr, NumOpsDis, modSecName, secNum, distance, pop_offset)
			return


def disHereCallpop64(address, NumOpsDis, secNum, data, distance):
	# print ("disHereCallpop64")
	pop = False
	CODED2 = ""
	x = NumOpsDis

	origAddr = address
	# address = address + distance
	valOffsets =[]

	CODED2 = data[(origAddr):(address+20)]

	# I create the individual lines of code that will appear>
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]
	valOpstr =[]
	if(secNum != "noSec"):
		section = s[secNum]
	# dprint2("HERE IS THE CALL LINE")
	# start = timeit.default_timer()
	CODED3 = CODED2

	# print ("test1")
	for i in cs64.disasm(CODED3, address):
		if(secNum == "noSec"):
			# add = hex(int(i.address))
			add4 = hex(int(i.address))
			addb = hex(int(i.address))
		else:
			add = hex(int(i.address))
			addb = hex(int(i.address +  section.VirtualAdd))
			add2 = str(add)
			add3 = hex (int(i.address + section.startLoc	))
			add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		valOpstr.append(i.op_str)
		val5.append(val)

		valOffsets.append(addb)
		dprint2(val)



	dprint2 (len(val5), "lenght val5")
	disString = val5
	t = 0
	# print("CODED2 Before", CODED2.hex())

	for line in disString:
		##############################################
		dprint2(line)
		call = re.match("^call [0x]*[0-9a-f]{1,2}", disString[0], re.IGNORECASE)
		if(call):
			# print("Found call")
			# input()
			# pop_addr = line.split()[1]
			# pop_addr = pop_addr[:-1]
			# print ("found call")
			pop_addr = valOpstr[t]
			# print("pop address", pop_addr)
			dprint2("POP ADDR = " + str(pop_addr))
			# dprint2(binaryToStr(CODED3))
		# dprint2("POP OFFSET")
		t += 1

	if(secNum != "noSec"):
		section = s[secNum]
	CODED2 = data[(address):(address+NumOpsDis)]
	# print("CODED2 after", CODED2.hex())
	# input()
	# I create the individual lines of code that will appear>
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]
	

	# dprint2("2ND CHUNK")
	# start = timeit.default_timer()
	CODED3 = CODED2
	for i in cs64.disasm(CODED3, address):
		if(secNum == "noSec"):
			# add = hex(int(i.address))
			add4 = hex(int(i.address))
			addb = hex(int(i.address))
		else:
			add = hex(int(i.address))
			addb = hex(int(i.address +  section.VirtualAdd))
			add2 = str(add)
			add3 = hex (int(i.address + section.startLoc	))
			add4 = str(add3)
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		val5.append(val)

		dprint2(val)
		valOpstr.append(addb)



	disString2 = val5

	t=0
	dprint2 (disString)
	for line in disString:

		##############################################
		#Note that push/pop are invalid for e registers in x64. r registers are correct.
		# pop = re.match("^pop (((r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp))) | (r((8)|(9)|(1(0-5)))d?)", line, re.IGNORECASE)
		dprint2 ("t", t, "line", line)

		bad = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns)|(call))", line, re.M|re.I)   # addd call
		if bad:
			dprint2 ("got bad")
		if(bad) and (t > 0):
			# print("Returning")
			return
		t+=1

	t=0

	for line in disString:
		# print("Line", line, "offset", valOffsets[t])
		# print("offset: ", valOffsets)
		##############################################
		#Note that push/pop are invalid for e registers in x64. r registers are correct.
		# pop = re.match("^pop (((r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp))) | (r((8)|(9)|(1(0-5)))d?)", line, re.IGNORECASE)
		# print("disString2", line)
		# jmp = re.match("^jmp", line, re.IGNORECASE)
		# call = re.match("^call", line, re.IGNORECASE)
		# bad = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns))", line, re.M|re.I)
		# if(jmp or call or bad):
			# return

		pop = re.match("^pop ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8)|(9)|(1[0-5])))", line, re.IGNORECASE)
		if(pop):
			# print("offset: ", valOffsets[t])
			# print(pop)
			# input()
			# pop_offset = valOpstr[t]
			# print("Found pop offset")

			pop_offset = valOffsets[t]
			# dprint2("POP OFFSET")
			# dprint2(line)
		# dprint2(pop_offset)

		if(pop):

			if(rawHex):
				modSecName = peName
			else:
				modSecName = section.sectionName
			# dprint2("saving one")
			# print("Saving call pop: ", origAddr, "pop offset", pop_offset)
			# print("Saving: ", hex(origAddr), "pop_offset", pop_offset)
			saveBaseCallpop(origAddr, NumOpsDis, modSecName, secNum, distance, pop_offset)
			return
		t+=1
def callPopRawHex_old(address, secNum, data):
	global bit32
	global ignoreDisDiscovery
	global maxDistance
	global linesForward

	global debuging

	# debuging = True
	address = int(address)
	linesGoBack = 10
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(address, 0x0, linesGoBack)

	print("##################DISASM HERE####################")
	for e in orgListDisassembly:
		print(e)
	print("##################DISASM HERE####################")



	if(ignoreDisDiscovery):
		truth = False
	t = 0
	if(truth):
		for e in orgListDisassembly:
			dprint2(e, orgListOffset[t])

			isCall = re.match("^call (0x)?[0-9,a-f]{1,2}", e, re.IGNORECASE)
			
			if(isCall):
				# print("got a call")
				distance = orgListDisassembly[t]

				dprint2("disthere", distance)
				try:
					distance = int(distance[5:], 16)
					dprint2("disthere", distance)
					dprint2("dist before sub: ", distance)
					distance = distance - orgListOffset[t]
					dprint2("dist after sub: ", distance)
					if distance <= maxDistance:
						dprint2("made it into cond")
						# dprint2("The thing is: ", e)
						# fz = input("> ")
						dprint2("disthere", distance)
						dprint2("disthere2", distance)
						dprint2("distance is: ", hex(distance))
						# dprint2("checking call at: ", orgListOffset[t])
						chunk = orgListDisassembly[t+distance+1:t+distance+linesForward]
						chunkOffsets = orgListOffset[t+distance+1:t+distance+linesForward]
						w = t +distance + 1
						dprint2("start t is ", t)
						print("\nChecking this chunk:")
						for item in chunk:
							print(item)
						for item in chunk:
							dprint2("w is ", w)
							bad = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns)|(call))", item, re.M|re.I)
							if bad:
								print ("got bad: ", item)
								break
							# dprint2("item: ",item)
							# if not (distance + orgListOffset[t] > orgListOffset[w]): 
							isPop = re.search("^pop ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8)|(9)|(1[0-5])))", item, re.IGNORECASE)

							# if(orgListOffset[t] + distance < orgListOffset[w+t]):
							# 	dprint2("Call distance ", orgListOffset[t] + distance)
							# 	dprint2("Pop loc ", orgListOffset[w+t])
							# 	if isPop:
							# 		dprint2("saving")
							# 		pop_offset = orgListOffset[w+t]
							# 		saveBaseCallpop(address, linesForward, 'noSec', secNum, distance, pop_offset)
							# 		break
							if isPop:
									address = orgListOffset[t]
									pop_offset = orgListOffset[w]
									distance = pop_offset - address

									pop_offset = hex(pop_offset)
									dprint2("numopsdis is: ")
									saveBaseCallpop(address, linesForward, 'noSec', secNum, distance, pop_offset)
									break
							# else:
							# 	print("bad distance, e: ", e, " orgListOffset[t]: ", hex(orgListOffset[t]), "   orgListOffset[w]: ", hex(orgListOffset[w]), "   distance: ", distance, "t: ", t, "w: ", w)
							w+=1
				except Exception as e:

					print(e)
					# print(traceback.format_exc())

					pass

			# if bad:
			# 	break
			t+=1
	else:
		for match in CALLPOP_START.values(): #iterate through all opcodes representing combinations of registers
			get_Callpop(10, match[0], secNum, data, match[1])


def callPopRawHex(address, linesForward2, secNum, data):
	global bit32
	global ignoreDisDiscovery
	global maxDistance
	global linesForward

	global debuging

	# debuging = True
	address = int(address)
	linesGoBack = 10
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(address, 0x0, linesGoBack)

	t = 0
	if truth:
		for disasmLine in orgListDisassembly:
			distance = None
			isCall = re.match("^call (0x)?[0-9,a-f]{1,2}", disasmLine, re.IGNORECASE)
			if(isCall):
				dest = disasmLine.split()[1]
				numeric = re.match(" ?(0x)?([0-9A-F])+$", dest, re.IGNORECASE)
				# print("found call with dest ", dest, "on line ", disasmLine, " ||||| NUMERIC = ", numeric)
				if(numeric):
					distance = int(dest, 0) - orgListOffset[t]
					# print("Distance after math = ", distance)
					w = t+1
					for postCallLine in orgListDisassembly[t+1:t+1+linesForward+maxDistance]:
						bad = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns)|(call))", postCallLine, re.M|re.I)
						isPop = re.search("^pop ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8)|(9)|(1[0-5])))", postCallLine, re.IGNORECASE)

						# print("comparing destination ", dest, " to line ", orgListDisassembly[w], " OFFSET:", hex(orgListOffset[w]))
						if(bad and (int(dest,0) <= orgListOffset[w])):
							# print("got a bbad on line ", postCallLine, " | offset: ", hex(orgListOffset[w]), " | call offset: ", hex(orgListOffset[t]))
							break
						if(isPop and (int(dest,0) <= orgListOffset[w])):
							# print("found a good pop on line", postCallLine, " | offset: ", hex(orgListOffset[w]), " | call offset: ", hex(orgListOffset[t]))
							address = orgListOffset[t]
							pop_offset = orgListOffset[w]
							distance = pop_offset - address

							pop_offset = hex(pop_offset)
							saveBaseCallpop(address, linesForward, 'noSec', secNum, distance, pop_offset)
							break
						w+=1
				
			t += 1

	else:
		for match in CALLPOP_START.values(): #iterate through all opcodes representing combinations of registers
			get_Callpop(10, match[0], secNum, data, match[1])


	
	if(rawHex):
		m[o].save_Callpop_info = helperListToSet(m[o].save_Callpop_info)
	else:
		s[secNum].save_Callpop_info =helperListToSet(s[secNum].save_Callpop_info)
		

def helperListToSet(ourList):

	ourList = set(ourList)
	ourList = list(ourList)
	return ourList

def saveBaseCallpop(address, NumOpsDis,modSecName,secNum,distance,pop_offset): 
	# print("saveBaseCallpop", address, NumOpsDis,modSecName,secNum,distance,pop_offset)
	# dprint2("saving")
	#save virtaul address as well
	tmp = tuple((address,NumOpsDis,modSecName,secNum,distance, pop_offset))
	# 

	if(secNum != "noSec"):
		# if tmp not in s[secNum].save_Callpop_info:
		# print("Saving pop_offset", pop_offset)
		s[secNum].save_Callpop_info.append(tuple((address,NumOpsDis,modSecName,secNum,distance, pop_offset)))
	else:
		secNum = -1
		modSecName = "rawHex"
		# tmp = tuple((address,NumOpsDis,modSecName,secNum,distance, pop_offset))
		
		# if tmp not in m[o].save_Callpop_info:
		m[o].save_Callpop_info.append(tuple((address,NumOpsDis,modSecName,secNum,distance,pop_offset)))



def saveBaseCallpop_backup(address, NumOpsDis,modSecName,secNum,distance,pop_offset): 
	# print("saveBaseCallpop", address, NumOpsDis,modSecName,secNum,distance,pop_offset)
	# dprint2("saving")
	#save virtaul address as well
	tmp = tuple((address,NumOpsDis,modSecName,secNum,distance, pop_offset))
	

	if(secNum != "noSec"):
		if tmp not in s[secNum].save_Callpop_info:
		# print("Saving pop_offset", pop_offset)
			s[secNum].save_Callpop_info.append(tuple((address,NumOpsDis,modSecName,secNum,distance, pop_offset)))
	else:
		secNum = -1
		modSecName = "rawHex"
		tmp = tuple((address,NumOpsDis,modSecName,secNum,distance, pop_offset))
		
		if tmp not in m[o].save_Callpop_info:
			m[o].save_Callpop_info.append(tuple((address,NumOpsDis,modSecName,secNum,distance,pop_offset)))






def printSavedCallPop(bit = 32): ######################## AUSTIN ###############################3
	# print("in print")
	#formatting
	j = 0
	if(bit == 64):
		callCS = cs64
	else:
		callCS = cs
	if(rawHex):
		for item in m[o].save_Callpop_info:



			CODED2 = b""

			origAddr = item[0]
			NumOpsDis = item[1]
			modSecName = item[2]
			secNum = item[3]
			distance = item[4]
			pop_offset = item[5]
			address = origAddr + distance
			popOpcLen = 1
			CODED2 = rawData2[(origAddr):(address+NumOpsDis	)]

			outString = "Item: " + str(j)
			if(secNum != -1):

				outString += " | Section: " + str(secNum) + " | Section name: " + str(modSecName)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Call address: " + str(hex(origAddr)) + " | Pop offset: " + str(pop_offset) + " | Distance from call: " + str(hex(distance))

			print ("******************************************************************************")
			print (yel + outString + res)
			val =""
			val2 = []
			val3 = []
			#address2 = address + section.ImageBase + section.VirtualAdd
			val5 =[]
			
			for i in callCS.disasm(CODED2, origAddr):
				if(rawHex):
					add4 = hex(int(i.address))
					addb = hex(int(i.address))
				else:
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	))
					add4 = str(add3)
				val = formatPrint(i, add4, addb)

				# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
				print (gre + val + res)
				if(addb == pop_offset):
					break
				# print (val)
				#stop printing after we print out our getPC pop
				# isPop = re.search("^pop ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8)|(9)|(1[0-5])))", val, re.IGNORECASE)
				# if(isPop):
					# break


				


	#return val5
			# print ("\n")
			j += 1
			# print("dist:")
			# print(distance)
	else:
		h = 0
		for section in s:
			h += 1
			# print("PRINTING SECTION " + str(h))
			for item in section.save_Callpop_info:
				CODED2 = ""
				origAddr = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				distance = item[4]
				pop_offset = item[5]
				address = origAddr + distance
				popOpcLen = 1
				# print("NUMBACK = " + str(NumOpsBack))

				section = s[secNum]

				printAddress = origAddr + section.VirtualAdd
				outString = "\n\nItem: " + str(j)
				if(secNum != -1):
					outString += " | Call address: " + str(hex(printAddress)) + " | Pop offset: " + str(pop_offset) + " | Distance from call: " + str(hex(distance))

					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				print ("\n******************************************************************************")
				print (yel + outString + res)
				print ("\n")
				val =""
				val2 = []
				val3 = []
				address2 = address + section.ImageBase + section.VirtualAdd
				val5 =[]
				CODED2 = section.data2[(origAddr):(address+NumOpsDis)]
				
				CODED3 = CODED2
				# print("origAddr: ", origAddr, "CODED3", CODED3, "Address", address)
				# print("print output", CODED3.hex())

				for i in callCS.disasm(CODED3, origAddr):
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc))
					add4 = str(add3)
					val = formatPrint(i, add4, add, pe=True)

					# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					val5.append(val)
					print (gre + val + res)
					if(addb == pop_offset):
						break
					
					# print (val)
					#stop printing after we print out our getPC pop
					# isPop = re.search("^pop ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)|(8)|(9)|(1[0-5])))", val, re.IGNORECASE)
					# if(isPop):
						# break

				print ("\n")
				j += 1
				# print str(type(m[o].data2))
				# trash = raw_input("enter...")




def identifySyscall(callNum): # returns two lists containing lists of the format [syscall name 1, version 1, version 2.... ]. First list is results for x86 OSes, second is for x86-64
	# callNum = 0x26
	result = []
	result64 = []
	result32 = []
	callNum = format(callNum, '#06x')
	with open('nt64.csv', 'r') as file:
		nt64Csv = csv.reader(file)
		# print(format(callNum, '#06x'))
		nt64Header = next(nt64Csv)
		# print(ntHeader)
		for row in nt64Csv:
			if(callNum in row):
				newEntry = []
				newEntry.append(row[0])
				# print(row[0])
				while(callNum in row):
					newEntry.append(nt64Header[row.index(callNum)])
					# print(ntHeader[row.index(callNum)])
					row[row.index(callNum)] = ""
				result64.append(newEntry)


	# print("################### WIN32K #########################")

	with open('win32k64.csv', 'r') as file:
		w3264Csv = csv.reader(file)
		# print(format(callNum, '#06x'))
		w3264header = next(w3264Csv)
		# print(w32header)
		for row in w3264Csv:
			if(callNum in row):
				newEntry = []
				newEntry.append(row[0])
				# print("\n")
				# print(row[0])
				while(callNum in row):
					newEntry.append(w3264header[row.index(callNum)])
					row[row.index(callNum)] = ""
				result64.append(newEntry)


	with open('nt.csv', 'r') as file:
		ntCsv = csv.reader(file)
		# print(format(callNum, '#06x'))
		ntHeader = next(ntCsv)
		# print(ntHeader)
		for row in ntCsv:
			if(callNum in row):
				newEntry = []
				newEntry.append(row[0])
				# print(row[0])
				while(callNum in row):
					newEntry.append(ntHeader[row.index(callNum)])
					# print(ntHeader[row.index(callNum)])
					row[row.index(callNum)] = ""
				result32.append(newEntry)


	# print("################### WIN32K #########################")

	with open('win32k.csv', 'r') as file:
		w32Csv = csv.reader(file)
		# print(format(callNum, '#06x'))
		w32header = next(w32Csv)
		# print(w32header)
		for row in w32Csv:
			if(callNum in row):
				newEntry = []
				newEntry.append(row[0])
				# print("\n")
				# print(row[0])
				while(callNum in row):
					newEntry.append(w32header[row.index(callNum)])
					row[row.index(callNum)] = ""
				result32.append(newEntry)

	result.append(result32)
	result.append(result64)
	return result

#enter callNum as hex code of syscall, bit and wanted version are optional and will return most recent 64bit OS by default
def getSyscall(callNum, bit = 64, version = "default"):



	apiList = identifySyscall(callNum)
	if(bit == 64):
		apiList = apiList[1]
	else:
		apiList = apiList[0]

	# print("inAPI")
	if(version == "default"):

		if(bit == 64):
			with open('nt64.csv', 'r') as file:
				nt64Csv = csv.reader(file)
				# print(format(callNum, '#06x'))
				nt64Header = next(nt64Csv)
				version = nt64Header[-1]

		else:
			with open('nt32.csv', 'r') as file:
				nt32Csv = csv.reader(file)
				# print(format(callNum, '#06x'))
				nt32Header = next(nt32Csv)
				version = nt64Header[-1]

	#some user friendliness -- handle upper/lower and differences in spaces
	version = version.lower()
	version = version.replace(" ", "")


	for item in apiList:
		name = item[0]
		osList = item[1:]

		for osItem in osList:

			if(osItem.lower().replace(" ", "") == version):
				result = name
				return result



def getSyscallRecent(callNum, bit = 64, print2File=None):
	global syscallSelection
	global syscallString

	syscallString = ''
	apiList = identifySyscall(callNum)
	if(bit == 64):
		apiList = apiList[1]
	else:
		apiList = apiList[0]

	# print("inAPI")

	if(bit == 64):
		with open('nt64.csv', 'r') as file:
				nt64Csv = csv.reader(file)
				# print(format(callNum, '#06x'))
				versions = next(nt64Csv)
				versions = versions[1:]

	else:
		with open('nt32.csv', 'r') as file:
				nt32Csv = csv.reader(file)
				# print(format(callNum, '#06x'))
				versions = next(nt32Csv)
				versions = versions[1:]



	categories = []
	for version in versions:
		version = version.rsplit('(',1)[0]
		if(version not in categories):
			categories.append(version)
	# print(categories)
	finalCat = [[] for _ in range(len(categories))]
	finalList = ["" for _ in range(len(versions))]
	# print(finalCat)

	for item in apiList:
		name = item[0]
		osList = item[1:]

		# print("OSLIST IS")
		# print(osList)
		for osItem in osList:
			# osCategory = osItem.rsplit('(',1)[0]
			for i in range(len(versions)):
				if(osItem == versions[i]):
					addAPI = (name, osItem)
					finalList[i] = name
	try:
		for i in range(len(versions)):
			for sys in syscallSelection:
				tempName = sys.name
				if(re.search("^release ", tempName, re.IGNORECASE)):
					tempName = tempName[8:]
				if sys.toggle and (re.search(fr"{sys.category}", versions[i], re.IGNORECASE)) and (re.search(fr"{tempName}", versions[i], re.IGNORECASE)):
					if(print2File == None):
						print("OS: " + versions[i])
						print("Syscall: " + finalList[i])
						print("\n")
					else:
						syscallString += "OS: " + versions[i]
						syscallString += " Syscall: " + finalList[i]
						syscallString += "\n"
						# return syscallString
	except:
		for i in range(len(categories)):
			newest = "N\A"
			newestVersion = "N\A"
			for j in range(len(finalList)):
				category = versions[j].rsplit('(',1)[0]
				if((category == categories[i]) and (finalList[j] != "")):
					newest = finalList[j]
					newestVersion = versions[j]
			if(print2File == None):
				print(categories[i])
				print("OS: " + newestVersion)
				print("Syscall: " + newest)
				print("\n")
			else:
				syscallString += "OS: " + newestVersion
				syscallString += " Syscall: " +newest
				syscallString += "\n"
				# return syscallString
	return syscallString



	



def printSyscallResult(syscalls):
	syscalls32 = syscalls[0]
	syscalls64 = syscalls[1]


	print("---------------------- x86 INFO -------------------------")

	for item in syscalls[0]:
		name = item[0]
		print("\nAPI Name: \t" + str(name))
		print("Versions:")
		for opSys in item[1:]:
			print(str(opSys))

	print("\n\n\n---------------------- x86-64 INFO -------------------------")

	for item in syscalls[1]:
		name = item[0]
		print("\nAPI Name: \t" + str(name))
		print("Versions:")
		for opSys in item[1:]:
			print(str(opSys))


def trackRegs(disAsm, startStates, stack): #disAsm: disassembly string | startStates: tuple containing starting values of each register | stack: list of items on the stack
	eax = startStates[0]
	ebx = startStates[1]
	ecx = startStates[2]
	edx = startStates[3]
	edi = startStates[4]
	esi = startStates[5]
	ebp = startStates[6]
	esp = startStates[7]

	eaxOffset = 0
	ebxOffset = 0
	ecxOffset = 0
	edxOffset = 0
	ediOffset = 0
	esiOffset = 0
	ebpOffset = 0
	espOffset = 0






	# print("&&&&&&&&&&&&&&&&&&&&&&&&\n\n")
	for line in disAsm:
		line = line.rsplit('	', 1)[0]
		# print("____________-")
		# print(line)

		mov = re.match("^(mov) (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
		add = re.match("^(add) (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
		sub = re.match("^(sub) (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
		xor = re.match("^(xor) (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
		xchg = re.match("^(xchg) (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
		push = re.match("^(push)", line, re.IGNORECASE)
		pop = re.match("^(pop)", line, re.IGNORECASE)

		if(mov):
			reg = mov.group().split(' ')[1].replace(',','').lower()

			if(reg == 'eax'):
				eaxOffset = 0
			elif(reg == 'ebx'):
				ebxOffset = 0
			elif(reg == 'ecx'):
				ecxOffset = 0
			elif(reg == 'edx'):
				edxOffset = 0
			elif(reg == 'edi'):
				ediOffset = 0
			elif(reg == 'esi'):
				esiOffset = 0
			elif(reg == 'ebp'):
				ebpOffset = 0
			elif(reg == 'esp'):
				espOffset = 0

			line = line.split(',',1)[-1]
			line = line.replace(' ', '')

			
			variable = re.search(" ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
			numeric = re.search(" ?(0x)?([0-9A-F])+", line, re.IGNORECASE)
			ptr = re.search(" ?(ptr)", line, re.IGNORECASE)

			if(ptr):
				found = "unknown"
				if(reg == 'eax'):
					eax = found
				elif(reg == 'ebx'):
					ebx = found
				elif(reg == 'ecx'):
					ecx = found
				elif(reg == 'edx'):
					edx = found
				elif(reg == 'edi'):
					edi = found
				elif(reg == 'esi'):
					esi = found
				elif(reg == 'ebp'):
					ebp = found
				elif(reg == 'esp'):
					esp = found


			elif(variable):
				found = str(variable.group())
				# print("here is what i found:")
				# print(found)

				if(found == 'eax'):
					found = eax
				elif(found == 'ebx'):
					found = ebx
				elif(found == 'ecx'):
					found = ecx
				elif(found == 'edx'):
					found = edx
				elif(found == 'edi'):
					found = edi
				elif(found == 'esi'):
					found = esi
				elif(found == 'ebp'):
					found = ebp
				elif(found == 'esp'):
					found = esp
				else:
					found = "unknown"

			elif(numeric):
				found = int(numeric.group(), 16)
				# print("here is what i found:")
				# print(found)

				found = hex(found)

			else:
				found = "unknown"

			if(reg == 'eax'):
				eax = found
			elif(reg == 'ebx'):
				ebx = found
			elif(reg == 'ecx'):
				ecx = found
			elif(reg == 'edx'):
				edx = found
			elif(reg == 'edi'):
				edi = found
			elif(reg == 'esi'):
				esi = found
			elif(reg == 'ebp'):
				ebp = found
			elif(reg == 'esp'):
				esp = found

		elif(add):
			reg = add.group().split(' ')[1].replace(',','').lower()

			line = line.split(',',1)[-1]
			line = line.replace(' ', '')

			variable = re.search(" ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
			numeric = re.search(" ?(0x)?([0-9A-F])+", line, re.IGNORECASE)

			ptr = re.search(" ?(ptr)", line, re.IGNORECASE)
			
			if(ptr):
				found = "unknown"
				if(reg == 'eax'):
					eax = found
				elif(reg == 'ebx'):
					ebx = found
				elif(reg == 'ecx'):
					ecx = found
				elif(reg == 'edx'):
					edx = found
				elif(reg == 'edi'):
					edi = found
				elif(reg == 'esi'):
					esi = found
				elif(reg == 'ebp'):
					ebp = found
				elif(reg == 'esp'):
					esp = found

			elif(variable):
				found = str(variable.group())
				# print("here is what i found:")
				# print(found)

				if(found == 'eax'):
					found = eax
				elif(found == 'ebx'):
					found = ebx
				elif(found == 'ecx'):
					found = ecx
				elif(found == 'edx'):
					found = edx
				elif(found == 'edi'):
					found = edi
				elif(found == 'esi'):
					found = esi
				elif(found == 'ebp'):
					found = ebp
				elif(found == 'esp'):
					found = esp
				else:
					found = "unknown"

				found = str(found)

			elif(numeric):
				found = int(numeric.group(), 0)
				# print("here is what i found:")
				# print(found)

				found = hex(found)

			else:
				found = "unknown"

			curOffset = found

			if(reg == 'eax'):
				if(eax == 'unknown'):
					if(curOffset == "unknown"):
						eaxOffset = 0
					else:	
						eaxOffset += int(curOffset, 0)

				elif(found == "unknown"):
					eax = "unknown"
				else:
					eax = int(str(eax),0) + int(str(found), 0)
			elif(reg == 'ebx'):
				if(ebx == 'unknown'):
					if(curOffset == "unknown"):
						ebxOffset = 0
					else:	
						ebxOffset += int(curOffset, 0)

				elif(found == "unknown"):
					ebx = "unknown"
				else:
					ebx = int(str(ebx),0) + int(str(found), 0)
			elif(reg == 'ecx'):
				if(ecx == 'unknown'):
					if(curOffset == "unknown"):
						ecxOffset = 0
					else:	
						ecxOffset += int(curOffset, 0)

				elif(found == "unknown"):
					ecx = "unknown"
				else:
					ecx = int(str(ecx),0) + int(str(found), 0)
			elif(reg == 'edx'):
				if(edx == 'unknown'):
					if(curOffset == "unknown"):
						edxOffset = 0
					else:	
						edxOffset += int(curOffset, 0)

				elif(found == "unknown"):
					edx = "unknown"
				else:
					edx = int(str(edx),0) + int(str(found), 0)
			elif(reg == 'edi'):
				if(edi == 'unknown'):
					if(curOffset == "unknown"):
						ediOffset = 0
					else:	
						ediOffset += int(curOffset, 0)

				elif(found == "unknown"):
					edi = "unknown"
				else:
					edi = int(str(edi),0) + int(str(found), 0)
			elif(reg == 'esi'):
				if(esi == 'unknown'):
					if(curOffset == "unknown"):
						esiOffset = 0
					else:	
						esiOffset += int(curOffset, 0)

				elif(found == "unknown"):
					esi = "unknown"
				else:
					esi = int(str(esi),0) + int(str(found), 0)
			elif(reg == 'ebp'):
				if(ebp == 'unknown'):
					if(curOffset == "unknown"):
						ebpOffset = 0
					else:	
						ebpOffset += int(curOffset, 0)

				elif(found == "unknown"):
					ebp = "unknown"
				else:
					ebp = int(str(ebp),0) + int(str(found), 0)
			elif(reg == 'esp'):
				if(esp == 'unknown'):
					if(curOffset == "unknown"):
						espOffset = 0
					else:	
						espOffset += int(curOffset, 0)

				elif(found == "unknown"):
					esp = "unknown"
				else:
					esp = int(str(esp),0) + int(str(found),0)

		elif(sub):
			reg = sub.group().split(' ')[1].replace(',','').lower()

			line = line.split(',',1)[-1]
			line = line.replace(' ', '')

			variable = re.search(" ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
			numeric = re.search(" ?(0x)?([0-9A-F])+", line, re.IGNORECASE)

			ptr = re.search(" ?(ptr)", line, re.IGNORECASE)
			
			if(ptr):
				found = "unknown"
				if(reg == 'eax'):
					eax = found
				elif(reg == 'ebx'):
					ebx = found
				elif(reg == 'ecx'):
					ecx = found
				elif(reg == 'edx'):
					edx = found
				elif(reg == 'edi'):
					edi = found
				elif(reg == 'esi'):
					esi = found
				elif(reg == 'ebp'):
					ebp = found
				elif(reg == 'esp'):
					esp = found

			elif(variable):
				found = str(variable.group())
				# print("here is what i found:")
				# print(found)

				if(found == 'eax'):
					found = eax
				elif(found == 'ebx'):
					found = ebx
				elif(found == 'ecx'):
					found = ecx
				elif(found == 'edx'):
					found = edx
				elif(found == 'edi'):
					found = edi
				elif(found == 'esi'):
					found = esi
				elif(found == 'ebp'):
					found = ebp
				elif(found == 'esp'):
					found = esp
				else:
					found = "unknown"

				found = str(found)

			elif(numeric):
				found = int(numeric.group(), 0)
				# print("here is what i found:")
				# print(found)

				found = hex(found)

			else:
				found = "unknown"


			curOffset = found

			if(reg == 'eax'):
				if(eax == 'unknown'):
					if(curOffset == "unknown"):
						eaxOffset = 0
					else:	
						eaxOffset -= int(curOffset, 0)

				elif(found == "unknown"):
					eax = "unknown"
				else:
					eax = int(str(eax),0) - int(str(found), 0)
			elif(reg == 'ebx'):
				if(ebx == 'unknown'):
					if(curOffset == "unknown"):
						ebxOffset = 0
					else:	
						ebxOffset -= int(curOffset, 0)

				elif(found == "unknown"):
					ebx = "unknown"
				else:
					ebx = int(str(ebx),0) - int(str(found), 0)
			elif(reg == 'ecx'):
				if(ecx == 'unknown'):
					if(curOffset == "unknown"):
						ecxOffset = 0
					else:	
						ecxOffset -= int(curOffset, 0)

				elif(found == "unknown"):
					ecx = "unknown"
				else:
					ecx = int(str(ecx),0) - int(str(found), 0)
			elif(reg == 'edx'):
				if(edx == 'unknown'):
					if(curOffset == "unknown"):
						edxOffset = 0
					else:	
						edxOffset -= int(curOffset, 0)

				elif(found == "unknown"):
					edx = "unknown"
				else:
					edx = int(str(edx),0) - int(str(found), 0)
			elif(reg == 'edi'):
				if(edi == 'unknown'):
					if(curOffset == "unknown"):
						ediOffset = 0
					else:	
						ediOffset -= int(curOffset, 0)

				elif(found == "unknown"):
					edi = "unknown"
				else:
					edi = int(str(edi),0) - int(str(found), 0)
			elif(reg == 'esi'):
				if(esi == 'unknown'):
					if(curOffset == "unknown"):
						esiOffset = 0
					else:	
						esiOffset -= int(curOffset, 0)

				elif(found == "unknown"):
					esi = "unknown"
				else:
					esi = int(str(esi),0) - int(str(found), 0)
			elif(reg == 'ebp'):
				if(ebp == 'unknown'):
					if(curOffset == "unknown"):
						ebpOffset = 0
					else:	
						ebpOffset -= int(curOffset, 0)

				elif(found == "unknown"):
					ebp = "unknown"
				else:
					ebp = int(str(ebp),0) - int(str(found), 0)
			elif(reg == 'esp'):
				if(esp == 'unknown'):
					if(curOffset == "unknown"):
						espOffset = 0
					else:	
						espOffset -= int(curOffset, 0)

				elif(found == "unknown"):
					esp = "unknown"
				else:
					esp = int(str(esp),0) - int(str(found),0)

		elif(xor):
			# print("in xor")
			nullify = False
			reg = xor.group().split(' ')[1].replace(',','').lower()

			if(reg == 'eax'):
				eaxOffset = 0
			elif(reg == 'ebx'):
				ebxOffset = 0
			elif(reg == 'ecx'):
				ecxOffset = 0
			elif(reg == 'edx'):
				edxOffset = 0
			elif(reg == 'edi'):
				ediOffset = 0
			elif(reg == 'esi'):
				esiOffset = 0
			elif(reg == 'ebp'):
				ebpOffset = 0
			elif(reg == 'esp'):
				espOffset = 0


			line = line.split(',',1)[-1]
			line = line.replace(' ', '')

			variable = re.search(" ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
			numeric = re.search(" ?(0x)?([0-9A-F])+", line, re.IGNORECASE)
			ptr = re.search(" ?(ptr)", line, re.IGNORECASE)
			
			if(ptr):
				found = "unknown"
				if(reg == 'eax'):
					eax = found
				elif(reg == 'ebx'):
					ebx = found
				elif(reg == 'ecx'):
					ecx = found
				elif(reg == 'edx'):
					edx = found
				elif(reg == 'edi'):
					edi = found
				elif(reg == 'esi'):
					esi = found
				elif(reg == 'ebp'):
					ebp = found
				elif(reg == 'esp'):
					esp = found

			elif(variable):

				found = str(variable.group())
				if(found == reg):
					nullify = True

				# print("here is what i found:")
				# print(found)

				elif(found == 'eax'):
					found = eax
				elif(found == 'ebx'):
					found = ebx
				elif(found == 'ecx'):
					found = ecx
				elif(found == 'edx'):
					found = edx
				elif(found == 'edi'):
					found = edi
				elif(found == 'esi'):
					found = esi
				elif(found == 'ebp'):
					found = ebp
				elif(found == 'esp'):
					found = esp

				else:
					found = "unknown"

				found = str(found)


			elif(numeric):
				found = int(numeric.group(), 0)
				# print("here is what i found:")
				# print(found)

				found = hex(found)

			else:
				found = "unknown"

			if(reg == 'eax'):
				if(nullify):
					eax = '0'
				elif((eax == "unknown") or (found == "unknown")):
					eax = "unknown"
				else:
					eax = int(str(eax), 0)^int(str(found), 0)
			elif(reg == 'ebx'):
				if(nullify):
					ebx = '0'
				elif((ebx == "unknown") or (found == "unknown")):
					ebx = "unknown"
				else:
					ebx = int(str(ebx), 0)^int(str(found), 0)
			elif(reg == 'ecx'):
				if(nullify):
					ecx = '0'
				elif((ecx == "unknown") or (found == "unknown")):
					ecx = "unknown"
				else:
					ecx = int(str(ecx), 0)^int(str(found), 0)
			elif(reg == 'edx'):
				if(nullify):
					edx = '0'
				elif((edx == "unknown") or (found == "unknown")):
					edx = "unknown"
				else:
					edx = int(str(edx), 0)^int(str(found), 0)
			elif(reg == 'edi'):
				if(nullify):
					edi = '0'
				elif((edi == "unknown") or (found == "unknown")):
					edi = "unknown"
				else:
					edi = int(str(edi), 0)^int(str(found), 0)
			elif(reg == 'esi'):
				if(nullify):
					esi = '0'
				elif((esi == "unknown") or (found == "unknown")):
					esi = "unknown"
				else:
					esi = int(str(esi), 0)^int(str(found), 0)
			elif(reg == 'ebp'):
				if(nullify):
					ebp = '0'
				elif((ebp == "unknown") or (found == "unknown")):
					ebp = "unknown"
				else:
					ebp = int(str(ebp), 0)^int(str(found), 0)
			elif(reg == 'esp'):
				if(nullify):
					esp = '0'
				elif((esp == "unknown") or (found == "unknown")):
					esp = "unknown"
				else:
					esp = int(str(esp), 0)^int(str(found), 0)

		elif(xchg):
			reg = xchg.group().split(' ')[1].replace(',','').lower()

			if(reg == 'eax'):
				eaxOffset = 0
			elif(reg == 'ebx'):
				ebxOffset = 0
			elif(reg == 'ecx'):
				ecxOffset = 0
			elif(reg == 'edx'):
				edxOffset = 0
			elif(reg == 'edi'):
				ediOffset = 0
			elif(reg == 'esi'):
				esiOffset = 0
			elif(reg == 'ebp'):
				ebpOffset = 0
			elif(reg == 'esp'):
				espOffset = 0

			line = line.split(',',1)[-1]
			line = line.replace(' ', '')

			variable = re.search(" ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
			if(variable):
				found = str(variable.group())
				# print("here is what i found:")
				# print(found)

				if(found == 'eax'):
					found = eax
					if(reg == 'ebx'):
						eax = ebx
						ebx = found
					elif(reg == 'ecx'):
						eax = ecx
						ecx = found
					elif(reg == 'edx'):
						eax = edx
						edx = found
					elif(reg == 'edi'):
						eax = edi
						edi = found
					elif(reg == 'esi'):
						eax = ebx
						ebx = found
					elif(reg == 'ebp'):
						eax = ebp
						ebp = found
					elif(reg == 'esp'):
						eax = esp
						esp = found
				elif(found == 'ebx'):
					found = ebx
					if(reg == 'eax'):
						ebx = eax
						eax = found
					elif(reg == 'ecx'):
						ebx = ecx
						ecx = found
					elif(reg == 'edx'):
						ebx = edx
						edx = found
					elif(reg == 'edi'):
						ebx = edi
						edi = found
					elif(reg == 'esi'):
						ebx = esi
						esi = found
					elif(reg == 'ebp'):
						ebx = ebp
						ebp = found
					elif(reg == 'esp'):
						ebx = esp
						esp = found
				elif(found == 'ecx'):
					found = ecx
					if(reg == 'eax'):
						ecx = eax
						eax = found
					elif(reg == 'ebx'):
						ecx = ebx
						ebx = found
					elif(reg == 'edx'):
						ecx = edx
						edx = found
					elif(reg == 'edi'):
						ecx = edi
						edi = found
					elif(reg == 'esi'):
						ecx = esi
						esi = found
					elif(reg == 'ebp'):
						ecx = ebp
						ebp = found
					elif(reg == 'esp'):
						ecx = esp
						esp = found
				elif(found == 'edx'):
					found = edx
					if(reg == 'eax'):
						edx = eax
						eax = found
					elif(reg == 'ebx'):
						edx = ebx
						ebx = found
					elif(reg == 'ecx'):
						edx = ecx
						ecx = found
					elif(reg == 'edi'):
						edx = edi
						edi = found
					elif(reg == 'esi'):
						edx = esi
						esi = found
					elif(reg == 'ebp'):
						edx = ebp
						ebp = found
					elif(reg == 'esp'):
						edx = esp
						esp = found
				elif(found == 'edi'):
					found = edi
					if(reg == 'eax'):
						edi = eax
						eax = found
					elif(reg == 'ebx'):
						edi = ebx
						ebx = found
					elif(reg == 'ecx'):
						edi = ecx
						ecx = found
					elif(reg == 'edx'):
						edi = edx
						edx = found
					elif(reg == 'esi'):
						edi = esi
						esi = found
					elif(reg == 'ebp'):
						edi = ebp
						ebp = found
					elif(reg == 'esp'):
						edi = esp
						esp = found
				elif(found == 'esi'):
					found = esi
					if(reg == 'eax'):
						esi = eax
						eax = found
					elif(reg == 'ebx'):
						esi = ebx
						ebx = found
					elif(reg == 'ecx'):
						esi = ecx
						ecx = found
					elif(reg == 'edx'):
						esi = edx
						edx = found
					elif(reg == 'edi'):
						esi = edi
						edi = found
					elif(reg == 'ebp'):
						esi = ebp
						ebp = found
					elif(reg == 'esp'):
						esi = esp
						esp = found
				elif(found == 'ebp'):
					found = ebp
					if(reg == 'eax'):
						ebp = eax
						eax = found
					elif(reg == 'ebx'):
						ebp = ebx
						ebx = found
					elif(reg == 'ecx'):
						ebp = ecx
						ecx = found
					elif(reg == 'edx'):
						ebp = edx
						edx = found
					elif(reg == 'edi'):
						ebp = edi
						edi = found
					elif(reg == 'esi'):
						ebp = esi
						esi = found
					elif(reg == 'esp'):
						ebp = esp
						esp = found
				elif(found == 'esp'):
					found = esp

					if(reg == 'eax'):
						esp = eax
						eax = found

					elif(reg == 'ebx'):
						esp = ebx
						ebx = found
					elif(reg == 'ecx'):
						esp = ecx
						ecx = found
					elif(reg == 'edx'):
						esp = edx
						edx = found
					elif(reg == 'edi'):
						esp = edi
						edi = found
					elif(reg == 'esi'):
						esp = esi
						esi = found
					elif(reg == 'ebp'):
						esp = ebp
						ebp = found
				else:
					found = "unknown"

				found = str(found)

			else:
				found = "unknown"

			

		elif(push):

			line = line.split(' ',1)[-1]

			line = line.replace(' ', '')

			# print("PUSH LINE IS")
			# print(line)
			variable = re.search(" ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
			numeric = re.search(" ?(0x)?([0-9A-F])+", line, re.IGNORECASE)
			ptr = re.search(" ?(ptr)", line, re.IGNORECASE)
			
			if(ptr):
				found = "unknown"

			elif(variable):
				found = str(variable.group())

				# print("here is what i found:")
				# print(found)

				if(found == 'eax'):
					found = eax
				elif(found == 'ebx'):
					found = ebx
				elif(found == 'ecx'):
					found = ecx
				elif(found == 'edx'):
					found = edx
				elif(found == 'edi'):
					found = edi
				elif(found == 'esi'):
					found = esi
				elif(found == 'ebp'):
					found = ebp
				elif(found == 'esp'):
					found = esp
				else:
					found = "unknown"

				found = str(found)

			elif(numeric):
				try:
					found = int(numeric.group(), 0)

					# print("here is what i found:")
					# print(found)


					found = hex(found)
				except:
					found = "unknown"
					pass

			else:
				found = "unknown"
			stack.append(found)

			if(esp != "unknown"):
				if type(esp) == int:
					esp = str(esp)
				esp = int(esp, 0) - 4
			else:
				espOffset -= 4


		elif(pop):	

			line = line.split(' ',1)[-1]
			line = line.replace(' ', '')

			# print("PUSH LINE IS")
			# print(line)
			variable = re.search(" ?(e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
			numeric = re.search(" ?(0x)?([0-9A-F])+", line, re.IGNORECASE)


			ptr = re.search(" ?(ptr)", line, re.IGNORECASE)

			if(variable and (not ptr)):
				found = str(variable.group())

				# print("here is what i found:")
				# print(found)

				if(stack):

					val = str(stack.pop())

				else:
					val = "unknown"

				if(found == 'eax'):
					eax = val
					eaxOffset = 0
				elif(found == 'ebx'):
					ebx = val
					ebxOffset = 0
				elif(found == 'ecx'):
					ecx = val
					ecxOffset = 0
				elif(found == 'edx'):
					edx = val
					edxOffset = 0
				elif(found == 'edi'):
					edi = val
					ediOffset = 0
				elif(found == 'esi'):
					esi = val
					esiOffset = 0
				elif(found == 'ebp'):
					ebp = val
					ebpOffset = 0
				elif(found == 'esp'):
					esp = val
					espOffset = 0
				else:
					found = "unknown"

			if(esp != "unknown"):
				if type(esp) == int:
					esp = str(esp)
				# print("----> ", esp, type(esp))
				esp = int(esp, 0) + 4
			else:
				espOffset += 4

	# if(eaxOffset == 0):
	# 	print("EAX = " + str(eax))
	# else:
	# 	print("EAX = " + str(eax) + ' + ' + str(hex(eaxOffset)))
	# if(ebxOffset == 0):
	# 	print("EBX = " + str(ebx))
	# else:
	# 	print("EBX = " + str(ebx) + ' + ' + str(hex(ebxOffset)))
	# if(ecxOffset == 0):
	# 	print("ECX = " + str(ecx))
	# else:
	# 	print("ECX = " + str(ecx) + ' + ' + str(hex(ecxOffset)))
	# if(edxOffset == 0):
	# 	print("EDX = " + str(edx))
	# else:
	# 	print("EDX = " + str(edx) + ' + ' + str(hex(edxOffset)))
	# if(ediOffset == 0):
	# 	print("EDI = " + str(edi))
	# else:
	# 	print("EDI = " + str(edi) + ' + ' + str(hex(ediOffset)))
	# if(esiOffset == 0):
	# 	print("ESI = " + str(esi))
	# else:
	# 	print("ESI = " + str(esi) + ' + ' + str(hex(esiOffset)))
	# if(ebpOffset == 0):
	# 	print("EBP = " + str(ebp))
	# else:
	# 	print("EBP = " + str(ebp) + ' + ' + str(hex(ebpOffset)))
	# if(espOffset == 0):
	# 	print("ESP = " + str(esp))
	# else:
	# 	print("ESP = " + str(esp) + ' + ' + str(hex(espOffset)))

	# for item in stack:
	# 	print("STACK ITEM: " + str(item))


	regsResult = [eax, ebx, ecx, edx, edi, esi, ebp, ebp]
	for x in range(len(regsResult)):
		try:
			regsResult[x] = hex(regsResult[x])
		except Exception as e:
			# print(e)
			pass
	return(regsResult, stack)



def getSyscallPE(NumOpsDis, NumOpsBack, bytesToMatch, secNum, data2): 
	#change to work off of data2 - add param - get rid of secNum


	# dprint2('in get, sec: ', secNum)


	global o
	foundCount = 0
	numOps = NumOpsDis


	t=0
	len_data2 = len(data2)
	len_bytesToMatch = len(bytesToMatch)

	# dprint2("Bytes: ", len_bytesToMatch)

	for v in data2:
		found = True #reset flag
		#replace with bytesToMatch list if desired
		#for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
		i = 0
		for x in bytesToMatch:
			if(found == False):
				break
			# elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
			# 	found = False # out of range
			try:

				# dprint2(data2[t+i])

				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				# input(e)
				pass
			i += 1

		if(found):
			# print("Found syscall")
			# input()
			# dprint2("here's one")
			# input("enter..")
			disHereSyscall(t, numOps, NumOpsBack, secNum, data2)

			

		t=t+1

def get_HeavenPE(NumOpsDis, NumOpsBack, bytesToMatch, secNum, data2): 
	#change to work off of data2 - add param - get rid of secNum

	# dprint2('in get')

	global o
	foundCount = 0
	numOps = NumOpsDis


	t=0
	len_data2 = len(data2)
	len_bytesToMatch = len(bytesToMatch)
	for v in data2:
		found = True #reset flag
		#replace with bytesToMatch list if desired
		#for i in range(len(bytesToMatch)): #can break out on no match for efficiency, left as is for simplicity
		i = 0
		for x in bytesToMatch:
			if(found == False):
				break
			# elif ((i+t) >= len_data2 or i >= len_bytesToMatch):
			# 	found = False # out of range
			try:
				#dprint2(data2[t+i])
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				# input(e)
				pass
			i += 1

		if(found):
			# dprint2("here's one")
			# input("enter..")
			disHereHeavenPE(t, numOps, NumOpsBack, secNum, data2)

			

		t=t+1

def disHereSyscall(address, NumOpsDis, NumOpsBack, secNum, data): ############ AUSTIN ##############

	global o
	global total1
	global total2
	global fcount
	global regsVals
	w=0

	op_const = 16
	line_const = 8
	NumOpsBack = NumOpsBack + op_const

	## Capstone does not seem to allow me to start disassemblying at a given point, so I copy out a chunk to  disassemble. I append a 0x00 because it does not always disassemble correctly (or at all) if just two bytes. I cause it not to be displayed through other means. It simply take the starting address of the jmp [reg], disassembles backwards, and copies it to a variable that I examine more closely.
	#lGoBack = linesGoBackFindOP

	# dprint2("disHere")
	# dprint2(hex(address))
	# dprint2(secNum)
	#input("addy")

	# dprint2("eggdis")


	CODED2 = ""
	x = NumOpsDis
	# start = timeit.default_timer()
	if(secNum != "noSec"):
		section = s[secNum]


	# dprint2("------------------------------------")
	for back in range(NumOpsBack):
		unlikely = 0
		# dprint2("back = " + str(back))
		CODED2 = data[(address-(NumOpsBack-back)):(address+x)]
			#dprint2("########################")
		#	dprint2(type(CODED2))
		#	dprint2("########################")
		#
		# stop = timeit.default_timer()
		# total1 += (stop - start)
		# dprint2("Time 1 PEB: " + str(stop - start))

		# I create the individual lines of code that will appear>
		# dprint2(len(CODED2))
		val =""
		val2 = []
		val3 = []
		#address2 = address + section.ImageBase + section.VirtualAdd
		val5 =[]

		# start = timeit.default_timer()
		#CODED3 = CODED2.encode()
		CODED3 = CODED2
		# dprint2("BINARY2STR")
		# dprint2(binaryToStr(CODED3))
		# dprint2("******************************************")
		for i in cs.disasm(CODED3, address):
			#dprint2('address in for = ' + str(address))
			if(secNum == "noSec"):

			#	dprint2("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
				# add = hex(int(i.address))
				add4 = hex(int(i.address))
				addb = hex(int(i.address))
			else:
				add = hex(int(i.address))
				addb = hex(int(i.address +  section.VirtualAdd  - (NumOpsBack - back) ))
				add2 = str(add)
				add3 = hex (int(i.address + section.startLoc	- (NumOpsBack - back) ))
				add4 = str(add3)
			val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
			# val2.append(val)
			# val3.append(add2)
			val5.append(val)
			# dprint2(val)

			disString = val5
			# dprint2("before")
			# dprint2(disString)
			# disString = disString[2:]
			# dprint2("after")
			# dprint2(disString)
			c0_match = False
			#check for dword ptr fs:[reg] and verify value of register


		for line in disString:
			# if(re.match("(fs:\[0xc0\])|(fs:\[(((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))))( ?\+ ?(0x)?[0-9a-f]+)?\])", line, re.IGNORECASE)):
			if(re.match("^((call)|(jump)) dword ptr fs:\[((((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))))( ?\+ ?(0x)?[0-9a-f]+)?|(0xc0))\]", line, re.IGNORECASE) or re.match("^(syscall)", line, re.IGNORECASE) or re.match("^(int 0x2e)", line, re.IGNORECASE)):
				c0_match = True
				c0_offset = line.split()[-1]
				c0_offset = c0_offset[:-1]

			byte = re.search("byte ptr", line, re.IGNORECASE)
			insd = re.search("insd", line, re.IGNORECASE)
			outsd = re.search("outsd", line, re.IGNORECASE)
			# longNum = re.search("(0x)([0-9a-f]){6,}", line, re.IGNORECASE)
			longNum = re.search("\[?(0x)([0-9a-f]){6,}\]", line, re.IGNORECASE)

			#adc eax, dword[0xe0ff42]
			#dword ptr [eax + 0xe0ff4212]
			#dword ptr [0xe0ff4212]
			if(byte or insd or longNum or outsd):
				unlikely = unlikely + 1

			# if(unlikely < 3):
				# dprint2("unlikely: ", unlikely, "c0: ", c0_match)

			if(c0_match and (unlikely < 3)):
				# dprint2("c0 match")
				# dprint2("SAVING THIS ONE")
				# input("> ")
				if(rawHex):
					modSecName = peName
				else:
					modSecName = section.sectionName

				startStates = ("unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown")
				eax = trackRegs(disString, startStates, [])[0][0]
				# eax = trackRegs(disString, regsVals, [])[0][0]

				# if(eax != "unknown"):
				# 	dprint2("TrackRegs found eax = " + str(eax))
				saveBaseEgg(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, eax, c0_offset)
				return

#generates entire disassembley and finds all instances of syscalls
def getSyscallRawHex(address, linesBack, secNum, data):
		global regsVals
		dprint2("DISEGG2")
		address = hex(address)
		linesGoBack = linesBack
		t = 0

		addressInt = int(address,16)
		truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(addressInt, 0x0, linesGoBack)  # arg: starting offset/entry point - leave 0 generally


		if truth:
		####the FULL disassembly of the shellcode
			# print ("Full disassembly of shellcode EGG")
			dprint2("hello33")
			for e in orgListDisassembly:
				dprint2 (str(hex(orgListOffset[t])) + "\t" + e)


				# dprint2("TESTING HERE")
				# dprint2(e, hex(orgListOffset[t]))
				# isEgg = re.search("fs:(\[0xc0\])?", e, re.IGNORECASE)
				isEgg = re.search("^((call)|(jump)) dword ptr fs:\[((((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))))( ?\+ ?(0x)?[0-9a-f]+)?|(0xc0))\]", e, re.IGNORECASE)
				eggNew = re.search("^((int 0x2e)|(syscall))", e, re.IGNORECASE)
				if(isEgg or eggNew):
					c0_offset = hex(orgListOffset[t])
					address = int(orgListOffset[t])
					# dprint2("EGGHUNT HERE")
					# t_temp = 0
					startChunk = t-linesBack
					if(startChunk < 0):
						startChunk = 0
					chunk = orgListDisassembly[startChunk:t+1]
					chunkOffsets = orgListOffset[startChunk:t+1]

					# dprint2("\n\n\n CHUNK HERE")
					# for item in chunk:
					# 	print (str(hex(chunkOffsets[t_temp])) + "\t" + item)
					# 	t_temp += 1 
					# dprint2("\n\n\n")


					#convert to disassembly format compatible with trackRegs()
					converted = convertStringToTrack(chunk, chunkOffsets)

					# dprint2("CONVERTED")
					# dprint2("t = ", t, "linesBack = ", linesBack)
					# dprint2(chunk)
					# dprint2(chunkOffsets)
					# fg = input("> ")
					# for item in converted:
					# 	dprint2( item)

					startStates = ("unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown")
					eax = trackRegs(converted, startStates, [])[0][0]

					# eax = trackRegs(converted, regsVals, [])[0][0]
					dprint2("THURS eax = " + str(eax) + "\n\n\n")

					# if(eax == "0x26"):
						# dprint2("TrackRegs found eax = " + str(eax))
					modSecName = peName
					# dprint2("CONVERTED2: ", converted)
					# fg = input("> ")
					saveBaseEgg(address, -1, (linesBack), modSecName, secNum, eax, c0_offset, converted)


				t+=1

			clearTempDis()
			# print ("\n\n\n")
		if(not truth):
			dprint2("I failed")
		if(rawHex):
			m[o].save_Egg_info = helperListToSet(m[o].save_Egg_info)
		else:
			s[secNum].save_Egg_info =helperListToSet(s[secNum].save_Egg_info)

def disHereHeavenPE_old(address, NumOpsDis, NumOpsBack, secNum, data): ############ AUSTIN ##############

	global o
	global total1
	global total2
	global fcount
	global regsVals
	w=0

	disString = []
	destLocation = -1
	push_offset = -1

	op_const = 16
	line_const = 8
	NumOpsBack = NumOpsBack + op_const

	retfBad = False

	# dprint2("disHere")
	# dprint2(hex(address))
	# dprint2(secNum)
	#input("addy")

	CODED2 = ""
	x = NumOpsDis
	# start = timeit.default_timer()
	if(secNum != "noSec"):
		section = s[secNum]



	# dprint2("------------------------------------")

	for back in range(NumOpsBack):
		unlikely = 0
		# dprint2("back = " + str(back))
		CODED2 = data[(address-(NumOpsBack-back)):(address+x)]

			#dprint2("########################")
		#	dprint2(type(CODED2))
		#	dprint2("########################")

		#
		# stop = timeit.default_timer()
		# total1 += (stop - start)
		# dprint2("Time 1 PEB: " + str(stop - start))

		# I create the individual lines of code that will appear>
		# dprint2(len(CODED2))
		val =""
		val2 = []
		val3 = []
		#address2 = address + section.ImageBase + section.VirtualAdd
		val5 =[]

		# start = timeit.default_timer()
		#CODED3 = CODED2.encode()
		CODED3 = CODED2

		# dprint2("BINARY2STR")
		# dprint2(binaryToStr(CODED3))
		# dprint2("******************************************")
		disString = []
		for i in cs.disasm(CODED3, address):
			#dprint2('address in for = ' + str(address))

			if(secNum == "noSec"):

			#	dprint2("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
				# add = hex(int(i.address))
				add4 = hex(int(i.address))
				addb = hex(int(i.address))
			else:
				add = hex(int(i.address))
				addb = hex(int(i.address +  section.VirtualAdd  - (NumOpsBack - back) ))
				add2 = str(add)
				add3 = hex (int(i.address + section.startLoc	- (NumOpsBack - back) ))
				add4 = str(add3)
			offsets.append(addb)
			val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
			# val2.append(val)
			# val3.append(add2)
			val5.append(val)
			# dprint2(val)

			disString = val5
			# dprint2("before")
			# dprint2(disString)
			# disString = disString[2:]

			# dprint2("after")
			# dprint2(disString)
			heav_match = False

			#check for dword ptr fs:[reg] and verify value of register
		retf = False

		push_offset = ""
		t = 0
		for line in disString:
			# print("HEAVLINE", line)
			bad = re.match("^((jmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns)|(call))", line, re.M|re.I)   # addd call
			if(bad and (not retf)):
				retfBad = True

				dprint2 ("got bad")



			if(re.match("^((ljmp)|(lcall)) 0x33:", line, re.IGNORECASE)):
				heav_match = True
				offset = line.split()[-1]
				offset = offset[:-1]
				destLocation = line.split(':')[-1] 
			if(re.match("^retf", line, re.IGNORECASE)):
				# print("FOUND RETF")
				retf = True
				retfBad = False
				# heav_match = True
				offset = line.split()[-1]
				offset = offset[:-1]

			if(re.search("push 0x33", line, re.IGNORECASE)):
				push_offset = offsets[t]
				# print("SAVED PUSH OFFSET: ", push_offset)

			byte = re.search("byte ptr", line, re.IGNORECASE)
			insd = re.search("insd", line, re.IGNORECASE)
			outsd = re.search("outsd", line, re.IGNORECASE)
			# longNum = re.search("(0x)([0-9a-f]){6,}", line, re.IGNORECASE)
			longNum = re.search("\[?(0x)([0-9a-f]){6,}\]", line, re.IGNORECASE)

			#adc eax, dword[0xe0ff42]
			#dword ptr [eax + 0xe0ff4212]
			#dword ptr [0xe0ff4212]
			if(byte or insd or longNum or outsd):
				unlikely = unlikely + 1



		if(heav_match and (unlikely < 3)):

			dprint2("heavenhere")
			dprint2(line)

			if(rawHex):
				modSecName = peName
			else:
				modSecName = section.sectionName
			saveBaseHeaven(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, offset)
			return

		elif(retf and (unlikely < 3) and (not retfBad)):
			dprint2("heavenhere")
			dprint2(line)


			# print("RETF DISSTRING = ", disString)
			startStates = ("unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown")
			stack = trackRegs(disString, startStates, [])[1]
			# stack = trackRegs(disString, regsVals, [])[1]
			# dprint2("STACK IS HERE")
			# dprint2(stack)
			if(hex(0x33) in stack):
				flag33 = False
				destLocation = -1
				for i in range(len(stack)-1, -1, -1):
					if(flag33):
						destLocation = stack[i]
						flag33 = False

					if(stack[i] == hex(0x33)):
						flag33 = True

				destRegex = "push " + destLocation
				print("DESTREGEX = ", destRegex)
				pushOffset = -1
				for line in disString:
						pushLine = re.match(destRegex, line, re.IGNORECASE)
						if pushLine:
								pushOffset = line.split()[-1]
								pushOffset = pushOffset[:-1]
				
				
				modSecName = peName
				saveBaseHeaven(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, offset, destLocation = destLocation, pushOffset = int(pushOffset, 0)	)

			return


		t += 1
			# if(c0_match and (unlikely < 3)):
			# 	# dprint2("c0 match")
			# 	# dprint2("SAVING THIS ONE")
			# 	# input()
			# 	if(rawHex):
			# 		modSecName = peName
			# 	else:
			# 		modSecName = section.sectionName

			# 	startStates = ("unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown")
			# 	eax = trackRegs(disString, startStates, [])[0][0]
			# 	if(eax == "0x26"):
			# 		# dprint2("TrackRegs found eax = " + str(eax))
			# 		saveBaseEgg(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, eax, c0_offset)
			# 	return



def work_from_directory():
	global filename
	global rawHex
	global rawBin
	global peName
	global rawData2


	readConf()

	for i in list_of_files:
		dirName = '\\'.join(i.split("\\")[:-1])
		fileName = i.split("\\")[-1]
		output = "******************************\n"
		output += yel + "\nFile      : " + gre + fileName +res + "\n"
		output += yel + "Directory : " + gre + dirName + res + "\n\n"
		output += "******************************\n\n"
		print(output)
		# print("******************************"  + yel + "\nFile: " + gre + i +res + "\n******************************")

		if os.path.isfile(i):
			if i[-3:] == "txt":
				newModule()
				# Extraction()
				rawHex = True
			elif i[-3:] == "exe":
				peName = i
				rawHex = False

			else:
				newModule()

				rawHex = True
				rawBin = True
				# peName = i
				f = open(i, "rb")
				rawData2 = f.read()
				# print("Length of rawData2", len(rawData2))
				f.close()
			filename = i
			# print(filename)
			# input()
			# print("O Before ", m)

			init2(filename)
			startupPrint()
			# print("peb: ", bPEBFound)

			clearAll()


def getHeavenRawHex_old(address, linesBack, secNum, data):
		global regsVals
		address = hex(address)
		linesGoBack = 10
		t = 0
		truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, 0x0, linesGoBack)  # arg: starting offset/entry point - leave 0 generally



		dprint2("TESTING PRESYSCAL")

		if truth:
			push_offset = -1
			destLocation = -1
		####the FULL disassembly of the shellcode
			# print ("Full disassembly of shellcode EGG")
			for e in orgListDisassembly:
				#account for if we're at the very beginning of the code

				push_offset = -1
				print (str(hex(orgListOffset[t])) + "\t" + e)
				

				isRETF = re.search("retf", e, re.IGNORECASE)
				isJMP = re.search("ljmp 0x33:", e, re.IGNORECASE)
				isCALL = re.search("lcall 0x33:", e, re.IGNORECASE)
				if(isCALL or isJMP):
					offset = hex(orgListOffset[t])
					address = int(orgListOffset[t])
					t_temp = 0

					if(t-linesBack < 0):
						chunk = orgListDisassembly[0:t+1]
						chunkOffsets = orgListOffset[0:t+1]
					else:
						chunk = orgListDisassembly[t-linesBack:t+1]
						chunkOffsets = orgListOffset[t-linesBack:t+1]
					# print("\n\n\n CHUNK HERE")

					# for item in chunk:
						# print (str(hex(chunkOffsets[t_temp])) + "\t" + item)
						# t_temp += 1 
					# dprint2("\n\n\n")

					heavString = e
					destLocation = heavString.split(':')[-1]
					converted = convertStringToTrack(chunk, chunkOffsets)
					modSecName = peName
					saveBaseHeaven(address, -1, (linesBack), modSecName, secNum, offset, converted)
					# dprint2("CONVERTED")


					# for item in converted:
						# dprint2( item)

				elif(isRETF):
					c = 0
					pushCount = 0
					pushed33 = False
					offset = hex(orgListOffset[t])
					address = int(orgListOffset[t])
					t_temp = 0

					print("t-LinesBack here: ", t-linesBack	)
					if(t-linesBack < 0):
						chunk = orgListDisassembly[0:t+1]
						chunkOffsets = orgListOffset[0:t+1]
					else:
						chunk = orgListDisassembly[t-linesBack:t+1]
						chunkOffsets = orgListOffset[t-linesBack:t+1]
					# print("\n\n\n CHUNK HERE")
					# for item in chunk:
						# print (str(hex(chunkOffsets[t_temp])) + "\t" + item)
						# t_temp += 1 
					# print("\n\n\n")
					# for line in chunk:
					# 	if(re.search("push 0x33", line, re.IGNORECASE)):
					# 		push_offset = chunkOffsets[c]
					# 		pushed33 = True
					# 		pushCount = 0
					# 	elif(re.search("push", line, re.IGNORECASE) and pushed33):
					# 		pushCount += 1

					# 	if(pushCount >= 2):
					# 		push_offset = -1
					# 		pushCount = 0
					# 		pushed33 = False
							
					# 	c += 1

					converted = convertStringToTrack(chunk, chunkOffsets)
					startStates = ("unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown")
					stack = trackRegs(converted, startStates, [])[1]
					print("STACK IS HERE")
					print(stack)
					# print("RELATED CHUNK:")
					# for line in chunk:
					# 	print(line)
					# print("END RELATED CHUNK")

					if(hex(0x33) in stack):
						print("found33 in stack")
						flag33 = False
						destLocation = -1
						for i in range(len(stack)-1, -1, -1):
							# print("checking this value: ", stack[i])
							if(flag33):
								# print("set deslocation = ", stack[i])
								destLocation = stack[i]
								flag33 = False

							if(stack[i] == hex(0x33)):
								# print("set 33 flag")
								flag33 = True

						# print("after loop, destLocation = ", destLocation)
						if(destLocation != -1 and destLocation != "unknown"):
							c = 0
							destRegex = "push " + destLocation
							print("DESTREGEX : ", destRegex	)
							for line in chunk:
								if(re.search(destRegex, line, re.IGNORECASE)):
									push_offset = chunkOffsets[c]
								c += 1
						modSecName = peName

						saveBaseHeaven(address, -1, (linesBack), modSecName, secNum, offset, converted)
					# # dprint2("eax = " + str(eax) + "\n\n\n")

					# if(eax == "0x26"):
					# 	# dprint2("TrackRegs found eax = " + str(eax))
					


				t+=1

			clearTempDis()
			# print ("\n\n\n")


def saveBaseHeaven_old(address, NumOpsDis, linesBack, modSecName, secNum, offset, converted = ""):
	if(secNum != "noSec"):
		dprint2("heavensave")
		s[secNum].save_Heaven_info.append(tuple((address,NumOpsDis,linesBack,modSecName,secNum, offset)))
	else:
		dprint2("Saving one raw")

		secNum = -1
		modSecName = "rawHex"
		m[o].save_Heaven_info.append(tuple((address,NumOpsDis,linesBack,modSecName,secNum, offset, pushOffset, destLocation, converted)))


def disHereHeavenPE(address, NumOpsDis, NumOpsBack, secNum, data): ############ AUSTIN ##############

	global o
	global total1
	global total2
	global fcount
	w=0
	if shellBit == 32:
		callCS = cs
	else:
		callCS = cs64
	disString = []
	destLocation = -1
	push_offset = -1


	op_const = 16
	line_const = 8
	NumOpsBack = NumOpsBack + op_const

	retfBad = False
	## Capstone does not seem to allow me to start disassemblying at a given point, so I copy out a chunk to  disassemble. I append a 0x00 because it does not always disassemble correctly (or at all) if just two bytes. I cause it not to be displayed through other means. It simply take the starting address of the jmp [reg], disassembles backwards, and copies it to a variable that I examine more closely.
	#lGoBack = linesGoBackFindOP

	# dprint2("disHere")
	# dprint2(hex(address))
	# dprint2(secNum)
	#input("addy")


	CODED2 = ""
	x = NumOpsDis
	# start = timeit.default_timer()
	if(secNum != "noSec"):
		section = s[secNum]




	# dprint2("------------------------------------")
	for back in range(NumOpsBack):
		unlikely = 0
		# dprint2("back = " + str(back))
		CODED2 = data[(address-(NumOpsBack-back)):(address+x)]

			#dprint2("########################")
		#	dprint2(type(CODED2))
		#	dprint2("########################")
		#
		# stop = timeit.default_timer()
		# total1 += (stop - start)
		# dprint2("Time 1 PEB: " + str(stop - start))


		# I create the individual lines of code that will appear>
		# dprint2(len(CODED2))
		val =""
		val2 = []
		val3 = []
		#address2 = address + section.ImageBase + section.VirtualAdd
		val5 =[]


		# start = timeit.default_timer()
		#CODED3 = CODED2.encode()
		CODED3 = CODED2
		# dprint2("BINARY2STR")
		# dprint2(binaryToStr(CODED3))
		# dprint2("******************************************")
		offsets = []
		for i in callCS.disasm(CODED3, address):
			# dprint2('address in for = ' + str(address))
			if(secNum == "noSec"):

			#	dprint2("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
				# add = hex(int(i.address))
				add4 = hex(int(i.address))
				addb = hex(int(i.address))
			else:
				add = hex(int(i.address))
				addb = hex(int(i.address +  section.VirtualAdd  - (NumOpsBack - back) ))
				add2 = str(add)
				add3 = hex (int(i.address + section.startLoc	- (NumOpsBack - back) ))
				add4 = str(add3)
			offsets.append(addb)
			val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
			# val2.append(val)
			# val3.append(add2)
			val5.append(val)

			# dprint2(val)

			disString = val5
			# print(disString)
			# input()
			# dprint2("before")
			# dprint2(disString)
			# disString = disString[2:]
			# dprint2("after")
			# dprint2(disString)
		heav_match = False
			#check for dword ptr fs:[reg] and verify value of register
		retf = False

		push_offset = ""
		t = 0
		# print("Length: ", len(disString))
		# input()
		for line in disString:
			# dprint2("HEAVLINE", line)
			bad = re.match("^((jmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns)|(call))", line, re.M|re.I)   # addd call
			if(bad and (not retf)):
				retfBad = True
				# dprint2("got bad")


			if(re.match("^((ljmp)|(lcall)) 0x33:", line, re.IGNORECASE)):
				heav_match = True
				offset = line.split()[-1]
				offset = offset[:-1]
				destLocation = line.split(':')[-1] 
			if(re.match("^retf", line, re.IGNORECASE)):
				# dprint2("FOUND RETF")
				retf = True
				retfBad = False
				# heav_match = True
				offset = line.split()[-1]
				offset = offset[:-1]

			if(re.search("push 0x33", line, re.IGNORECASE)):
				push_offset = offsets[t]
				# dprint2("SAVED PUSH OFFSET: ", push_offset)

			byte = re.search("byte ptr", line, re.IGNORECASE)
			insd = re.search("insd", line, re.IGNORECASE)
			outsd = re.search("outsd", line, re.IGNORECASE)
			# longNum = re.search("(0x)([0-9a-f]){6,}", line, re.IGNORECASE)
			longNum = re.search("\[?(0x)([0-9a-f]){6,}\]", line, re.IGNORECASE)

			#adc eax, dword[0xe0ff42]
			#dword ptr [eax + 0xe0ff4212]
			#dword ptr [0xe0ff4212]
			if(byte or insd or longNum or outsd):
				unlikely = unlikely + 1

		if(heav_match and (unlikely < 3)):
			# dprint2("heavenhere")
			# dprint2(line)

			if(rawHex):
				modSecName = peName
			else:
				modSecName = section.sectionName
			saveBaseHeaven(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, offset,"ljmp/lcall", destLocation = destLocation)
			return

		elif(retf and (unlikely < 3) and (not retfBad)):
			# dprint2("heavenhere")
			# dprint2(line)

			# dprint2("RETF DISSTRING = ", disString)
			startStates = ("unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown")
			stack = trackRegs(disString, startStates, [])[1]
			# dprint2("STACK IS HERE")
			# dprint2(stack)
			if(hex(0x33) in stack):
				flag33 = False
				destLocation = -1
				for i in range(len(stack)-1, -1, -1):
					if(flag33):
						destLocation = stack[i]
						flag33 = False

					if(stack[i] == hex(0x33)):
						flag33 = True

				destRegex = "push " + destLocation
				dprint2("DESTREGEX = ", destRegex)
				pushOffset = -1
				for line in disString:
						pushLine = re.match(destRegex, line, re.IGNORECASE)
						if pushLine:
								pushOffset = line.split()[-1]
								pushOffset = pushOffset[:-1]
				
				
				if(rawHex):
					modSecName = peName
				else:
					modSecName = section.sectionName
				saveBaseHeaven(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, offset, "retf", destLocation = destLocation, pushOffset = int(pushOffset, 0))

			return


		t += 1
			# if(c0_match and (unlikely < 3)):
			# 	# dprint2("c0 match")
			# 	# dprint2("SAVING THIS ONE")
			# 	# input()
			# 	if(rawHex):
			# 		modSecName = peName
			# 	else:
			# 		modSecName = section.sectionName

			# 	startStates = ("unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown")
			# 	eax = trackRegs(disString, startStates, [])[0][0]
			# 	if(eax == "0x26"):
			# 		# dprint2("TrackRegs found eax = " + str(eax))
			# 		saveBaseEgg(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, eax, c0_offset)
			# 	return

def getHeavenRawHex(address, linesBack, secNum, data):
		address = hex(address)
		linesGoBack = linesBack
		t = 0
		truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, 0x0, linesGoBack)  # arg: starting offset/entry point - leave 0 generally

		# dprint2("TESTING PRESYSCAL")
		if truth:
			push_offset = -1
			destLocation = -1
		####the FULL disassembly of the shellcode
			# dprint2("Full disassembly of shellcode EGG")
			for e in orgListDisassembly:
				#account for if we're at the very beginning of the code

				push_offset = -1
				dprint2(str(hex(orgListOffset[t])) + "\t" + e)
				

				isRETF = re.search("retf", e, re.IGNORECASE)
				isJMP = re.search("ljmp 0x33:", e, re.IGNORECASE)
				isCALL = re.search("lcall 0x33:", e, re.IGNORECASE)
				if(isCALL or isJMP):
					offset = hex(orgListOffset[t])
					address = int(orgListOffset[t])
					t_temp = 0
					if(t-linesBack < 0):
						chunk = orgListDisassembly[0:t+1]
						chunkOffsets = orgListOffset[0:t+1]
					else:
						chunk = orgListDisassembly[t-linesBack:t+1]
						chunkOffsets = orgListOffset[t-linesBack:t+1]
					# dprint2("\n\n\n CHUNK HERE")
					# for item in chunk:
						# dprint2(str(hex(chunkOffsets[t_temp])) + "\t" + item)
						# t_temp += 1 
					# dprint2("\n\n\n")

					heavString = e
					destLocation = heavString.split(':')[-1]
					converted = convertStringToTrack(chunk, chunkOffsets)
					modSecName = peName
					saveBaseHeaven(address, -1, (linesBack), modSecName, secNum, offset, "ljmp/lcall", pushOffset = push_offset, converted = converted, destLocation = destLocation)
					# dprint2("CONVERTED")
					# for item in converted:
						# dprint2( item)

				elif(isRETF):
					c = 0
					pushCount = 0
					pushed33 = False
					offset = hex(orgListOffset[t])
					address = int(orgListOffset[t])
					t_temp = 0
					dprint2("t-LinesBack here: ", t-linesBack	)
					if(t-linesBack < 0):
						chunk = orgListDisassembly[0:t+1]
						chunkOffsets = orgListOffset[0:t+1]
					else:
						chunk = orgListDisassembly[t-linesBack:t+1]
						chunkOffsets = orgListOffset[t-linesBack:t+1]
					# dprint2("\n\n\n CHUNK HERE")
					# for item in chunk:
						# dprint2(str(hex(chunkOffsets[t_temp])) + "\t" + item)
						# t_temp += 1 
					# dprint2("\n\n\n")
					# for line in chunk:
					# 	if(re.search("push 0x33", line, re.IGNORECASE)):
					# 		push_offset = chunkOffsets[c]
					# 		pushed33 = True
					# 		pushCount = 0
					# 	elif(re.search("push", line, re.IGNORECASE) and pushed33):
					# 		pushCount += 1

					# 	if(pushCount >= 2):
					# 		push_offset = -1
					# 		pushCount = 0
					# 		pushed33 = False
							
					# 	c += 1

					converted = convertStringToTrack(chunk, chunkOffsets)
					startStates = ("unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown")
					stack = trackRegs(converted, startStates, [])[1]
					dprint2("STACK IS HERE")
					dprint2(stack)
					# dprint2("RELATED CHUNK:")
					# for line in chunk:
					# 	dprint2(line)
					# dprint2("END RELATED CHUNK")

					if(hex(0x33) in stack):
						dprint2("found33 in stack")
						flag33 = False
						destLocation = -1
						for i in range(len(stack)-1, -1, -1):
							# print("Processing: ", str(stack[i]))
							if(stack[i] == hex(0x33)):
								# print("Flag True")
								# input()
								# dprint2("set 33 flag")
								flag33 = True
							# dprint2("checking this value: ", stack[i])
							if(flag33):
								# dprint2("set deslocation = ", stack[i])
								destLocation = stack[i]
								# print("New dstlocation", str(stack[i]))
								flag33 = False

							# if(stack[i] == hex(0x33)):
							# 	print("Flag True")
							# 	input()
							# 	# dprint2("set 33 flag")
							# 	flag33 = True
						# dprint2("after loop, destLocation = ", destLocation)
						if(destLocation != -1 and destLocation != "unknown"):
							c = 0
							destRegex = "push " + destLocation
							dprint2("DESTREGEX : ", destRegex	)
							for line in chunk:
								if(re.search(destRegex, line, re.IGNORECASE)):
									push_offset = chunkOffsets[c]

								c += 1

						modSecName = peName
						saveBaseHeaven(address, -1, (linesBack), modSecName, secNum, offset, "retf", pushOffset = push_offset, destLocation = destLocation, converted = converted)
					# # dprint2("eax = " + str(eax) + "\n\n\n")
					# if(eax == "0x26"):
					# 	# dprint2("TrackRegs found eax = " + str(eax))
					


				t+=1

			clearTempDis()

		if(rawHex):
			m[o].save_Heaven_info = helperListToSet(m[o].save_Heaven_info)
		else:
			s[secNum].save_Heaven_info =helperListToSet(s[secNum].save_Heaven_info)
			# print ("\n\n\n")

def saveBaseHeaven(address, NumOpsDis, linesBack, modSecName, secNum, offset, pivottype, pushOffset = -1, destLocation = -1, converted = ""):
	if(secNum != "noSec"):
		found = False
		# saving = tuple((address,NumOpsDis,linesBack,modSecName,secNum, offset, pushOffset, destLocation, pivottype))
		for i in s[secNum].save_Heaven_info:
			if offset == i[5]:
				found = True
				# print("found")
		#dprint2("heavensave")
		# print("--> ", saving)
		# input()
		if not found:
			s[secNum].save_Heaven_info.append(tuple((address,NumOpsDis,linesBack,modSecName,secNum, offset, pushOffset, destLocation, pivottype)))
	else:

		dprint2("Saving one raw")

		secNum = -1
		modSecName = "rawHex"
		m[o].save_Heaven_info.append(tuple((address,NumOpsDis,linesBack,modSecName,secNum, offset, pushOffset, destLocation, converted, pivottype)))

def printSavedHeaven(bit = 32): ######################## AUSTIN ###############################3
	#formatting
	if(bit32):
		callCS = cs
	else:
		callCS = cs64

	j = 0
	if(rawHex):
		for item in m[o].save_Heaven_info:

			address = item[0]
			NumOpsDis = item[1]
			NumOpsBack = item[2]
			modSecName = item[3]
			secNum = item[4]
			offset = item[5]
			pushOffset = item[6]
			destLocation = item[7]
			converted = item[8]
			pivottype = item[9]
			# print("here is pushOffset in print: ", pushOffset)

			outString = "\n\nHeaven Item: " + str(j)
			if(secNum != -1):

				outString += " | Section: " + str(secNum) + " | Section name: " + modSecName.decode() + " | Heaven's Gate offset: " + str(offset) 
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName + " | Heaven's Gate offset: " + str(offset) + " | Push dest. addr offset: " + hex(pushOffset) + " | Dest. Address: " + str(destLocation)

			print ("\n********************************************************")
			print (yel + outString + res)
			print ("\n")
			if(pivottype == "ljmp/lcall"):
				converted = converted[-1:]
			elif(pivottype == "retf"):
				converted = converted[-5:]
			for line in converted:
				print(gre + line + res)
	#return val5
			print ("\n")
			j += 1

	else:
		h = 0
		for section in s:
			h += 1
			# print("PRINTING SECTION " + str(h))
			for item in section.save_Heaven_info:
				CODED2 = ""


				address = item[0]
				NumOpsDis = item[1]
				NumOpsBack = item[2]
				modSecName = item[3]
				secNum = item[4]
				offset = item[5]
				pushOffset = item[6]
				destLocation = item[7]
				pivottype = item[8]

				# print("NUMBACK = " + str(NumOpsBack))

				section = s[secNum]

				outString = "\nHeaven Item: " + str(j)
				if(secNum != -1):
					outString += " | Section: " + str(secNum) + " | Section name: " + modSecName.decode() + " | Heaven's Gate offset: " + str(offset) + " | Push dest. addr offset: " + hex(pushOffset) + " | Dest. Address: " + str(destLocation) + "\n"

					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName + " | Heaven's Gate offset: " + str(offset) + " | Push dest. addr offset: " + hex(pushOffset) + " | Dest. Address: " + str(destLocation) + "\n"



				print ("\n********************************************************")
				print (yel + outString + res)
				# print ("\n")
				val =""
				val2 = []
				val3 = []
				address2 = address + section.ImageBase + section.VirtualAdd
				val5 =[]
				# CODED2 = section.data2[(address-NumOpsBack):(address+NumOpsDis)]
				bytesCompensation = 18
				if(pivottype == "ljmp/lcall"):
					start = int(offset, 16) - section.VirtualAdd
					#The 7 is for the ljmp assembly mnemonic
					CODED2 = section.data2[(start):(start+7)]
				elif(pivottype == "retf"):
					start = int(offset, 16) - section.VirtualAdd
					#The two bytes is for the retf
					CODED2 = section.data2[(start - bytesCompensation):start + 2]

				CODED3 = CODED2

				# for i in callCS.disasm(CODED3, address):
				if(pivottype == "ljmp/lcall"):
					bytesCompensation = 0
				elif(pivottype == "retf"):
					bytesCompensation = 18
				for i in callCS.disasm(CODED3, start - bytesCompensation):

					add = hex(int(i.address))
					# addb = hex(int(i.address +  section.VirtualAdd - NumOpsBack))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					# add3 = hex (int(i.address + section.startLoc	- NumOpsBack))
					add3 = hex (int(i.address + section.startLoc))
					add4 = str(add3)
					val = formatPrint(i, add4, addb, pe=True)

					# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					val5.append(val)
					print (gre + val + res)

				j += 1
				# print("\n")
				# print str(type(m[o].data2))
				# trash = raw_input("enter...")

def printSavedHeaven_old(bit = 32): ######################## AUSTIN ###############################3
	#formatting
	j = 0
	if(bit32):
		callCS = cs
	else:
		callCS = cs64
	if(rawHex):
		for item in m[o].save_Heaven_info:

			address = item[0]
			NumOpsDis = item[1]
			NumOpsBack = item[2]
			modSecName = item[3]
			secNum = item[4]
			offset = item[5]
			converted = item[6]

			

			outString = "\n\nHeaven Item: " + str(j)
			if(secNum != -1):

				outString += " | Section: " + str(secNum) + " | Section name: " + str(modSecName) + " | Heaven's Gate offset: " + str(offset)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName + " | Heaven's Gate offset: " + str(offset)

			print ("\n******************************************************************************")
			print (outString)
			print ("\n")
			for line in converted:
				print(line)
	#return val5
			print ("\n")
			j += 1


	else:
		h = 0
		for section in s:
			h += 1
			# print("PRINTING SECTION " + str(h))
			for item in section.save_Heaven_info:
				CODED2 = ""


				address = item[0]
				NumOpsDis = item[1]
				NumOpsBack = item[2]
				modSecName = item[3]
				secNum = item[4]
				offset = item[5]


				# print("NUMBACK = " + str(NumOpsBack))

				section = s[secNum]

				outString = "\n\nHeaven Item: " + str(j)
				if(secNum != -1):

					outString += " | Section: " + str(secNum) + " | Section name: " + str(modSecName) + " | Heaven's Gate offset: " + str(offset)
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName + " | Heaven's Gate offset: " + str(offset)


				print ("\n******************************************************************************")
				print (outString)
				print ("\n")
				val =""
				val2 = []
				val3 = []
				address2 = address + section.ImageBase + section.VirtualAdd
				val5 =[]

				CODED2 = section.data2[(address-NumOpsBack):(address+NumOpsDis)]

				CODED3 = CODED2
				for i in cs.disasm(CODED3, address):
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd - NumOpsBack))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc	- NumOpsBack))
					add4 = str(add3)
					val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					val5.append(val)
					print (val)
				print ("\n")
				j += 1
				# print str(type(m[o].data2))
				# trash = raw_input("enter...")

	

def convertStringToTrack(dis, offsets):

	dprint2("convertcall")
	dprint2(dis)
	dprint2(offsets)
	t = 0
	result = [""]
	#val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
	for item in dis:
		# outstr = '{:<35s} {:<20s} {:<20s}'.format(item, hex(offsets[t]), " (offset " + hex(offsets[t]) + ")")
		outstr = item + "\t\t\t\t" + " " + hex(offsets[t]) + " (offset " + hex(offsets[t]) + ")"
		result.append(outstr)
		t += 1

	return result



def saveBaseEgg(address, NumOpsDis, linesBack, modSecName, secNum, eax, c0_offset, converted = ""):

	if(secNum != "noSec"):

		# print ("before")
		# print (secNum)
		# print(type(secNum))
		s[secNum].save_Egg_info.append(tuple((address,NumOpsDis,linesBack,modSecName,secNum,eax, c0_offset)))
	else:
		dprint2("Saving one raw")
		secNum = -1
		modSecName = "rawHex"
		m[o].save_Egg_info.append(tuple((address,NumOpsDis,linesBack,modSecName,secNum, eax, c0_offset, converted)))



def printSavedEgg(bit = 32, showDisassembly = True): ######################## AUSTIN ###############################3
	#formatting)
	j = 0
	if(bit == 64):
		callCS = cs64
	else:
		callCS = cs
	if(rawHex):
		for item in m[o].save_Egg_info:

			address = item[0]
			NumOpsDis = item[1]
			NumOpsBack = item[2]
			modSecName = item[3]
			secNum = item[4]
			eax = item[5]
			c0_offset = item[6]
			converted = item[7]

			

			outString = "\n\nItem: " + str(j)
			if(secNum != -1):

				# outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
				outString += " | Section name: " + str(modSecName)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")

				
			else:
				outString += " | Module: " + modSecName

			outString += " | EAX: " + eax + " | Syscall Offset: " + c0_offset

			print ("\n******************************************************************************")
			print (yel + outString + res)
			print ("\n")
			if(showDisassembly):
				for line in converted:
					print(gre + line + res)

	#return val5
			print ("\n")
			j += 1
			if(eax != "unknown"):
				getSyscallRecent(int(eax, 0))

	else:
		h = 0
		for section in s:
			h += 1
			# print("PRINTING SECTION " + str(h))
			for item in section.save_Egg_info:
				CODED2 = ""


				address = item[0]
				NumOpsDis = item[1]
				NumOpsBack = item[2]
				modSecName = item[3]
				secNum = item[4]
				eax = item[5]
				c0_offset = item[6]

				# print("NUMBACK = " + str(NumOpsBack))

				section = s[secNum]

				outString = "\n\nItem: " + str(j)
				if(secNum != -1):

					outString += " | Section: " + modSecName.decode()
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				outString += " | EAX: " + eax + " | Syscall Offset: " + c0_offset

				print ("\n******************************************************************************")
				print (yel + outString + res)
				print ("\n")
				if(showDisassembly):
					val =""
					val2 = []
					val3 = []
					address2 = address + section.ImageBase + section.VirtualAdd
					val5 =[]

					CODED2 = section.data2[(address-NumOpsBack):(address+NumOpsDis)]

					CODED3 = CODED2
					for i in callCS.disasm(CODED3, address):
						add = hex(int(i.address))
						addb = hex(int(i.address +  section.VirtualAdd - NumOpsBack))
						add2 = str(add)
						add3 = hex (int(i.address + section.startLoc	- NumOpsBack))
						add4 = str(add3)
						val = formatPrint(i, add4, addb, pe=True)

						# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
						val2.append(val)
						val3.append(add2)
						val5.append(val)
						print (gre + val + res)
						if c0_offset == addb:
							break
					print ("\n")
				j += 1
				if(eax != "unknown"):
					getSyscallRecent(int(eax, 0))
				# print str(type(m[o].data2))
				# trash = raw_input("enter...")



def saveBasePEBWalk(address, NumOpsDis,modSecName,secNum, points, loadTIB_offset, loadLDR_offset, loadModList_offset, advanceDLL_Offset): 
	# print("saving")
	#save virtaul address as well

	peb_data = tuple((address,NumOpsDis,modSecName,secNum,points,loadTIB_offset,loadLDR_offset,loadModList_offset,advanceDLL_Offset))

	if(secNum != "noSec"):
		if peb_data not in s[secNum].save_PEB_info:
			s[secNum].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points,loadTIB_offset,loadLDR_offset,loadModList_offset,advanceDLL_Offset)))
	else:
		secNum = -1
		modSecName = "rawHex"
		m[o].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points,loadTIB_offset,loadLDR_offset,loadModList_offset,advanceDLL_Offset)))


def findAllFSTENV_old2(data2, secNum): ################## AUSTIN ######################
	if(secNum == 'noSec'):
		FSTENVrawhex(0, 10, 'noSec', data2)

	else:
		for match in FSTENV_GET_BASE.values(): #iterate through all opcodes representing combinations of registers
			get_FSTENV(10, 15, match, secNum, data2) 

def findAllFSTENV(data2, secNum): ################## AUSTIN ######################
	global linesBack
	# print("Inside findallfstenv", data2.hex())
	if(secNum == 'noSec'):
		FSTENVrawhex(0, linesBack, 'noSec', data2)
#numOps, match, secNum, data2, funcName = None):
	else:
		for match in FSTENV_GET_BASE.values(): #iterate through all opcodes representing combinations of registers
			optimized_find(10, match, secNum, data2, "disHereFSTENV")
			# get_FSTENV(10, 15, match, secNum, data2) 

def findAllSyscall(data2, secNum):
	for match in EGGHUNT.values():
		getSyscallPE(20, 20, match, secNum, data2)

def findAllHeaven_old2(data2, secNum):
	for match in HEAVEN.values():
		get_HeavenPE(4, 20, match, secNum, data2)

def findAllHeaven(data2, secNum):
	for match in HEAVEN.values():
		optimized_find(4, match, secNum, data2, "disHereHeavenPE")
		# get_HeavenPE(4, 20, match, secNum, data2)
#disHereHeavenPE(t, numOps, NumOpsBack, secNum, data2)
def findAllFSTENV_old(): ################## AUSTIN ######################

	if(rawHex):
		for match in FSTENV_GET_BASE.values(): #iterate through all opcodes representing combinations of registers
			get_FSTENV(10, 15, match, "noSec", rawData2) 


	elif(bit32):
		for secNum in range(len(s)):
			# print("Trying section: " + str(secNum))
			data2 = s[secNum].data2
			# print("before mov"
			for match in FSTENV_GET_BASE.values(): #iterate through all opcodes representing combinations of registers
				get_FSTENV(10, 15, match, secNum, data2) 


def findAllCallpop_old2(data2, secNum, numOps = 10): ################## AUSTIN ######################
	if(secNum == 'noSec'):
		callPopRawHex(0, secNum, data2)
	else:
		for match in CALLPOP_START.values(): #iterate through all opcodes representing combinations of registers
			# optimized_find(numOps, match, secNum, data2, "disHereCallpop")
			get_Callpop(numOps, match[0], secNum, data2, match[1]) 




def findAllCallpop(data2, secNum, numOps = 10):
 ################## AUSTIN ######################
	# print(data2.hex())
	if(secNum == 'noSec'):
		callPopRawHex(0, 15, secNum, data2)
	else:
		for match in CALLPOP_START.values(): #iterate through all opcodes representing combinations of registers
			optimized_find(numOps, match, secNum, data2, "disHereCallpop")
			# get_Callpop(numOps, match[0], secNum, data2, match[1]) 


def findAllCallpop64_old2(data2, secNum): ################## AUSTIN ######################

	for match in CALLPOP_START.values(): #iterate through all opcodes representing combinations of registers
		get_Callpop64(10, match[0], secNum, data2, match[1])

def findAllCallpop64(data2, secNum): ################## AUSTIN ######################

	for match in CALLPOP_START.values(): #iterate through all opcodes representing combinations of registers
		optimized_find(10, match, secNum, data2, "disHereCallpop64")
		# get_Callpop64(10, match[0], secNum, data2, match[1])



def findAllPebSequences_old(data2, secNum): ################## AUSTIN ######################
	# global rawHex
#get_PEB_walk_start(mode, NumOpsDis ,bytesToMatch, secNum, data2): 
#disHerePEB(mode, t, numOps, secNum, data2)
	for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
		optimized_find(19, match, secNum, data2, "disHerePEB")
		# get_PEB_walk_start("normal", 19, match, secNum, data2)

def findAllPebSequences_old2(data2, secNum): ################## AUSTIN ######################
	# global rawHex

	for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
		get_PEB_walk_start("normal", 19, match, secNum, data2) 


def optimized_find(numOps, match, secNum, data2, funcName = None):
	start = 0

	# print(funcName, type(data2))
	if "disHereCallpop" == funcName or "disHereCallpop64" == funcName:
		patternMatch = match[0]
	else:
		patternMatch = match
	foundFS = False
	while True:
		
		start = data2.find(patternMatch, start)
		if start == -1:
			break
		else:
			
			if "disHerePEB_64" == funcName:
				disHerePEB_64(start, numOps, secNum, data2)
			elif "disHereCallpop" == funcName:
				disHereCallpop(start, numOps, secNum, data2, match[1])
			elif "disHereCallpop64" == funcName:
				disHereCallpop64(start, numOps, secNum, data2, match[1])
			elif "disHerePushRet" == funcName:
				disHerePushRet(start, numOps, secNum, data2)
			elif "disHerePushRet64" == funcName:
				disHerePushRet64(start, numOps, secNum, data2)
			elif "disHereFSTENV" == funcName:
				disHereFSTENV(start, numOps, 15, secNum, data2)
			elif "disHereSyscall" == funcName:
				disHereSyscall(start, numOps, 20, secNum, data2)
			elif "disHerePEB" == funcName:
				disHerePEB("normal", start, numOps, secNum, data2)
			elif "disHereHeavenPE" == funcName:
				matchList = ["push", "xor", "xchg", "pop", "sub", "add"]
			# dprint2("back = " + str(back))
			# CODED2 = data[(address-(NumOpsBack-back)):(address+x)]
				flag = False
				for back in range(20):

		# dprint2("back = " + str(back))
			# CODED2 = data[(address-(NumOpsBack-back)):(address+x)]
					CODED3 = data2[start - (20-back):(start+numOps)]
			# CODED3 = data2[start:(start+numOps)]
					instr=""
					for i in cs.disasm(CODED3, start):
						instr+=  i.mnemonic + " "
					# print("intr", instr)
					# input()
					if "retf" in instr:
						if "add" in instr or "push" in instr or "xor" in instr or "xchg" in instr or "pop" in instr or "sub" in instr:
							flag = True
							# foundFS = False
					if "lcall" in instr or "ljmp" in instr:
						# print("CODED3", CODED3.hex(), "back --> ",back, instr, start)
						# input()
						flag = True
				if flag:
					disHereHeavenPE(start, numOps, 20, secNum, data2)
#disHerePEB(mode, t, numOps, secNum, data2)
#disHereHeavenPE(t, numOps, NumOpsBack, secNum, data2)

			# disHerePEB_64(start, 28, secNum, data2)
			start += len(patternMatch)

#mode, data2=None, secNum=None
# def findAllPebSequences(data2, secNum, mode): ################## AUSTIN ######################
def findAllPebSequences_old2(mode, data2=None, secNum=None): ################## AUSTIN ######################

	# global rawHex
	# print ("findAllPebSequences", mode, binaryToStr(rawData2),)
	if(rawHex):
		# print("in check")

		if shellBit == 32:
			for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
				# ans=get_PEB_walk_start(mode, 19, match, "noSec", data2) #19 hardcoded for now, seems like good value for peb walking sequence
				ans=get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
				# print ("ans", ans)

				if mode=="decrypt" and ans is not None:
					print ("good, get peb walk")
					print (ans)
					return (ans)
		else:
			# print("Here")
			# input()
			for match in PEB_WALK_MOV_64.values():
				get_PEB_walk_start_64(28, match, secNum, data2)

		# for match in PEB_WALK_ADD.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_ADC.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_OR.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_XOR.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_XCHG.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
	else:

		if(bit32):
			for secNum in range(len(s)):
				# print("Trying section: " + str(secNum))
				data2 = s[secNum].data2

				# print("before mov")
				for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
					get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# # # print("after mov")
			# for match in PEB_WALK_MOV_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_ADD_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_ADC_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_OR_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_XOR_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_XCHG_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence

			# def get_PEB_walk_start_64(NumOpsDis ,bytesToMatch, secNum, data2):

			# 	if(found):
			# 			disHerePEB_64(t, numOps, secNum, data2)
		else:
			startTime = time.time()

			for secNum in range(len(s)):
				# print("Sec Num: ", secNum)
				data2 = s[secNum].data2
				# start = time.time()
				data2Tmp = data2
				# offset = 0
				# index=0
				for match in PEB_WALK_MOV_64.values(): #iterate through all opcodes representing combinations of registers
					# print("Finding value", match.hex())
					# optimized_find(match, secNum, data2, disHerePEB_64) 
					# optimized_find(match, secNum, data2, disHerePEB_64) 
					# optimized_find(match, secNum, data2) 

					# print("Section ", secNum)
					# start = 0
					# while True:
					# 	start = data2.find(match, start)
					# 	if start == -1:
					# 		break
					# 	else:
							# disHerePEB_64(start, 28, secNum, data2)
					# 		start += len(match)

					get_PEB_walk_start_64(28, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence


					# if match in data2Tmp:
					# # 	print("found one")
					# 	offset = data2.find(match)
					# 	print("Offset is: ", offset, secNum)
					# 	disHerePEB_64(offset, 28, secNum, data2)
					# 	offset += 1
					# 	index += 1
					# data2Tmp = data2Tmp[index:]
					# disHerePEB_64(t, numOps, secNum, data2)
					# data2 = s[secNum].data2
					# print("Testing..")
					# if match in data2:
						# print("data2 at  39068", hex(data2[39068]), hex(data2[16974]))
						# print("Found already at", data2.index(match))
						# disHerePEB_64(data2.index(match), 28, secNum, data2)
				# end = time.time()
				# print("Time: ", (end-start))
			end = time.time()
			print("\nElapsed time: ", end-startTime)

def findAllPebSequences(mode, data2=None, secNum=None): ################## AUSTIN ######################
	global shellBit
	# global rawHex
	# print ("findAllPebSequences", mode, binaryToStr(rawData2),)
	if(rawHex):
		# print("in check")

		if shellBit == 32:

			for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
				# ans=get_PEB_walk_start(mode, 19, match, "noSec", data2) #19 hardcoded for now, seems like good value for peb walking sequence
				ans=get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
				# print ("ans", ans)

				if mode=="decrypt" and ans is not None:
					print ("good, get peb walk")
					print (ans)
					return (ans)
		else:
			# print("Here")
			# input()
			for match in PEB_WALK_MOV_64.values():
				get_PEB_walk_start_64(28, match, secNum, data2)

		# for match in PEB_WALK_ADD.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_ADC.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_OR.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_XOR.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_XCHG.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
	else:

		if(bit32):
			for secNum in range(len(s)):
				# print("Trying section: " + str(secNum))
				data2 = s[secNum].data2

				# print("before mov")
				for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
					optimized_find(19, match, secNum, data2, "disHerePEB")
					# get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# # # print("after mov")
			# for match in PEB_WALK_MOV_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_ADD_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_ADC_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_OR_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_XOR_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence
			# for match in PEB_WALK_XCHG_OLD.values(): #iterate through all opcodes representing combinations of registers
			# 	get_PEB_walk_start(mode, 19, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence

			# def get_PEB_walk_start_64(NumOpsDis ,bytesToMatch, secNum, data2):

			# 	if(found):
			# 			disHerePEB_64(t, numOps, secNum, data2)
		else:

			for secNum in range(len(s)):
				# print("Sec Num: ", secNum)
				data2 = s[secNum].data2
				# start = time.time()
				data2Tmp = data2
				# offset = 0
				# index=0
				for match in PEB_WALK_MOV_64.values(): #iterate through all opcodes representing combinations of registers
					# print("Finding value", match.hex())
					optimized_find(28, match, secNum, data2, "disHerePEB_64") 

					# print("Section ", secNum)
					# start = 0
					# while True:
					# 	start = data2.find(match, start)
					# 	if start == -1:
					# 		break
					# 	else:
							# disHerePEB_64(start, 28, secNum, data2)
					# 		start += len(match)

					# get_PEB_walk_start_64(28, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence


					# if match in data2Tmp:
					# # 	print("found one")
					# 	offset = data2.find(match)
					# 	print("Offset is: ", offset, secNum)
					# 	disHerePEB_64(offset, 28, secNum, data2)
					# 	offset += 1
					# 	index += 1
					# data2Tmp = data2Tmp[index:]
					# disHerePEB_64(t, numOps, secNum, data2)
					# data2 = s[secNum].data2
					# print("Testing..")
					# if match in data2:
						# print("data2 at  39068", hex(data2[39068]), hex(data2[16974]))
						# print("Found already at", data2.index(match))
						# disHerePEB_64(data2.index(match), 28, secNum, data2)
				# end = time.time()
				# print("Time: ", (end-start))


def findAllPushRet(data2, secNum): ################## AUSTIN #########################
	if(secNum == 'noSec'):
		PushRetrawhex(0, 'noSec', data2)
	else:
		for match in PUSH_RET.values():
			optimized_find(4, match, secNum, data2, "disHerePushRet") 
			# get_PushRet_start(4, match, secNum, data2)

	# for match in PUSH_RET.values(): 
	# 	get_PushRet_start(4, match, secNum, data2)
def findAllPushRet_old2(data2, secNum): ################## AUSTIN #########################
	if(secNum == 'noSec'):
		PushRetrawhex(0, 'noSec', data2)
	else:
		for match in PUSH_RET.values():
			get_PushRet_start(4, match, secNum, data2)


def findAllPushRet_old(): ################## AUSTIN #########################
	if(rawHex):
		for match in PUSH_RET.values(): 
			get_PushRet_start(4, match, "noSec", rawData2)

	elif(bit32):
		for secNum in range(len(s)):
			data2 = s[secNum].data2
			for match in PUSH_RET.values(): #iterate through all opcodes representing combinations of registers
				get_PushRet_start(4, match, secNum, data2) 

def findAndPrintSuspicious():  ################## AUSTIN #########################
	mode=""
	findAllPebSequences(mode)
	findAllPushRet()
	printSavedPEB()
	printSavedPushRet()

	

def findStrings(binary,Num):#,t):
	dprint2 ("findingStrings sharem")
	global t
	global o
	global stringsTemp
	newop=" 0x00\t"
	newAscii=""
	# newUnicode=""
	old=0
	offset=0
	word=""
	wordSize=0
	skip=False
	try:
		x=0
		y=1
		inProgress=False
		for v in binary:
			i = ord2(v) 
			newop += " "+show1(i)
			if inProgress==False:
				# print ("before")
				test=chr(i)
				# print ("after")
				if test.isalpha()==False:
					# print ("falsity")
					skip =True

				if test.isalpha()==True:
					# print ("truth")
					skip =False
			# print (skip)
			if (i > 31) & (i < 127) & (skip==False):
				if inProgress==False:
					offset=x
				inProgress=True
				word += ""+chr(i)
				# print (word)
			else:
				if inProgress:
					if (len(word) >= Num):
						# print "t: " + str(t)
						wordSize=len(word)
						try:
							s[t].Strings.append(tuple((word, offset, wordSize)))
						except:
							# print ("saving string", word.encode("utf-8"))
							# print("6934", word)
							stringsTemp.append(tuple((word, offset, wordSize)))
					inProgress=False
					word=""
					offset=0
			x+=1
			y+=1
			if x == len(binary):   #last byte, final end
			# dprint ("reached")
				wordSize=len(word)
				# dprint2 (word, hex(offset), wordSize)
				if wordSize>0:
					try:
						s[t].Strings.append(tuple((word, offset, wordSize)))
					except: 

						# print("6949", word)
						# print ("saving string", word.encode("utf-8"))
						stringsTemp.append(tuple((word, offset, wordSize)))
	except Exception as e:
		print ("*String finding error1!!!")
		print (e)

	# print (stringsTemp)


def changeWide(word):

	wordNodots = word.replace(".", "")
	return wordNodots



def findStringsWide(binary,Num):#,t):
	dprint2 ("findStringsWide")
	global t
	global o
	global s
	global stringsTempWide
	newop=" 0x00\t"
	newAscii=""
	old=0
	offset=0
	limit=0
	try:
		x=0
		y=1
		word=""
		inProgress=False
		PossibleWide=False
		WideCnt=0
		maxBinary=len(binary)
		for v in binary:
			i = ord2(v) 
			newop += " "+show1(i)
			previous=chr(i)
			if (i > 31) & (i < 127):
				if inProgress==False:
					offset=x
				inProgress=True
				word += ""+chr(i)
				limit=0
				if ((x==maxBinary-1)):
					if (len(word) >= (Num*2)):
						odd = True
						even = True

						for i in range(len(word)):

							if (i%2) != 0:
								# print("I: ", i, word)
								if(word[i] != "."):
									odd = False
						
							if i == 10:
								break

						# if ((word[1]==".") and (word[3]==".") and (word[5]==".") and (word[7]==".") and (word[9]==".") and (word[2]!=".") and (word[4]!=".") and (word[6]!=".") and (word[8]!=".") and (word[10]!=".")):
						if odd:
							wordSize=len(word)
							# print ("ws - got one1\n")
							try:

								# print("word", word, "offset", hex(offset))
								s[t].wideStrings.append(tuple((word, offset,wordSize)))
							except:
								# print("7001", word)

								stringsTempWide.append(tuple((word, offset,wordSize)))
			else:
				if inProgress:
					if (i==0):
						WideCnt+=1
						limit+=1
						if limit < 2:
							PossibleWide=True
							word+="."
						
						if limit > 1:
							PossibleWide=False
						try:
							length=len(word)
							if ((word[length-2]==" ") and (word[length-3]==".") and (WideCnt >= Num)):
							# if ((word[length-2]=="\x00") and (word[length-3]=="\x00") and (WideCnt >= Num)):
								inProgress=False
								if (len(word) >= (Num*2)):
									odd = True
									even = True

									for i in range(len(word)):

										if (i%2) != 0:
											# print("I: ", i, word)
											if(word[i] != "."):
												odd = False
									
										if i == 10:
											break



										if odd:
									# if ((word[1]==".") and (word[3]==".") and (word[5]==".") and (word[7]==".") and (word[9]==".") and (word[2]!=".") and (word[4]!=".") and (word[6]!=".") and (word[8]!=".") and (word[10]!=".")):
											if ((ord(word[0])>0x40 ) and (ord(word[0])<0x5b ) or (ord(word[0])>0x60 ) and (ord(word[0])<0x7b )):
												# wordSize=len(word)
												# print ("wideStrings - got one2", "t", hex(t), word, hex(offset), wordSize)
												wordSize=int(len(word)/2)
												word = changeWide(word)
												if wordSize>0:
													try:
														
														s[t].wideStrings.append(tuple((word, offset,wordSize)))
														# print ("success")
													except:
														# print("7028", word)
														# print("7036", hex(offset), word)
														stringsTempWide.append(tuple((word, offset,wordSize)))
								word=""
								offset=0
								WideCnt=0
						except:
							pass
				if (i!=0):
					PossibleWide=False
					limit=0
				if ((inProgress==True) & (PossibleWide == False)) or ((x==maxBinary) and (inProgress==True)):# & (WideCnt >= Num):
					# print("Size of word", len(word), word)
					if (len(word) >= (Num*2)):
						# print("Problem with ", word)
						# # input()
						odd = True
						even = True

						for i in range(len(word)):

							if (i%2) != 0:
								# print("I: ", i, word)
								if(word[i] != "."):
									odd = False
							# else:
							# 	if(word[i] == "."):
							# 		even = False

							if i == 8:
								break

													

						# if (((word[1]==".") and (word[3]==".") and (word[5]==".") and (word[7]==".")) or  ((word[2]!=".") and (word[4]!=".") and (word[6]!=".") and (word[8]!="."))):
						if odd:
							if (((ord(word[0]))>0x40 ) and (ord(word[0])<0x5b ) or (ord(word[0])>0x60 ) and (ord(word[0])<0x7b )):
								# print("found2", word)
								wordSize=int(len(word)/2)
								word = changeWide(word)
								if wordSize>0:
									# print("Found2", word)
									# print(word)
									# input()
									try:
										s[t].wideStrings.append(tuple((word, offset,wordSize)))
									except:
										# print("7054", word)
										stringsTempWide.append(tuple((word, offset,wordSize)))


					inProgress=False
					word=""
					offset=0
					WideCnt=0
			x+=1
			y+=1
	except Exception as e:
		print(traceback.format_exc())
		print ("*String finding error 2!!!")
		print(e)
	dprint2("Strings Wide")
	t=1
	# for x, y, z  in s[t].wideStrings:
	# 	print (x + "\t" + str(hex(y)))
	# print ("Total: "  + str(len(s[t].wideStrings)))

def findPushAscii(binary,Num):
	global t
	global o
	newop=" 0x00\t"
	newAscii=""
	old=0
	offset=0
	try:
		x=0
		y=1
		word=""
		inProgress=False
		startPush=False
		start=True
		first=True
		old=""
		z=0
		word2=""
		progCount=0
		for v in binary:
			i = ord2(v) 
			newop += " "+show1(i)
			if ((v=="\x68") or (startPush==True)):
				startPush=True
				if (i > 31) & (i < 127):
					progCount+=1
					if inProgress==False:
						offset=x+1
					inProgress=True
				else:
					if inProgress:
						if 1 ==1:
							for xx in binary[z-progCount:z]:
								# print "*"
								yy=ord2(xx)
								zz=show1(yy)
								try: 
									zz=int(zz,16)
									zz = chr(zz)
								except:
									zz = chr(zz)
								word2 += zz#chr(zz)
							end=""
							t3=0
							validPushString=True
							for xx in binary[z-progCount-5:z-progCount]:
								# print "*"
								if t3==0:
									if xx == "h":
										validPushString=True
									else:
										validPushString=False
								if validPushString:
									yy=ord2(xx)
									zz=show1(yy)

									try: 
										zz=int(zz,16)
										zz = chr(zz)
									except:
										zz = chr(zz)
									if t3 != 0:
										end += zz#chr(zz)
								t3+=1
							end3=end.lstrip()
							end3=end3.lstrip('\x00')
							end3=end3.lstrip('\x0a')
							end3=end3.lstrip('\x0d')
							t2=1
							tem=""
							spec =[]
							for dd in word2:
								tem+=dd
								if t2==5:
									# print "\t*"+tem
									spec.append(tem[1 :  :])
									tem=""
									t2=0
								t2+=1
							word2=""
							spec.reverse()
							word = ''.join(spec)+end3
						progCount=0
					if inProgress:
						if (len(word) >= Num):
							if len(end) > 0:
								offsetVA = offset + s[t].VirtualAdd - 6
								offsetPlusImagebase=offsetVA + s[t].ImageBase
							else:
								offsetVA = offset + s[t].VirtualAdd
								offsetPlusImagebase=offsetVA + s[t].ImageBase
							wordLength=len(word)

							instructionsLength=0
							try:
								s[t].pushStrings.append(tuple((word, offset, offsetVA,offsetPlusImagebase, wordLength, instructionsLength)))  # decoded string, raw offset, raw offset + virtual address (VA may not be possible in raw binary shellcode)
							except:
								pushStringsTemp.append(tuple((word4, offset, wordLength,instructionsLength)))  
						inProgress=False
						word=""
						offset=0
						first=True
						startPush=False
			x+=1
			y+=1
			z+=1

	except Exception as e:
		print ("*String finding error3!!!")
		print(e)
	t=0

def findPushAsciiSmall(binary,Num):
	global t
	global o
	newop=" 0x00\t"
	offset=0
	word4=""
	try:
		x=0
		y=1
		word=""
		inProgress=False
		startPush=False
		z=0
		word2=""
		progCount=0
		for v in binary:
			i = ord2(v) 
			newop += " "+show1(i)
			if ((v=="\x6a") or (startPush==True)):
				startPush=True
				if (i > 31) & (i < 127):
					progCount+=1
					if inProgress==False:
						offset=x+1
					inProgress=True
				else:
					if inProgress:
						for xx in binary[z-progCount:z]:
							yy=ord2(xx)
							zz=show1(yy)
							try: 
								zz=int(zz,16)
								zz = chr(zz)
							except:
								zz = chr(zz)
							word2 += zz#chr(zz)
						end=""
						t3=0
						validPushString=True

						for xx in binary[z-progCount:z+progCount]:
							
							if t3==0:
								if xx == "j":
									validPushString=True
								else:
									validPushString=False
							if validPushString:
								yy=ord2(xx)
								zz=show1(yy)
								try: 
									zz=int(zz,16)
									zz = chr(zz)
								except:
									zz = chr(zz)
								if t3 != 0:
									end += zz#chr(zz)
							t3+=1
						end3=end.lstrip()
						end3=end3.lstrip('\x00')
						end3=end3.lstrip('\x0a')
						end3=end3.lstrip('\x0d')

						t2=1
						tem=""
						spec =[]
						old=""
						cnt=0
						# if (offset==708) or (offset==754):
						if 1==1:
							done = False
							for letter in word2:
								# print letter 
								tem+=letter
								# print tem
								# print "old " +old
								if ((t2==2) and (old =="j") and (done==False)) or ((t2==2) and (old =="h") and (done==False)):
									# print "\t*"+tem
									spec.append(tem[1 :  :])
									tem=""
									t2=0
								if t2>2:	#### this part here may be redundant, or could cause weird problems, but I like the idea of a done for thte single push byte. if push byte, word, dword, then no go.
									done=True
									tem=""
									t2=0
								t2+=1
								old = letter
						word2=""
						spec.reverse()
						word4 = ''.join(spec)
						progCount=0
						instructionsLength=0
					if inProgress:
						if (len(word4) >= Num):
							offset +=1 # correcting erroroneous calculation
							if len(end) > 0:
								offsetVA = offset + s[t].VirtualAdd - 2
								offsetPlusImagebase=offsetVA + s[t].ImageBase
							else:
								offsetVA = offset + s[t].VirtualAdd -2
								offsetPlusImagebase=offsetVA + s[t].ImageBase
							wordLength=len(word4)
							s[t].pushStrings.append(tuple((word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength)))  # decoded string, raw offset, raw offset + virtual address (VA may not be possible in raw binary shellcode)
						inProgress=False
						word4=""
						offset=0
						first=True
						startPush=False
			x+=1
			y+=1
			z+=1
	except Exception as e:
		print ("*String finding error4!!!")
		print(e)
	t=0


#push
def findPushAsciiMixed(binary,Num, index=None):
	dprint2 ("findPushAsciiMixed")
	# global t
	global o
	global pushStringsTemp
	global chMode

	t=index
	binary += b"\x90"
	newop=" 0x00\t"
	offset=0
	word4=""
	try:
		x=0
		y=1
		word=""
		inProgress=False
		startPush=False
		z=0
		word2=""
		altWord=""
		progCount=0
		old1=0x0
		old2=0x0
		old3=0x0
		offsetVA = 0
		offsetPlusImagebase=0

		for v in binary:
			
			i = ord2(v) 
			v = chr(v)
			# try:
			# 	print ("v", v, "i", hex(i), "x", hex(x), "progCount", hex(progCount))
			# except:
			# 	print ( "i", hex(i), "x", hex(x), "progCount", hex(progCount))
			newop += " "+show1(i)
			if ((v=="\x6a") or (startPush==True) or (v=="\x68")):
				startPush=True

				if ((i > 31) & (i < 127)):
					progCount+=1
					if inProgress==False:

						offset=x+1
					inProgress=True

				elif ((old1 == "h") & (v == "\x00")):
					# print "life"
					progCount+=1
				elif ((old2 == "h") & (v == "\x00")):
					# print "life"
					progCount+=1
				elif ((old3 == "h") & (v == "\x00")):
					# print "life"
					progCount+=1
				elif ((old4 == "h") & (v == "\x00")):
					# print "life"
					progCount+=1
				else:
					if inProgress:

						# print binaryToStr(binary[z-progCount:z])
						for xx in binary[z-progCount:z]:

							yy=(xx) 
							zz=show1(yy)

							try: 
								zz=int(zz,16)
								zz = chr(zz)
							except:
								zz = chr(zz)
							word2 += zz # stripWhite(zz)#chr(zz)
							try:
								dprint2 ("word", word2)
							except:
								dprint2 ("word2 error")
						end=""
						t3=0
						#alternative - off by one :-)
						# print binaryToStr(binary[z-progCount-1:z])
						for xx in binary[z-progCount-1:z]:
							yy=ord2(xx) 
							zz=show1(yy) 
							try: 
								zz=int(zz,16)
								zz = chr(zz)
							except:
								zz = chr(zz)
							altWord += zz # stripWhite(zz)#chr(zz)
						end=""
						t3=0
						validPushString=True
						t2=1
						tem=""
						spec =[]
						old=""
						cnt=0
						checkedString=False
						if len(word2) > 11:
							# print "w2: " + word2 + " offset: " + str(offset)
							# print binaryToStr(word2)
							# print binaryToStr(altWord)
							# print "end " + word2 + " " + altWord
							pass
						if len(word2)>2:
							done = False
							word4=""
							# print ("enter checkedString: " + word2)
							valid, word4temp, checkedString = checkedString1(word2)
							if valid:
								word4=word4temp
								# try:
								# 	print ("word4 1", word4)
								# except:
								# 	print ("word4 1", word4.encode("utf-8"))
						done = True
						# print "word4: " +  word4
						if (checkedString==False) and (len(word2)>2):
							# print "altword: " + altWord
							valid, word4temp,checkedString = checkedString1(altWord)
							if valid:
								word4=word4temp  #   +"@"
								# offset=offset-1
								progCount=progCount+1
							checkedString=True
						word2=""
						altWord=""
						instructionsLength=progCount
						finalWord=""
						UsesPushByte=False
						if len(word4) > 6:
							# print "w4: " + word4
							# print (z-progCount-5,z-progCount, z, progCount)
							if ((z-progCount-5) >0):
								sample = binary[z-progCount-5:z-progCount]
							else:
								sample="\x00"
							# print (binaryToStr(sample))
							if (sample[0]=="h"):
								sample=sample[1 :  :]
								sample = stripWhite(sample)
								word4+=sample+"!"
								offset=offset-5
								instructionsLength=instructionsLength+5
								# print "h "+ word4 + " "+ sample
							else:
								# print "else"
								if ((z-progCount-8) >0):
									sample = binary[z-progCount-8:z-progCount]
								else:
									sample="\x00"
								if sample[0]=="j":
									# print binaryToStr(sample)
									# print sample
									zy=1
									newWord=""
									# print "j "+ word4 + " "+ sample
									# print len(sample)
									for samp in sample:
										newWord+=samp
										if zy==2:
											UsesPushByte=True
											# print newWord
											newWord=newWord[1 : : ]
											finalWord+=newWord
											newWord=""
											zy=0
										zy+=1
									if ((sample[7] < 31) or (sample[7] > 127) and (sample[6]!="j")) or ((sample[5] < 31) or (sample[5] > 127) and (sample[4]!="j")) or ((sample[3] < 31) or (sample[3] > 127) and (sample[2]!="j")) or ((sample[1] < 31) or (sample[1] > 127) and (sample[0]!="j")):
										dprint2 ("throw out " + finalWord)
										finalWord=""
						# print "finalWord " + finalWord
						try:
							if len(finalWord) > 0:
								# print "offy " + str(offset)
								offset=offset-8
								instructionsLength=instructionsLength+8
						except Exception as e:
							print (e)
							pass
						if UsesPushByte:
							finalWord=stripWhite(finalWord)
							finalWord=finalWord[ :  :-1]
							word4+=finalWord+"*"
							UsesPushByte=False
						progCount=0
					if inProgress:
						if (len(word4) >= Num):
							offset +=1 # correcting erroroneous calculation
							if len(end) > 0:
								
								try:
									offsetVA = offset + s[t].VirtualAdd -2 #- 6
									offsetPlusImagebase=offsetVA + s[t].ImageBase
								except:
									# print (e)
									pass
							else:
								try:
									offsetVA = offset + s[t].VirtualAdd -2
									offsetPlusImagebase=offsetVA + s[t].ImageBase
								except:
									# print (e)
									pass
							wordLength=len(word4)
							try:
								# print ("other saving", word4)
								s[t].pushStrings.append(tuple((word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength)))  # decoded string, raw offset, raw offset + virtual address (VA may not be possible in raw binary shellcode)
							except:
								try:
									dprint2("saving pushMixed", word4)
								except:
									pass
								pushStringsTemp.append(tuple((word4, offset, wordLength,instructionsLength)))  # 
						inProgress=False
						word4=""
						offset=0
						first=True
						startPush=False
			x+=1
			y+=1
			z+=1
			old4=old3
			old3 = old2
			old2 = old1
			old1 =  v
	except Exception as e:
		print ("*String finding error!!!")
		print(e)
		exc_type, exc_obj, exc_tb = sys.exc_info()
		fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
		print(exc_type, fname, exc_tb.tb_lineno)
	t=0

def disHereStrings(address, NumOpsDis, secNum, mode): #
	global o
	w=0
	CODED2 = ""
	section = s[secNum]
	x = NumOpsDis
	address=address-section.VirtualAdd
	for i in range (x):
		CODED2 += chr(section.data2[address+i])
	# print binaryToStr(CODED2)
	val =""
	val2 = []
	val3 = []
	val5 =[]
	startAdd=[]
	nextAdd=[]
	bytesPerLine=[]
	cntLines=0
	bytesEachLine=[]
	asciiPerLine=[]
	
	CODED3 = CODED2.encode()
	for i in cs.disasm(CODED3, address):
		cntLines+=1
	current=0
	for i in cs.disasm(CODED3, address):
		if current>0:
			nextAd=sadd1
			nextAdd.append(nextAd)
		sadd1=hex(int(i.address ))
		startAdd.append(int(sadd1, 16))
		current+=1

	# print len(startAdd)
	# print len(nextAdd)
	# print startAdd
	# print nextAdd

	t=0
	ans=0
	total=0
	for each in startAdd:
		try:
			# print hex(startAdd[t+1])
			# print hex(each)
			ans=int(startAdd[t+1]) - int(each)
			bytesPerLine.append(ans)
			# print hex(ans)
			total+=ans
			# print "**"
		except:
			# print hex(total)
			ans2= hex(NumOpsDis-total)
			# print ans2
			# print hex(NumOpsDis)
			bytesPerLine.append(int(ans2,16))
		t+=1

	cnt=0
	t=0
	for i in cs.disasm(CODED3, address): 
		ans= binaryToStr(CODED3[cnt:cnt+bytesPerLine[t]]) #+ " " + str(t) + "\n"
		res=""
		for y in CODED3[cnt+1:cnt+bytesPerLine[t]]:
			yy=ord2(y) 
			zz=show1(yy) 
			old="nope"
			if ((yy > 31) & (yy < 127)):
				try: 
					zz=int(zz,16)
					zz = chr(zz)
				except:
					zz = chr(zz)
			else:
				zz="."
# psqrTUVW
			firstL=CODED3[cnt:cnt+bytesPerLine[t]]
			if ((old == "nope") & (zz=="P") & (firstL[0]=="f")) or ((old == "nope") & (zz=="S") & (firstL[0]=="f")) or ((old == "nope") & (zz=="Q") & (firstL[0]=="f")) or ((old == "nope") & (zz=="R") & (firstL[0]=="f")) or ((old == "nope") & (zz=="T") & (firstL[0]=="f")) or ((old == "nope") & (zz=="U") & (firstL[0]=="f"))  or ((old == "nope") & (zz=="V") & (firstL[0]=="f")) or ((old == "nope") & (zz=="W") & (firstL[0]=="f")) : 
				zz=""
			old=zz
			res += zz # stripWhite(zz)#chr(zz)
		asciiPerLine.append(res)
		# print res
		# print ans
		bytesEachLine.append(ans)
		cnt+=bytesPerLine[t]
		t+=1	

	t=0
	for i in cs.disasm(CODED3, address):
		add = hex(int(i.address))
		addb = hex(int(i.address +  section.VirtualAdd))
		add2 = str(add)
		add3 = hex (int(i.address + section.startLoc	))
		add4 = str(add3)
		if mode=="ascii":
			val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (" + addb + ") \t\t" + bytesEachLine[t] + " ; \t" + asciiPerLine[t] +"\n"# + str(cntLines)
		else:
			val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		val2.append(val)
		val3.append(add2)
		val5.append(val)
		t+=1
	returnString=""
	for y in val5:
		returnString+=y
	return returnString

	
def r32hexToAscii(r1, r2, r3, r4, reverse):
	newAscii=""
	if (r1 > 31) & (r1 < 127):
		newAscii += chr(r1)
	else:
		newAscii += "."
	if (r2 > 31) & (r2 < 127):
		newAscii += chr(r2)
	else:
		newAscii += "."	
	if (r3 > 31) & (r3 < 127):
		newAscii += chr(r3)
	else:
		newAscii += "."
	if (r4 > 31) & (r4 < 127):
		newAscii += chr(r4)
	else:
		newAscii += "."

	if not reverse:
		return newAscii
	else:
		return newAscii[::-1]

def r16hexToAscii( r3, r4, reverse):
	newAscii=""
	if (r3 > 31) & (r3 < 127):
		newAscii += chr(r3)
	else:
		newAscii += "."
	if (r4 > 31) & (r4 < 127):
		newAscii += chr(r4)
	else:
		newAscii += "."

	if not reverse:
		return newAscii
	else:
		return newAscii[::-1]


def disCheckStrings(address, NumOpsDis, secNum, mode): #
	global realEAX
	global realEAX2
	global realEBX
	global realEBX2
	global realECX
	global realECX2
	global realEDX
	global realEDX2
	global realEDI
	global realEDI2
	global realESI
	global realESI2
	global realESP
	global realESP2
	global realEBP
	global realEBP2
	global o
	w=0
	CODED2 = ""
	section = s[secNum]
	x = NumOpsDis
	address=address-section.VirtualAdd
	for i in range (x):
		CODED2 += chr(section.data2[address+i])
	# print binaryToStr(CODED2)
	val =""
	val2 = []
	val3 = []
	val5 =[]
	startAdd=[]
	nextAdd=[]
	bytesPerLine=[]
	cntLines=0
	bytesEachLine=[]
	asciiPerLine=[]
	
	CODED2 = CODED2.encode()
	for i in cs.disasm(CODED2, address):
		cntLines+=1
	current=0
	for i in cs.disasm(CODED2, address):
		if current>0:
			nextAd=sadd1
			nextAdd.append(nextAd)
		sadd1=hex(int(i.address ))
		startAdd.append(int(sadd1, 16))
		current+=1
	t=0
	ans=0
	total=0
	for each in startAdd:
		try:
			# print hex(startAdd[t+1])
			# print hex(each)
			ans=int(startAdd[t+1]) - int(each)
			bytesPerLine.append(ans)
			# print hex(ans)
			total+=ans
			# print "**"
		except:
			# print hex(total)
			ans2= hex(NumOpsDis-total)
			# print ans2
			# print hex(NumOpsDis)
			bytesPerLine.append(int(ans2,16))
		t+=1

	cnt=0
	t=0
	for i in cs.disasm(CODED2, address): 
		ans= binaryToStr(CODED2[cnt:cnt+bytesPerLine[t]]) #+ " " + str(t) + "\n"
		res=""
		for y in CODED2[cnt+1:cnt+bytesPerLine[t]]:
			yy=ord2(y) 
			zz=show1(yy) 
			old="nope"
			if ((yy > 31) & (yy < 127)):
				try: 
					zz=int(zz,16)
					zz = chr(zz)
				except:
					zz = chr(zz)
			else:
				zz="."
# psqrTUVW
			firstL=CODED2[cnt:cnt+bytesPerLine[t]]
			if ((old == "nope") & (zz=="P") & (firstL[0]=="f")) or ((old == "nope") & (zz=="S") & (firstL[0]=="f")) or ((old == "nope") & (zz=="Q") & (firstL[0]=="f")) or ((old == "nope") & (zz=="R") & (firstL[0]=="f")) or ((old == "nope") & (zz=="T") & (firstL[0]=="f")) or ((old == "nope") & (zz=="U") & (firstL[0]=="f"))  or ((old == "nope") & (zz=="V") & (firstL[0]=="f")) or ((old == "nope") & (zz=="W") & (firstL[0]=="f")) : 
				zz=""
			old=zz
			res += zz # stripWhite(zz)#chr(zz)
		asciiPerLine.append(res)
		# print res
		# print ans
		bytesEachLine.append(ans)
		cnt+=bytesPerLine[t]
		t+=1	

	t=0
	for i in cs.disasm(CODED2, address):
		add = hex(int(i.address))
		addb = hex(int(i.address +  section.VirtualAdd))
		add2 = str(add)
		add3 = hex (int(i.address + section.startLoc	))
		add4 = str(add3)
		if mode=="ascii":
			val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (" + addb + ") \t\t" + bytesEachLine[t] + " ; \t" + asciiPerLine[t] +"\n"# + str(cntLines)
		elif mode=="basic":
			val =  i.mnemonic + " " + i.op_str +"\n" #+ "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		else:
			val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		val2.append(val)
		val3.append(add2)
		val5.append(val)
		t+=1

	resultA=[]
	charAns=""
	for val in val5:
		push = re.match( r'\bpush\b', val, re.M|re.I)
		if push:
			# print ("got push")
			getVal = re.search( r'0x[0-9A-F]*', val, re.M|re.I)
			getEAX = re.search( r'\beax\b', val, re.M|re.I)
			getEBX = re.search( r'\bebx\b', val, re.M|re.I)
			getECX = re.search( r'\becx\b', val, re.M|re.I)
			getEDX = re.search( r'\bedx\b', val, re.M|re.I)
			getESI = re.search( r'\besi\b', val, re.M|re.I)
			getEDI = re.search( r'\bedi\b', val, re.M|re.I)
			getESP = re.search( r'\besp\b', val, re.M|re.I)
			getEBP = re.search( r'\bebp\b', val, re.M|re.I)
			getAX = re.search( r'\bax\b', val, re.M|re.I)
			getBX = re.search( r'\bbx\b', val, re.M|re.I)
			getCX = re.search( r'\bcx\b', val, re.M|re.I)
			getDX = re.search( r'\bdx\b', val, re.M|re.I)
			getSI = re.search( r'\bsi\b', val, re.M|re.I)
			getDI = re.search( r'\bdi\b', val, re.M|re.I)
			getSP = re.search( r'\bsp\b', val, re.M|re.I)
			getBP = re.search( r'\bbp\b', val, re.M|re.I)

			if getVal:
				result = str(getVal.group())
				result = result[2:len(result)]
				# print result
				elm=0x0
				t=0
				b=2
				for x in range(4):
					elem=result[t:b]
					# print elem
					t+=2
					b+=2
					try:
						elm1="0x"+elem
						elm=int(elm1,16)
					except:
						elm=0x17 #  Not likely to be maningful/relevant--will remove. 
					# print chr(elm)
					charAns +=chr(elm) # stripWhite(zz)#chr(
			elif getEAX:
				# print "32:"
				r1, r2, r3, r4,strReg= realEAX2
				ans = r32hexToAscii(r1,r2,r3,r4, False)

				charAns +=ans
			elif getEBX:
				# print "32:"
				r1, r2, r3, r4,strReg= realEBX2
				ans = r32hexToAscii(r1,r2,r3,r4, False)
				charAns +=ans
			elif getECX:
				# print "32:"
				r1, r2, r3, r4,strReg= realECX2
				ans = r32hexToAscii(r1,r2,r3,r4, False)
				charAns +=ans
			elif getEDX:
				# print "32:"
				r1, r2, r3, r4,strReg= realEDX2
				ans = r32hexToAscii(r1,r2,r3,r4, False)
				charAns +=ans
			elif getEDI:
				# print "32:"
				r1, r2, r3, r4,strReg= realEDI2
				ans = r32hexToAscii(r1,r2,r3,r4, False)
				charAns +=ans
			elif getESI:
				# print "32:"
				r1, r2, r3, r4,strReg= realESI2
				ans = r32hexToAscii(r1,r2,r3,r4, False)
				charAns +=ans
			elif getEBP:
				# print "32:"
				r1, r2, r3, r4,strReg= realEBP2
				ans = r32hexToAscii(r1,r2,r3,r4, False)
				charAns +=ans
			elif getESP:
				# print "32:"
				r1, r2, r3, r4,strReg= realESP2
				ans = r32hexToAscii(r1,r2,r3,r4, False)
				charAns +=ans
			elif getAX:
				# print "16:"
				r1, r2, r3, r4,strReg= realEAX2
				ans = r16hexToAscii(r3,r4, False)
				charAns +=ans
			elif getBX:
				# print "16:"
				r1, r2, r3, r4,strReg= realEBX2
				ans = r16hexToAscii(r3,r4, False)
				charAns +=ans
			elif getCX:
				# print "16:"
				r1, r2, r3, r4,strReg= realECX2
				ans = r16hexToAscii(r3,r4, False)
				charAns +=ans
			elif getDX:
				# print "16:"
				r1, r2, r3, r4,strReg= realEDX2
				ans = r16hexToAscii(r3,r4, False)
				charAns +=ans
			elif getDI:
				# print "16:"
				r1, r2, r3, r4,strReg= realEDI2
				ans = r16hexToAscii(r3,r4, False)
				charAns +=ans
			elif getSI:
				# print "16:"
				r1, r2, r3, r4,strReg= realESI2
				ans = r16hexToAscii(r3,r4, False)
				charAns +=ans
			elif getBP:
				# print "16:"
				r1, r2, r3, r4,strReg= realEBP2
				ans = r16hexToAscii(r3,r4, False)
				charAns +=ans
			elif getSP:
				# print "16:"
				r1, r2, r3, r4,strReg= realESP2
				ans = r16hexToAscii(r3,r4, False)
				charAns +=ans

			# print charAns
			
			charAns=stripSpec(charAns)	
			charAns=stripWhite(charAns)
			resultA.append(charAns)
			charAns=""
	# print charAns
	# print resultA   # displays array of results prior to transforming them to final string form
	returnString= reverseListLittleEndian(resultA)
	resultA [:] = []
	return returnString

def reverseListLittleEndian(val):
	val2=[]
	for x in val:
		x=x[::-1]
		val2.append(x)

	val2.reverse()

	res=""
	for each in val2:
		res+=each
	# print res
	return res

	# returnval=""
	# for w in val2:
	# 	returnval+=w+"\n"
	# return returnval



def hexStrtoAscii(word):
	# print ("hexStrtoAscii", word)
	word2=""
	for i in range(0, len(word), 2):
		word2+=chr(int(word[i:i+2],16))
	word2=word2[ :  :-1]
	if word2.isascii():
		# print("isAscii")
		# print (word2)
		return word2
	else:
		# print("isNotAscii", len(word2))
		return "^^^^"

def checkedString1(altWord):
	# print("checkedString1", altWord)
	# print(altWord)
	global chMode
	mode = chMode
	t2=1
	tem=""
	spec =[]
	old=""
	old2=""
	old3=""
	old4=""
	old5=""
	cnt=0
	checkedString=False
	word2=altWord
	done = False
	truncate=False
	truncateVal=0
	
	

	# print("-------> ", word2)
	for letter in word2:

		# print (letter  + " t2: " + str(t2) + " old "  + old)
		tem+=letter
		if ((t2==2) and (old =="j") and (done==False)): #or ((t2==2) and (old =="h") and (done==False)):
			tem=tem[1 :  :]
			# print tem
			spec.append(stripWhite(tem))
			tem=""
			t2=0
			checkedString=True
		elif ((t2==5) and (old4 =="h") and (done==False)):
			# print tem
			tem=tem[1 :  :]
			spec.append(stripWhite(tem))
			tem=""
			t2=0
			checkedString=True
			# print "t2=4"
		elif ((t2==1) and (letter =="P") and  (done==False)):
			# print ("push EAX")
			tem="^^^^"
			if (mode):
				tem=retR32("eax","n")

				tem = hexStrtoAscii(tem)
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==1) and (letter =="S") and  (done==False)):
			dprint2 ("push EBX2")
			tem="^^^^"
			if (mode):
				tem=retR32("ebx","n")
				tem = hexStrtoAscii(tem)
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==1) and (letter =="Q") and  (done==False)):
			# print ("push ECX")
			tem="^^^^"
			if (mode):
				tem=retR32("ecx","n")
				tem = hexStrtoAscii(tem)

			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==1) and (letter =="R") and  (done==False)):
			# print "push EDX"
			tem=""
			tem="^^^^"
			if (mode):
				tem=retR32("edx","n")
				tem = hexStrtoAscii(tem)
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==1) and (letter =="V") and  (done==False)):
			# print "push ESI"
			tem="^^^^"
			if (mode):
				tem=retR32("esi","n")
				tem = hexStrtoAscii(tem)
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==1) and (letter =="W") and  (done==False)):
			# print "push EDI"
			tem="^^^^"
			if (mode):
				tem=retR32("edi","n")
				tem = hexStrtoAscii(tem)
			spec.append((tem))
			t2=0
			tem=""
			# investigate esp
		elif ((t2==1) and (letter =="T") and  (done==False)):
			# print "push ESP"
			# tem="^^^^"
			# if (mode):
			# 	tem=retR32("esp","n")
			# 	tem = hexStrtoAscii(tem)
			# spec.append((tem))
			# t2=0
			# tem=""


			
			if checkedString:
				word4=""
				spec.reverse()
				word4 = ''.join(spec)
				Valid=False
				cnt=0
				for char in word4:
					if char.isalpha():
						cnt+=1
				if cnt <4:
					word4=""
				# print word4
				# print "end checkedString1"
				if len(word4)>2:
					Valid=True
				return Valid, word4, checkedString

		elif ((t2==1) and (letter =="U") and  (done==False)):
			# print "push EBP"
			tem="^^^^"
			if (mode):
				tem=retR32("ebp","n")
				tem = hexStrtoAscii(tem)
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==2) and (old =="f") and (letter=="P") and (done==False)):
			# print "push ax"
			tem="``"
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==2) and (old =="f") and (letter=="S") and (done==False)):
			# print "push bx"
			tem="``"
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==2) and (old =="f") and (letter=="Q") and (done==False)):
			# print "push cx"
			tem="``"
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==2) and (old =="f") and (letter=="R") and (done==False)):
			# print "push dx"
			tem="``"
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==2) and (old =="f") and (letter=="V") and (done==False)):
			# print "push si"
			tem="``"
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==2) and (old =="f") and (letter=="W") and (done==False)):
			# print "push di"
			tem="``"
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==2) and (old =="f") and (letter=="T") and (done==False)):
			# print "push sp"
			tem="``"
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==2) and (old =="f") and (letter=="U") and (done==False)):
			# print "push bp"
			tem="``"
			spec.append((tem))
			t2=0
			tem=""
		t2+=1
		old5=old4
		old4=old3
		old3=old2
		old2=old
		old = letter
	word2=""
	altWord=""
	spec.reverse()
	word4 = ''.join(spec)
	# print "moonpie: " + word4
	Valid=False
	if not checkedString:
		word4=""
	####checking to see if any leters
	cnt=0
	for char in word4:
		if char.isalpha():
			cnt+=1
	if cnt <4:
		word4=""
	# print word4
	# print "end checkedString1"
	if len(word4)>2:
		Valid=True
	return Valid, word4, checkedString


def hexDword(intVal):
    ans="0x{0:08x}".format(intVal)
    return ans

def pushStringsOutput(Num):
	mode =asciiMode

	k =0
	outText = ""
	outText += "\nNote: The offset value is created by adding the offset plus the section virtual address.\n\n"
	if filename == "":
		outfile = peName.split(".")[0]
		outfileName = peName
	else:	
		outfile = filename.split(".")[0]
		outfileName = filename


	# txtFileName =  os.getcwd() + "\\" + outfile + "\\output_" + outfileName + "_" + filetime + ".txt"


	txtFileName =  os.getcwd() + "\\" + outfile + "\\" + "pushStrings_validation" +".txt"
	os.makedirs(os.path.dirname(txtFileName), exist_ok=True)

	t=0
	
	for sec in pe.sections:
		# outText += "\n*Sec num*"+str(t)+"\n\n"

		# print("Length of pushStrings: ", len(s[t].pushStrings))
		# t+= 1
		if len(s[t].pushStrings) > 0:
			outText += "\n**Checking original stack strings found.\n\tNote: Emulation is performed by using register values provided or in regs.txt.\n\n"


			for x,rawOffset, y, offsetPlusImagebase, length, instructionsLength in s[t].pushStrings:
				# print ("\t"+str(k)+"  "+ str(x) + "\t" + str(hex(y)) + " (" + str(hex(offsetPlusImagebase)) + ")") #+"  iL: " + str(hex(instructionsLength))  +"\n"#+" length: " + str(length)
				if mode==asciiMode:
					tmp = disHereStrings(y, instructionsLength, t, mode)
					outText += tmp
					# print (tmp)


				ans = disCheckStrings(y, instructionsLength, t, "basic")
				outText += '\t'+ ans+'**\n*************************\n'
				# print ('\t'+ans+'\n*************************\n')
				k+= 1
			#LoadaryA0 (start: 0x267; end: 0x271)
			outText += "\n*Original Stack strings Found*\n\n"
			# input()
			for word, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength in s[t].pushStrings:

				outText += word+ " (start: "+ str(hex(offset)) + ";" +" " + "end:"+ str(hex(offset+instructionsLength)) + ")\n"
				# print(outText)
				# print (word, "starting offset:", hex(offset), "; ending offset:", hex(offset+instructionsLength))
		t+= 1
	print(outText)

	fp = open(txtFileName, "w")

	fp.write(outText)
	fp.close()


def getPushStrings(Num):
	mode=asciiMode
	# global t
	# t=0
	# for sec in pe.sections:
	# 	findPushAscii(s[t].data2,Num)
	# 	t+=1
	# t=0
	# for x,rawOffset, y, offsetPlusImagebase, length,instructionsLength in s[0].pushStrings:
	# 	print "\n\n\t"+str(t)+"  "+ str(x) + "\t" + str(hex(y)) + " (" + str(hex(offsetPlusImagebase)) + ")"#+" length: " + str(length)
	# 	t+=1
	# print "\n"

	# print "**SMALL************"
	# # global t
	# t=0
	# for sec in pe.sections:
	# 	findPushAsciiSmall(s[t].data2,Num)
	# 	t+=1
	# t=0
	# for x,rawOffset, y, offsetPlusImagebase, length, instructionsLength in s[0].pushStrings:
	# 	print "\n\n\t"+str(t)+"  "+ str(x) + "\t" + str(hex(y)) + " (" + str(hex(offsetPlusImagebase)) + ")"#+" length: " + str(length)
	# 	t+=1
	# print "\n"

	print ("**MIXED************")
	# global t
	t=0
	for sec in pe.sections:
		print("here")
		findPushAsciiMixed(s[t].data2,Num, t)
		t+=1
	t=0
	for x,rawOffset, y, offsetPlusImagebase, length, instructionsLength in s[0].pushStrings:
		print ("\t"+str(t)+"  "+ str(x) + "\t" + str(hex(y)) + " (" + str(hex(offsetPlusImagebase)) + ")") #+"  iL: " + str(hex(instructionsLength))  +"\n"#+" length: " + str(length)
		if mode==asciiMode:
			print (disHereStrings(y, instructionsLength, 0, mode))
		t+=1

		# print disCheckStrings(y, instructionsLength, 0, "basic")

	print ("\n")

	for x,rawOffset, y, offsetPlusImagebase, length, instructionsLength in s[0].pushStrings:
		print ("\t"+str(t)+"  "+ str(x) + "\t" + str(hex(y)) + " (" + str(hex(offsetPlusImagebase)) + ")") #+"  iL: " + str(hex(instructionsLength))  +"\n"#+" length: " + str(length)
		if mode==asciiMode:
			print (disHereStrings(y, instructionsLength, 0, mode))
		t+=1


		ans = disCheckStrings(y, instructionsLength, 0, "basic")

		print ("checkstrings", ans+'\n*************************\n')

	for word, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength in s[0].pushStrings:
		print ("word", word, "starting offset:", hex(offset), "; ending offset:", hex(offset+instructionsLength))
	print ("\n")
def getStringsOnSections(x):
	global t
	t=0
	for sec in pe.sections:
		# print "section: " +  s[t].sectionName
		findStrings(s[t].data2,x)#,t)
		findStringsWide(s[t].data2,x)
		findPushAscii(s[t].data2,x)
		t+=1
	t=0

	t=0
	print("Strings found:")
	for x in s:
		print (s[t].sectionName.decode())
		print ("\tASCII: "+str(len(s[t].Strings)))
		print ("\tWide char strings: "+str(len(s[t].wideStrings)))
		print ("\tPush stack strings: "+str(len(s[t].pushStrings)))
		t+=1
	t=0

def printStrings():
	global rawHex
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp

	t=0
	#print(s[t].Strings)
	#print(pushStringsTemp)
	try:
		if not rawHex:
			for sec in pe.sections:
				if len(s[t].Strings) > 0 or len(s[t].wideStrings) > 0:
					print (s[t].sectionName.decode('utf-8'))
				
				for x,y,z  in s[t].Strings:
					x = cya + x + res
					print ('{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<8}'.format("",str(x), s[t].sectionName.decode('utf-8'), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"(offset "+str(hex(y))+")", yel + "Ascii"+ res))

					# print ('{:<5} {:<32s} {:<20s} {:<11s} {:<4}'.format("",str(x), "Offset: " + str(hex(y)),"Address: " + str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"Size: "+ str(z)))
					
					#print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z))) 
				dprint2 ("wideStrings res")
				#(word, offset,wordSize
				for x,y,z in s[t].wideStrings:
					x = cya + x + res
					print ('{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<8}'.format("",str(x), s[t].sectionName.decode('utf-8'), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"("+str(hex(y))+")" , red + "Unicode")+res)

					# print ('{:<5} {:<32s} {:<20s} {:<11s} {:<4}'.format("",str(x), "Offset: " + str(hex(y)),"Address: " + str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"Size: "+ str(z)))
					#print ("\t"+ str(word) + "\t" + hex(offset) + "\t" + str(wordSize))
				# for x,y, z in s[1].wideStrings:
				# 	print ("\t"+ str(x) + "\t" + str(hex(y)))
				
				for word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength in s[t].pushStrings:
					word4 = cya + word4 + res
					# print ('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(word4), "Offset: " + str(hex(offset)),"Size: "+ str(wordLength)))
					print ('{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<12}'.format("",str(word4), s[t].sectionName.decode('utf-8'), str(hex(offset + s[t].ImageBase + s[t].VirtualAdd)),"(offset "+str(hex(offset))+")" , gre + "Stack String" + res))

					#print ("\t"+ str(word4) + "\t" + hex(offset) + "\t" + str(wordLength))
				print ("\n")
				t+=1
		else:
			print("\n")
			for x,y,z  in stringsTemp:
				x = cya + x + res
				# print('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(x), "Offset: " + str(hex(y)),"Size: "+ str(z)))
				print ('{:<5} {:<42s} {:<16s} {:<12}'.format("",str(x), "(offset "+str(hex(y))+")" , yel+"Ascii"+res))

				#print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
			for x,y,z  in stringsTempWide:
				x = cya + x + res
				print ('{:<5} {:<42s} {:<16s} {:<12}'.format("",str(x), "(offset "+str(hex(y))+")" , red+"Unicode"+res))

				# print('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(x), "Offset: " + str(hex(y)),"Size: "+ str(z)))
				#print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
			#word4, offset, wordLength,instructionsLength
			for word4,offset,wordLength, instLen  in pushStringsTemp:
				word4 = cya + word4 + res
				print ('{:<5} {:<42s} {:<16s} {:<12}'.format("",str(word4), "(offset "+str(hex(offset))+")" , gre+"Stack String"+res))

				# print('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(word4), "Offset: " + str(hex(offset)),"Size: "+ str(wordLength)))
				#print ("\t"+ str(word4) + "\t" + hex(offset) + "\t" + str(hex(wordLength)))

	except Exception as e:
		print(e)
		print(traceback.format_exc())
		
	


	t=0

def runIt():
	global PE_DLLS
	global peName
	global modName
	global o
	global index
	o = 0
	CheckallModules=True
	if CheckallModules:
			print ("Checking all modules...")
			zy = 0
			index = 0
			for dll in PE_DLLS:
				o = zy + 1
				extractDLL_MinNew(PE_DLLS[zy])
				zy+=1
				print ("PE: " + str(peName))
			modName = peName
			o = 0



def AustinTesting():

	# start = timeit.default_timer()
	# print("AUSTINHERE")
	# print(rawHex)

	# findAllFSTENV_old()
	# printSavedFSTENV()


	if(rawHex):
		findAllCallpop(rawData2, 'noSec')

	printSavedCallPop()

	if(bit32):
		for secNum in range(len(s)):
			# print("Trying section: " + str(secNum))
			data2 = s[secNum].data2
			# print("before mov"
			for match in FSTENV_GET_BASE.values(): #iterate through all opcodes representing combinations of registers
				get_FSTENV(10, 15, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence

		printSavedFSTENV()


		# print(s)
		for secNum in range(len(s)):
				# print("Trying section: " + str(secNum))
				data2 = s[secNum].data2
				# findAllPebSequences(data2, secNum)
				for match in EGGHUNT.values(): #iterate through all opcodes representing combinations of registers
					getSyscallPE(20, 20, match, secNum, data2)

		for secNum in range(len(s)):
				# print("Trying section: " + str(secNum))
				data2 = s[secNum].data2
				# findAllPebSequences(data2, secNum)
				for match in HEAVEN.values(): #iterate through all opcodes representing combinations of registers
					get_HeavenPE(4, 20, match, secNum, data2)

	# if(rawHex):
	# 	for match in EGGHUNT.values(): #iterate through all opcodes representing combinations of registers
	# 		getSyscallPE(20, 20, match, 'noSec', rawData2) 

	if(rawHex):
		getSyscallRawHex(0, 8, 'noSec', rawData2)
		getHeavenRawHex(0, 8, 'noSec', rawData2)

	printSavedEgg()
	printSavedHeaven()

	# stuff = identifySyscall(int(0x26))
	# printSyscallResult(stuff)
	getSyscallRecent(0x61)
	# printSavedPEB()

	# mode=""
	# findAllFSTENV()
	# printSavedFSTENV()
	# findAllPebSequences(mode)
	# printSavedPEB()
	# stop = timeit.default_timer()
	# print("PEB TIME PY3 = " + str(stop - start))
	# findAllPushRet()

	#print("Total 1 = " + str(total1))
	#print("Total 2 = " + str(total2))
	# printSavedPEB()
	#printSavedPEB_64()
	# printSavedPushRet()


def AustinTesting4():
	decryptUI()

def AustinTestingStub():
	global filename
	#stub end = 21
	analyzeDecoderStubs(filename)

def AustinTesting3():
	global pebPoints
	global peName
	global rawData2
	global filename
	print("HERE PENAME")
	print(peName)
	# start = timeit.default_timer()
	# print("AUSTINHERE")
	# print(rawHex)

	# findAllFSTENV_old()
	# printSavedFSTENV()

	init2(filename)

	# doPeb = False
	# doCallpop = False
	# doPushret = False
	# doFstenv = False
	# doSyscall = False
	# doHeaven = False

	doPeb = True
	doCallpop = True
	doPushret = True
	doFstenv = True
	doSyscall = True
	doHeaven = True



	if(rawHex):
		data2 = rawData2

		if(doPeb):
			findAllPebSequences_old(data2, "noSec")
		if(doCallpop):
			findAllCallpop(data2, "noSec")
		if(doPushret):
			findAllPushRet(data2, "noSec")
		if(doFstenv):
			findAllFSTENV(data2, "noSec")
		if(doSyscall):
			getSyscallRawHex(0, 8, 'noSec', rawData2)
		if(doHeaven):
			getHeavenRawHex(0, 8, 'noSec', rawData2)
	


	else:
		for secNum in range(len(s)):
			data2 = s[secNum].data2
			if(doPeb):
				findAllPebSequences_old(data2, secNum)
			if(doCallpop):
				findAllCallpop(data2, secNum)
			if(doPushret):
				findAllPushRet(data2, secNum)
			if(doFstenv):
				findAllFSTENV(data2, secNum)
			if(doSyscall):
				findAllSyscall(data2, secNum)
			if(doHeaven):
				findAllHeaven(data2, secNum)

	print("######################## PEB ########################")
	printSavedPEB()
	print("######################## CALLPOP ########################")
	printSavedCallPop()
	print("######################## PUSHRET ########################")
	printSavedPushRet()
	print("######################## FSTENV ########################")
	printSavedFSTENV()
	print("######################## EGG ########################")
	printSavedEgg()
	print("######################## HEAVEN ########################")
	printSavedHeaven()



def AustinTesting2():

	start = timeit.default_timer()
	print("before austinEncode")


	if rawBin == False:
		# filename=shellArg

		rawBytes=readShellcode("daltonShell2.txt") 

		rawData2=rawBytes
		# print("read dalton, data here: ", rawData2)
		# printBytes(rawBytes)
		# print (disHereShell(rawBytes, False, False, "ascii", True))


	


	# print ("SizeRawdata2", len(rawData2))
	rawBytes=rawData2
	# print("NORMAL BYTES")
	# print(binaryToStr(rawBytes))
	# print ("rawbytes class", type(rawBytes))
	# print("RAWDATA2 BEFORE ENCODE IN TEST FUNC: ", rawData2)
	encoded=encodeShellcode(rawData2)
	# print("encoded dalton, data here: ", encoded)




	# austinEncodeDecodeWork("daltonShell2.txt", ["^", "^", "-", "+", "^"])
	# austinEncodeDecodeWork("daltonShell2.txt", ["^", "^", "-", "+"])
	# austinEncodeDecodeWork("daltonShell2.txt", ["^", "^", "-"])

	decryptShellcode(encoded, ["^", "^", "-"], distributed = False, findAll = False, cpuCount = 32, fastMode = False, outputFile = True )
	stop = timeit.default_timer()
	print("Total time AUSTIN: " + str(stop - start))
	# rawBytes=readShellcode(shellArg) 

	# rawData2=rawBytes
	# # # printBytes(rawBytes)
	# print (disHereShell(rawBytes, False, False, "ascii", True))
	# print ("SizeRawdata2", len(rawData2))
	# rawBytes=rawData2
	# print ("rawbytes class", type(rawBytes))

	# disassembly=takeBytes(data2,(len(data2)-10))
	# directory, filename= (splitDirectory(filename))
	# directory=""

	# if not os.path.exists(directory+'outputs'):
	# 	os.makedirs(directory+'outputs')
	# print (directory+"outputs\\"+filename[:-4]+".bin")
	# # newBin = open(directory+"outputs\\"+filename[:-4]+".bin", "wb")
	# # newBin.write(rawBytes)
	# # newBin.close()
	# newDis = open(directory+"outputs\\"+filename[:-4]+"-disassembly.txt", "w")
	# newDis.write(disassembly)
	# newDis.close()


def AustinStart():

	# ObtainAndExtractDlls()
	# runIt()
	# showBasicInfo()
	# start = timeit.default_timer()
	if(not rawHex):
		ObtainAndExtractSections()
		print (showBasicInfoSections())
	# stop = timeit.default_timer()
	# print("START TIME = " + str(stop - start))


def goodString(data,word, size):
	global stringsDeeper
	global stringReadability
	try:
		readable = stringReadability
	except:
		readable = .65
	dprint2("goodstring ", word, size)
	numbers = sum(c.isdigit() for c in word)
	letters = sum(c.isalpha() for c in word)
	spaces  = sum(c.isspace() for c in word)
	others  = len(word) - numbers - letters - spaces
	dprint2 (numbers,letters,spaces,others)
	
	wordSize=len(word)
	if wordSize==0:
		wordSize=0.0001
	# print (wordSize, "size")
	# print ((letters+numbers+spaces)/wordSize, "num")

	# print ("size", len(data), len(word))
	# if len(data) == len(word):
	if len(word) >= 0.95*len(data):
		# print ("badsize")
		return False
	dprint2 (letters, (letters+numbers+spaces)/wordSize, len(word), size)
	if (letters >= 2) and ((letters+numbers+spaces)/wordSize > readable) and (len(word) >=size):
		dprint2 ("yes, goodString")
		return True

	if word.lower() in GoodStrings:
		return True
 

	for each in GoodStrings:	### maybe too computationally expensive if long list??
		if each.lower() in word.lower():
			return True

	return False


def goodStringWide(data,word, size):
	global stringsDeeper
	dprint2("goodStringWide ", word, size)
	numbers = sum(c.isdigit() for c in word)
	letters = sum(c.isalpha() for c in word)
	spaces  = sum(c.isspace() for c in word)
	others  = len(word) - numbers - letters - spaces
	dprint2 (numbers,letters,spaces,others)
	size=size*2
	
	wordSize=len(word)*2
	if wordSize==0:
		wordSize=0.0001
	# print (wordSize, "size")
	# print ((letters+numbers+spaces)/wordSize, "num")

	# print ("size", len(data), len(word))
	# if len(data) == len(word):
	if len(word) >= 0.95*len(data):
		return False
	dprint2 (letters, len(word), size)
	if (letters >= 5)  and (len(word) >=size):
		dprint2 ("yes, goodStringWide")
		return True

	if word.lower() in GoodStrings:
		return True
 

	for each in GoodStrings:	### maybe too computationally expensive if long list??
		if each.lower() in word.lower():
			return True

	return False


def removeLastLine(strLine):  #removes last line of disasembly that starts with \n0x
	array = strLine.split("\n0x")
	new = ""
	array.pop()
	for word in array:
		new +=  word+"\n"
	return new

def findStrings22(binary,Num):#,t):
	dprint2("findstrings Testing ", Num)
	global t
	global o
	global stringsTemp
	newop=" 0x00\t"
	newAscii=""
	# newUnicode=""
	old=0
	offset=0
	word=""
	wordSize=0
	try:
		x=0
		y=1
		inProgress=False
		for v in binary:
			i = ord2(v) 
			newop += " "+show1(i)
			if (i > 31) & (i < 127):
				if inProgress==False:
					offset=x
				inProgress=True
				word += ""+chr(i)
			else:
				if inProgress:
					if (len(word) >= Num):
						# print "t: " + str(t)
						wordSize=len(word)
						try:
							s[t].Strings.append(tuple((word, offset, wordSize)))
						except:
							stringsTemp.append(tuple((word, offset, wordSize)))
					inProgress=False
					word=""
					offset=0
			x+=1
			y+=1
			if x == len(binary):   #last byte, final end
 				# dprint ("reached")
 				wordSize=len(word)
 				# dprint2 (word, hex(offset), wordSize)
 				try:
 					s[t].Strings.append(tuple((word, offset, wordSize)))
 				except: 
 					stringsTemp.append(tuple((word, offset, wordSize)))
	except Exception as e:
		print ("*String finding error1!!!")
		print (e)

#########################################


cs = Cs(CS_ARCH_X86, CS_MODE_32)
stringLiteral="\x31\xC9\xB9\xAD\xDE\x65\x64\xC1\xE9\x10\x51\x68\x77\x6F\x72\x6B\x68\x6F\x69\x74\x20\x68\x45\x78\x70\x6C\x89\xE2\xB9\xCA\xAD\xDE\x29\xC1\xE9\x18\x51\x68\x6E\x73\x20\x3A\x68\x75\x74\x74\x6F\x68\x73\x65\x20\x62\x68\x20\x6D\x6F\x75\x68\x70\x69\x6E\x67\x68\x53\x77\x61\x70\x89\xE3\x31\xC9\x51\x52\x53\x51\xFF\xD0"
# stringLiteral=test2
ArrayLiteral="0x31, 0xC9, 0xB9, 0xAD, 0xDE, 0x65, 0x64, 0xC1, 0xE9, 0x10, 0x51, 0x68, 0x77, 0x6F, 0x72, 0x6B, 0x68, 0x6F, 0x69, 0x74, 0x20, 0x68, 0x45, 0x78, 0x70, 0x6C, 0x89, 0xE2, 0xB9, 0xCA, 0xAD, 0xDE, 0x29, 0xC1, 0xE9, 0x18, 0x51, 0x68, 0x6E, 0x73, 0x20, 0x3A, 0x68, 0x75, 0x74, 0x74, 0x6F, 0x68, 0x73, 0x65, 0x20, 0x62, 0x68, 0x20, 0x6D, 0x6F, 0x75, 0x68, 0x70, 0x69, 0x6E, 0x67, 0x68, 0x53, 0x77, 0x61, 0x70, 0x89, 0xE3, 0x31, 0xC9, 0x51, 0x52, 0x53, 0x51, 0xFF, 0xD0"
rawHex2 ="31C9B9ADDE6564C1E9105168776F726B686F697420684578706C89E2B9CAADDE29C1E91851686E73203A687574746F687365206268206D6F756870696E67685377617089E331C951525351FFD0"
shellcode='shellcode.txt'
shellcode2='shellcode2.txt'
shellcode3='shellcode3.txt'
shellcode4='shellcode4.txt'
shellcode5='shellcode5.txt'
shellcode6='shellcode6.txt'
shellcode7='shellcode7.txt'
shellcode8="shellcode8.txt"
labels=[]
labelOffsets=[]
offsets=[]
possibleBadLabelOffsets=[]
def show1(int):
		show = "{0:02x}".format(int) #
		return show
def binaryToStr(binary):
	newop=""
	try:
		for v in binary:
			i = ord2(v) 
			newop += "\\x"+show1(i)
			# newAscii += "\\x"+chr(i)
		# print newop
		# print newAscii
		return newop
	except Exception as e:
		print ("*Not valid format")
		print(e)
def ord2(x):
	return x

def splitArrLit(word):
	array = word.split(" 0x")
	res=""
	for each in array:
		res+=each
	return res

def splitBackslashx(word):
	array = word.split("\\x")
	res=""
	for each in array:
		res+=each
	return res
def split0x(word):
	array = word.split("0x")
	res=""
	for each in array:
		res+=each
	return res


def splitNewline(word):
	array = word.split("\n")
	array2=[]
	for word in array:
		word2=splitRemoveAssemblyComments(word)
		array2.append(word2)
	res=""
	for each in array2:
		res+=each
	return res
def splitRemoveAssemblyComments(word):
	array = word.split(";")[0]
	res=""
	for each in array:
		res+=each
	return res
def readShellcodeOLD(shellcode):
	dprint2("Shellcode : ", shellcode)
	file1 = open(shellcode, 'r') 
	shells = file1.read() 
	# shells = shells.replace('"', '')
	# #print(repr(shells))
	# if "0x" in shells:
	# 	shells = shells.replace("0x", "").replace(" ", "")
	# else:
	# 	shells = shells.replace(" ", "").replace('\n', '').replace('\\x', '')
	# print("Tarek: ", repr(shells))
	# shells = fromhexToBytes(shells)
	# return shells
	# print("\nshells\n")
	shells = re.sub(rf"[{string.punctuation}]", "", shells)
	dprint2(shells)
	shells=splitBackslashx(shells)
	shells=splitArrLit(shells)
	shells=split0x(shells)
	# print("\nshells2\n")
	dprint2(shells)
	shells=fromhexToBytes(shells)
	#printBytes(shells)
	#print(type(shells))
	print(shells)
	dprint2 ("\n\n\nend\n")
	return shells

def readShellcode(shellcode):  #  ADDED: get rid of newline (0d0a) - get rid of assembly comments   ---   ; comments -- added SplitNewline and the .join
	dprint2 ("readShellcodeTest")
	# print("Shellcode ----> ", shellcode)
	dprint2 ("Shellcode : ", shellcode)
	file1 = open(shellcode, 'r') 
	shells = file1.read()
	# print(shells)
	# input() 
	# print("\nshells\n")
	# shells=splitRemoveAssemblyComments(shells)
	shells=splitNewline(shells)
	shells = re.sub(rf"[{string.punctuation}]", "", shells)
	dprint2(shells)
	shells=splitBackslashx(shells)
	shells=splitArrLit(shells)
	shells=split0x(shells)

	shells = ''.join(shells.split())
	shells=shells.upper()
	# print("\nshells2\n")

	#print(shells)
	shells=fromhexToBytes(shells)
	# printBytes(shells)
	dprint2 ("\n\n\nend\n")
	return shells

def reduceShellToStrHex(shellcode):
	shells=splitBackslashx(shellcode)
	shells=splitArrLit(shells)
	shells=split0x(shells)
	# print("\nshells2\n")
	dprint2(shells)
	shells=fromhexToBytes(shells)
	return shells
def printBytes(mybtes):
	print (type(mybtes))
	for val in mybtes:
		print(hex(val),' ', end='')
	print("\n")
def printFromhexToBytes(hexadecimal_string):
	print ("fromhexToBytes\n")
	byte_array = bytearray.fromhex(hexadecimal_string)
	bytesStr = bytes(byte_array)
	printBytes(bytesStr)
	
def printFromStringLiteralToBytes(stringLiteral):
	print("printfromStringLiteralToBytes")
	b=bytes(stringLiteral.encode('raw_unicode_escape'))
	printBytes(b)

def printFromArrayLiteralToHex(lit):
	print ("fromArrayLiteralToHex\n")
	clean_string = re.sub(rf"[{string.punctuation}]", "", lit)
	retArrayLit=splitArrLit(clean_string)
	retArrayLit=retArrayLit[2:]
	printFromhexToBytes(retArrayLit)

def fromhexToBytes(hexadecimal_string):
	# print ("fromhexToBytes\n\n\n")
	byte_array = bytearray.fromhex(hexadecimal_string)
	bytesStr = bytes(byte_array)
	return bytesStr
	
def fromStringLiteralToBytes(stringLiteral):
	# print("fromStringLiteralToBytes")
	b=bytes(stringLiteral.encode('raw_unicode_escape'))
	dprint2 (type(b))
	# for val in b:
	# 	print(hex(val),' ', end='')
	return b
def fromArrayLiteralToHex(lit):
	# print ("fromArrayLiteralToHex\n")
	clean_string = re.sub(rf"[{string.punctuation}]", "", lit)
	retArrayLit=splitArrLit(clean_string)
	retArrayLit=retArrayLit[2:]
	returnVal=fromhexToBytes(retArrayLit)
	return returnVal

def checkForLabel(addb, labels):
	# dprint ("checkForLabel " + addb)
	for label in labels:
		if label==addb:
			val="	 label_"+addb+":\n"
			# dprint (val)
			return True, val
	return False,0



def signedNegHexTo(signedVal):
	strSigned=str(hex(signedVal))
	ba = binascii.a2b_hex(strSigned[2:])
	new = (int.from_bytes(ba, byteorder='big', signed=True))
	return new

def checkForValidAddress(val_a,val_b1, val_b2, sizeShell):
	val_b=val_b1+ " " +  val_b2 
	# print ("comparing: " + val_b2 + " > " + str(hex(sizeShell)) )
	try:
		controlFlow= re.match( r'\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bja\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', val_b1, re.M|re.I)

		if controlFlow:
			if int(val_b2,16) > int(sizeShell):
				# print("it is bigger")
				return val_b+ " (??)"	## ?? because goes to offset that doesn't exit! Probably db or something else
	except:
		pass
	return val_b

def checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, possibleBadLabelOffsets,data, num_bytes):
	# val_b=checkForValidAddress(val_a,val_b1, val_b2, sizeShell, possibleBadLabelOffsets)
	val_b=val_b1+ " " +  val_b2 
	try:
		if str(val_b2) in possibleBadLabelOffsets:
			dprint2 ("oh noes "  + val_b2)
			dprint2(val_a, val_b1, val_b2)
			# res=specialDisDB(data, int(val_a,16))
			# val_b=res
			addy=int(val_a,16)
			modifyShByRange(data, addy,addy+num_bytes,"d")
			# val_b =  val_b+ " (??)"
			
			dprint2 ("check2: valb: "  + val_b + " " + str(num_bytes) )
			
			num_bytes=num_bytes-1
			
			
			return val_b, num_bytes
	except:
		pass
	return val_b,0



def testcb(buffer, size, offset, userdata):
	# always skip 2 bytes of data
	return 8

def specialDisDB2(data):
	dprint2("special2")
	out=binaryToStr(data[:1])
	out=out[1:]
	val="db 0"
	return val+out+" (?)"
def specialDisDB(data,addy):  #//takes bytes
	cs.skipdata = True
	cs.skipdata_setup = ("db", None, None)
	dprint2 (binaryToStr(data[addy:addy+1]))
	address=0
	val_b=""
	for i in cs.disasm(data[addy:addy+1], address):
		val_b=i.mnemonic + " " + i.op_str 
		dprint2 ("hi2")
		try:
			dprint2 (val_b)
			return val_b
		except:
			pass
	return val_b

def makeDBforUnknownBytes(num_bytes, val_c,addb):
	# dprint ("makeDBforUnknownBytes(num_bytes, val_c)")
	dprint2 (num_bytes)
	dprint2 (val_c)
	bVal_c = reduceShellToStrHex(val_c)
	# dprint("ans:")
	reducedVal_c=(binaryToStr(bVal_c))
	dprint2 (reducedVal_c)
	# dprint(type(bVal_c))
	new=specialDisDB2(bVal_c)
	newVal_c=val_c[:4]
	dprint2 ("new")
	dprint2 (newVal_c)
	res=makeAsciiforDB(newVal_c)
	num_bytes=int(len(val_c)/4)
	address=0x0
	val =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(addb, new, newVal_c, res))
	dprint2 (val)
	dprint2 (num_bytes)
	dprint2 ("bval")
	dprint2 (type(bVal_c))
	reducedVal_c=reducedVal_c[4:]
	num_bytes=int(len(reducedVal_c)/4)

	return val, num_bytes, reducedVal_c

def disHereMakeDB(data,offset, end, mode, CheckingForDB):
	global labels

	dprint2 ("dishereMakeDB "  + str(offset) + " end: " + str(end))

	try:
		address=offset
	except:
		address=0
	cs.skipdata = True
	cs.skipdata_setup = ("db", None, None)
	if offset==False:
		offset=0
	if end==False:
		end=len(data)-1
	CODED2=data[offset:end]
	# print binaryToStr(CODED2)
	val =""
	val2 = []
	val3 = []
	val5 =[]
	startAdd=[]
	nextAdd=[]
	bytesPerLine=[]
	cntLines=0
	bytesEachLine=[]
	asciiPerLine=[]
	CODED3 = CODED2

	for i in cs.disasm(CODED3, address):
		cntLines+=1
		val=i.mnemonic + " " + i.op_str 
	current=0
	for i in cs.disasm(CODED3, address):
		if current>0:
			nextAd=sadd1
			nextAdd.append(nextAd)
		sadd1=int(i.address )
		startAdd.append(int(sadd1))
		current+=1
	t=0
	ans=0
	total=0
	for each in startAdd:
		try:
			ans=int(startAdd[t+1]) - int(each)
			bytesPerLine.append(ans)
			total+=ans
		except:
			ans2= hex(len(data)-total)
			bytesPerLine.append(int(ans2,16))
		t+=1
	cnt=0
	t=0

	for i in cs.disasm(CODED3, address): 
		ans= binaryToStr(CODED3[cnt:cnt+bytesPerLine[t]]) #+ " " + str(t) + "\n"
		res=""
		for y in CODED3[cnt:cnt+bytesPerLine[t]]:
			yy=ord2(y) 
			zz=show1(yy) 
			old="nope"
			if ((yy > 31) & (yy < 127)):
				try: 
					zz=int(zz,16)
					zz = chr(zz)
				except:
					zz = chr(zz)
			else:
				zz="."
			old=zz
			res += zz # stripWhite(zz)#chr(zz)
		asciiPerLine.append(res)
		bytesEachLine.append(ans)
		cnt+=bytesPerLine[t]
		t+=1	
	t=0
	add = hex(int(i.address))
	sizeShell=len(CODED2)
	for i in cs.disasm(CODED2, address):
		CantSkip=True
		add = hex(int(i.address))
		addb = hex(int(i.address))
		add2 = str(add)
		# add3 = hex (int(i.address + section.startLoc	))
		add3=0
		add4 = str(add3)
		val_a=addb#"\t"#\t"
		val_b=i.mnemonic + " " + i.op_str 
		val_b1=i.mnemonic
		val_b2=i.op_str
		num_bytes=0
		try:
			val_c= bytesEachLine[t] 
			val_d=asciiPerLine[t] 
		except:
			val_c=""
			val_d=""
		try:
			num_bytes=int(len(val_c)/4)
		except:
			num_bytes=1
		val_b, num_bytes =checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, possibleBadLabelOffsets,data,num_bytes)
		if mode=="ascii":
			val =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(val_a, val_b, val_c, val_d))
		else:
			val = addb + ":\t" + i.mnemonic + " " + i.op_str+"\n"
			val=('{:<10s} {:<35s}\n'.format(val_a, val_b))
		truth,res=checkForLabel(addb,labels)
		if truth:
			val=res+val
		valCheck=i.mnemonic + " " + i.op_str 
		val, num_bytes,val_c =makeDBforUnknownBytes(num_bytes, val_c, addb)
		dprint2 ("truth check " + addb)
		truth,res=checkForLabel(addb,labels)
		if truth:
			val=res+val
		valCheck=i.mnemonic + " " + i.op_str 
		addb=str(hex(int(addb,16)+1))
		dprint2("final val_c")
		dprint2(type(val_c))
		val2.append(val)
		val3.append(add2)
		val5.append(val+"(!)")
		t+=1
	returnString=""
	dprint2 ("dishereMakeDB2 "  + str(offset) + " end: " + str(end))
	for y in val5:
		returnString+=y
	return returnString

def makeAsciiforDB(data):
	res=""
	zz=""
	# dprint(type(data))
	CODED3=reduceShellToStrHex(data)
	# dprint(type(CODED3))
	for y in CODED3:
		yy=ord2(y) 
		zz=show1(yy) 
		if ((yy > 31) & (yy < 127)):
			try: 
				zz=int(zz,16)
				zz = chr(zz)
			except:
				zz = chr(zz)
		else:
			zz="."
	res += zz # stripWhite(zz)#chr(zz)
	# dprint (res)
	return res

def makeAsciiforDB2(data):
	res=""
	print ("makeAsciiforDB2")
	dprint2(type(data))
	CODED3=reduceShellToStrHex(data)

	dprint2(type(CODED3))
	for y in CODED3:
		yy=ord2(y) 
		zz=show1(yy) 
		if ((yy > 31) & (yy < 127)):
			try: 
				zz=int(zz,16)
				zz = chr(zz)
			except:
				zz = chr(zz)
		else:
			zz="."
	res += zz # stripWhite(zz)#chr(zz)
	dprint2 (res)
	return res



def addDis(address, line, mnemonic=None, op_str=None):
	global tempDisassembly
	global tempAddresses
	global tempMnemonic
	global tempOp_str

	tempDisassembly.append(line[:-2])

	try:
		tempAddresses.append(str(hex(address)))
	except:
		tempAddresses.append(address)

	tempMnemonic.append(mnemonic)
	tempOp_str.append(op_str)

def printTempDis():
	global labelOffsets
	global labels
	global tempDisassembly
	global tempAddresses
	t=0
	out=""
	for each in tempDisassembly:
		truth,res=checkForLabel((tempAddresses[t]),labels)
		if truth:
			each="\t"+res+each
		controlFlow= re.search( r'\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bja\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bret\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', each, re.M|re.I)
		if controlFlow:
			print ("cfi")
			each=each+"\n"
		out+=each+"\n"

		t+=1
	print (out)

def createDisassemblyLists():
	global labelOffsets
	global labels
	global tempDisassembly
	global tempAddresses
	listDisassembly=[]
	listOffset=[]
	t=0
	out=""
	each4 =""
	each5 = ""
	each6 = ""
	each7 =""
	for each in tempDisassembly:
		array = each.split()
		offset=array[0]
		remove=0
		if (offset[0] == "*") or (offset[0] == "A") or (offset[0] == "B") or (offset[0] == "C") or (offset[0] == "D") or (offset[0] == "E") or (offset[0] == "F") or (offset[0] == "G"):
			remove +=1
		if (offset[1] == "."):
			remove +=1
		offset = offset[remove:]
		try:
			offset=int(offset,16)
		except:
			offset = offset[1:]
			try:
				offset=int(offset,16)
			except:
				offset = offset[1:]
				offset=int(offset,16)

		each1, each2, each3 = array[1], array[2], array[3]
		# each2 = array[2]
		# each3 = array[3]
		try:
			each4 = array[4]
		except:
			pass
		try:
			each5 = array[5]
		except:
			pass
		try:
			each6 = array[6]
		except:
			pass
		try:
			each7 = array[7]
		except:
			pass
		eachAll = each1 + " " +  each2 + " " + each3 + " " + each4+ " " +  each5 + " " + each6 + " " + each7
		final  = eachAll.split("\\")
		listDisassembly.append(final[0])
		listOffset.append(offset)
		# out += final[0] +"\n"
	# print (out)
	t=0
	# for e in listDisassembly:
	# 	print (str(hex(listOffset[t])) + " " + e + "\n")
	# 	t+=1
	return listOffset, listDisassembly

def clearTempDis():
	global tempDisassembly
	global tempAddresses
	global tempMnemonic
	global tempOp_str
	tempDisassembly.clear()
	tempAddresses.clear()
	tempMnemonic.clear()
	tempOp_str.clear()



def checkForBad00(data, offset, end):
	dprint2("checkForBad00")
	global tempAddresses
	global tempDisassembly
	dprint2 (len(tempAddresses), len(tempDisassembly))
	sample="add byte ptr \[eax], al"
	ans=[]
	for x in range(4):
		if str(hex(offset)) in tempAddresses:
			# print("FOUND candidate", str(hex(offset)))
			index=tempAddresses.index(str(hex(offset)))


			dprint2 (index, tempDisassembly[index], tempAddresses[index])
			findBad00= re.search(sample, tempDisassembly[index], re.M|re.I)
			if findBad00:

				dprint2 ("    ", tempAddresses[index], "gots it")

				ans.append(int(tempAddresses[index],16))
				ans.append(int(tempAddresses[index],16) +1)
		offset+=1
	dprint2 (ans)
	if len(ans)>0:
		size=len(ans)-1
		distance = ans[size]-ans[0]
		dprint2(distance)
		dprint2 (ans[0], ans[distance])
		modifyShBySpecial(data, ans[0], end, "al")
		modifyShByRange(data, ans[0], end,  "d")



def disHereMakeDB2(data,offset, end, mode, CheckingForDB):
	dprint2("dis: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	num_bytes=end-offset
	dprint2 (num_bytes)
	printAllShByRange(offset,offset+num_bytes)

	global labels
	nada=""
	Ascii="B"
	stop=offset+1
	val=""
	stringVal=""
	db=0
	dbOut=""
	t=offset
	w=0
	length=end-offset
	dbFlag=False
	skip=True
	startAddString=""
	stringVala=""
	stringStart=0
	stringInProgress=False
	sVal=""
	beforeS=""
	curDisassembly=""
	# for x in range (length):
		# if offset >= length:
		# 	break

	maxSize=offset+length
	while offset < maxSize:
		stop=offset+1
		bytesRes= (binaryToStr(data[offset:stop]))
		instr="db 0"+bytesRes[1:]+" (!)"
		Ascii2=makeAsciiforDB(bytesRes)
		val +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
		# sVal +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
		dprint2 ("checkingDis", hex(offset), hex(length))
	

		if shBy.strings[offset]==True: # and shBy.boolspecial[offset]==False:
			dbFlag=True
			stringInProgress=True
			stringval=val
			# addDis(offset,stringVal)
			truth,res=checkForLabel(str(hex(offset)),labels)
			if truth:
				val=res + val
				stringVal=res + stringVal
			stringStart, stringDistance=shBy.stringsStart[offset]
			dprint2("FoundSTRING", hex(stringStart), hex(offset),"off")
			if stringStart==offset:
				dbOut=""
				before=""
				beforeS=sVal 
				# beforeS=removeLastLine(sVal)
				dprint2 (sVal, "\n", beforeS)
				# print ("beforeS", sVal, beforeS)
				sVal=""
				startAddString=str(hex(offset))
				stringVala=shBy.stringsValue[offset]+" ; string"
				dbOut+=(binaryToStr(data[t:t+1]))
				dprint2 (stringVala)
				
			if offset>stringStart:
				dprint2 (stringVala)
				dprint2 ("dbout ", hex(t))
				dbOut+=(binaryToStr(data[t:t+1]))
		if (shBy.strings[offset]==False):#  and shBy.boolspecial[offset]==False:
			dprint2("FoundNOTSTRING", hex(stringStart), hex(offset),"off")

			stringInProgress=False
			if dbFlag==False  and shBy.boolspecial[offset]==False:
				# print ("dbflag=False")
				truth,res=checkForLabel(str(hex(offset)),labels)
				if truth:
					val=val+res
					stringVal=stringVal+res
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				stringVal+=curDisassembly

				addDis(offset,"A."+curDisassembly, "db", "0x"+bytesRes[2:])
				# print ("y offset", hex(t))
		
				# stringVal= beforeS + stringVal
				skip=True
			if dbFlag==True:

				# print ("sV, offset: ", hex(offset), "value ", shBy.stringsValue[offset])
				nada=""
				truth,res=checkForLabel(str(hex(offset)),labels)
				if truth:
					val=val+res
					stringVal=stringVal+res
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(startAddString, stringVala,dbOut,nada ))
				stringVal+=curDisassembly
				addDis(int(startAddString, 16),"B."+curDisassembly, "string","")
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				if  shBy.boolspecial[offset]==False:
					stringVal+="*C"+curDisassembly
					addDis(offset,""+curDisassembly, "db", "0x"+bytesRes[2:])
				if len(beforeS) > 0:
					stringVal= beforeS +"\n"+ "C."+curDisassembly
				dprint2 ("stringVal", stringVal)
				dbOut=""
				dprint2 (stringVal)
				dbFlag=False
				skip=True
			if not skip:
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				stringVal+="*B"+curDisassembly
				addDis(offset,"d."+stringVal, "db", "0x"+bytesRes[2:])
			skip=False
		if shBy.boolspecial[offset]==True:
			mes=shBy.specialVal[offset]
			offset=shBy.specialEnd[offset]-1
			t=offset
			w=offset
			distanceStr =str(hex(shBy.specialEnd[offset]-shBy.specialStart[offset] ))
			if shBy.specialVal[t] == "al":
				stringValSp="align " +distanceStr
			elif shBy.specialVal[t] == "ff":
				stringValSp="db 0xff x "  + distanceStr 
			else:
				stringValSp="align " +distanceStr
			nada=""
			dbOutSp=(binaryToStr(data[shBy.specialStart[offset]:shBy.specialEnd[offset]]))
			curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(shBy.specialStart[offset])), stringValSp,dbOutSp,nada ))
			stringVal+=""+curDisassembly
			addDis(shBy.specialStart[offset],"D."+curDisassembly, "db 0xff\n"*int(len(dbOutSp)/4), "")
			# print ("got it align", hex(offset))
			dprint2(hex(len(shBy.boolspecial)))

			# shBy.specialVal[t]=dataType
			# shBy.specialStart[t]=start
			# shBy.specialEnd[t]=end
			# shBy.boolspecial[t]=True
			# print("changing value align @	
		offset +=1
		stop += 1
		t+=1
		w+=1
		# print ("t-eof", hex(w), hex(length))
		if w==(length):
			if dbFlag==True:
				nada=""
				# stringVal +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(startAddString, stringVala,dbOut,nada ))
				stringVal+=curDisassembly
				addDis(startAddString,"E."+curDisassembly, "string", "")
				# stringVal= beforeS + stringVal
				dbOut=""
				dbFlag=False
				if len(dbOut)>0:
					curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
					stringVal+=curDisassembly
					addDis(offset,"F."+curDisassembly)
			w=0
	# print("ending: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	dprint2("returnDB2\n", val)
	dprint2("stringval\n")
	dprint2(stringVal)
	dprint2 ("")
	val=stringVal
	return val

debuging=True
debuging=False
# debuging=False
def dprint(*args):
	# print("Debug")
	# if debuging==True:
		# print(info)
	dprint2(*args)

def dprint2(*args):

	if debuging:
		try:
			if  (len(args) == 1):
				if(type(args[0]) == list):
					print(args[0])
					return

			if  (len(args) > 1):
				strList = ""
				for each in args:
					try:
						strList += each + " "
					except:
						strList += str(each) + " "
				print(strList)

			else:
				for each in args:
					try:
						print (str(each) + " ")
					except:
						print ("dprint error: 1")
						print (each + " ")
		except Exception as e:
			print ("dprint error: 3")
			print (e)
			print(traceback.format_exc())
			print (args)

def removeBadOffsets(notBad):
	dprint2("remove offset ", notBad)
	global possibleBadLabelOffsets
	for x in possibleBadLabelOffsets:
		# print (x, type(x))
		if x == notBad:
			dprint2 ("it gone")
			possibleBadLabelOffsets.remove (x)
	dprint2 (possibleBadLabelOffsets)


def removeLabels(notLabel, val):
	dprint2("remove labels ", notLabel)
	# labels.append(str(hex(destination)))
	# labelOffsets.append(int(i.op_str, 16))
	global labels
	t=0
	for x in labels:
		# print (x, type(x))
		if x == val:
			dprint2 ("labels it gone")
			labels.remove (x)
			del labelOffsets[t]
			dprint2 ("labels it gone2")
		t+=1


def analysisFindHiddenCalls(data, startingAddress):
	dprint2("analysisFindHiddenCalls " + str(startingAddress))
	current=0
	start=startingAddress
	max=len(shBy.bytesType)-1
	finalPrint=""
	# dprint (start, "start")
	start, current, distance, typeBytes = findRange2(current)
	# dprint2 (start, "AFTER FIRST")
	reset = False
	while current < max:
		# dprint (start, "end2")
		dprint2 ("1ana",  "start", hex(start), "current", hex(current),  hex(distance))
		if max==current:
			current+=1
		dprint2(binaryToStr(data[start:current]))
		if not typeBytes:
			dprint2 ("AN: above is data")
			anaFindCalls(data,start, start+distance)
			anaFindShortJumps(data,start, start+distance)
		start, current, distance, typeBytes = findRange2(current)
		if current==max:
			# print ("gotme")
			pass
		#reset once done - do analysis again to catch any changes 
		if (current) == max and reset != True:
			reset=True
			# dprint ("reset")
			current=0


def anaFindAlign2(data):
	# global FFInstructions
	dprint2("anaFindF2")
	OP_FF=b"\x00"
	offset=0
	maxV=len(data)
	escape=False
	# modifyShByRange(data, 0x170, 0x175, "d")
	while offset < maxV:
	# for datum in data:
		# print ("ff:\t"+ str(binaryToStr(data[offset:offset+1])) + "\t" + str(hex(offset)))
		escape=False
		total=0			
		v=1
		w=0
		distance=0
		# print ("total", total)
		# test=b"\xff"
		test=(data[offset+distance+w:offset+distance+v])
		dprint2 ("checking", hex(offset))


		while (test == OP_FF) and (shBy.bytesType[offset]==False):
			dprint2 ("enter", hex(offset))
			# print ("w", hex(w), "v", hex(v), "offset", hex(offset))
			# print( "2binaryToStrCheck", binaryToStr(data[offset+distance:offset+distance+v]))
			test=(data[offset+distance+w:offset+distance+v])
			test2=(data[offset+distance+w:offset+distance+v+1])
			# if test==(OP_FF) and (test2 != inc_esi):
			if test==(OP_FF) and (test2 not in FFInstructions):
				# print("gots one") # this just counts how many FF's there are that are not part of a more import instruciton'
				total+=1
			v+=1
			w+=1
			escape=True
		# print ("ffcount",total)
		if total > 3:
			dprint2 (total, "newAlignTotal")
			# modifyShByRange(data, offset, offset+distance+total, "d")
			# modifyStringsRange(offset, offset+distance+total, "s", word)
			if total > 6:
				modifyShByRange(data, offset+3, offset+distance+total, "d")

		if escape:
			# print ("inc offset", escape, hex(offset))
			if total >1:
				offset+=total
			else:
				offset+=1
		if not escape:
			# print ("inc offset, not", escape, hex(offset))
			offset+=1

def analysisConvertBytes(data, startingAddress):
	dprint2("analysisConvertBytes", startingAddress)
	current=0
	start=startingAddress
	max=len(shBy.bytesType)-1
	finalPrint=""
	start0, current0, distance0, typeBytes = findRange2(current)
	reset = False
	distance=0
	dataRangeStart=[]
	dataRangeEnd=[]
	while current < max:
		finalPrint0=""
		if max==current:
			current+=1
		dprint2(binaryToStr(data[start:current]))
		finalPrint+=finalPrint0
		if not typeBytes:
			dataRangeStart.append(start)
			dataRangeEnd.append(current)
		start, current, distance, typeBytes = findRange2(current)
	t=0
	dprint2 ("final ranges")
	for x in dataRangeStart:
		try:
			distance=dataRangeStart[t]-dataRangeEnd[t-1]
		except:
			distance=0
		try:
			dprint2 (hex(dataRangeEnd[t-1]), hex(dataRangeStart[t]) )
			if str(hex(dataRangeEnd[t-1])) not in labels:
				# print (str(hex(dataRangeEnd[t-1])),"not in label0")
				# s2=dataRangeEnd[ t-1]
				# s1=dataRangeStart[t-1]
				# print (s1, s2)
				# ans, valb_1, valb_2, num_bytes=disHereTiny(data[s1:s2])
				# print(ans, "ans convertbyes")
				if distance <=5:
					dprint2 ("make data?")
					modifyShByRange(data, dataRangeEnd[t-1],dataRangeEnd[t-1]+distance, "d")
			else: 
				dprint2 (str(hex(dataRangeEnd[t-1])),"****in labels")
		except:
			pass
		dprint2 (hex(distance))
		dprint2 ("*************************\n")
		t+=1

def anaFindCalls(data, start, current):
	global offsets
	dprint2 ("anna: " + " "  + str(hex(start)) + " " + str(hex(current)) )
	OP_CALL =  b"\xe8"
	OP_ff =  b"\xff"
	dprint2 (binaryToStr(data[start:current]))
	t=0
	destination=99999999
	searchFor=[]
	for opcode in data[start:current]:
		test=int(data[start+t])
		# print (hex(test), hex(ord(OP_CALL)))
		if test==ord(OP_CALL):
			dprint2("FOUND 0xe8!")
			ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
			dprint2 (ans, valb_1, valb_2)
			if valb_1=="call":
				modifyShByRange(data, start+t,start+t+5,"i")
				###check to see if = FF FF FF  - negative - otherwise, positive!
				dprint2 ("checking ff")
				dprint2 (int(data[start+t+4]), ord(OP_ff))
				if (int(data[start+t+4]))==ord(OP_ff):
					if (int(data[start+t+3]))==ord(OP_ff):
						signedNeg=signedNegHexTo(int(valb_2,16))
						destination=(start+t) +signedNeg
						ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
						dprint2 (valb_2)
						dprint2("ff destination: " + str(hex(destination)))
						if str(hex(destination)) not in labels:
							dprint2  ("1 appending label " + str(hex(destination)))
							labels.append(str(hex(destination)))
				#ok, it is positive
				elif (int(data[start+t+4]))==0:
					# if (int(data[start+t+3]))==0:
					ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
					destination = (start+t) + int(valb_2,16)
					# print ((hex(start+t)))
					# print(hex(signedNeg))
					dprint2("00 destination: " + str(hex(destination)))
					if str(hex(destination)) not in labels:
						dprint2  ("2 appending label " + str(hex(destination)))
						labels.append(str(hex(destination)))
				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))
		t+=1
	for addy in searchFor:
		if addy in offsets:
			dprint2("In offsets")
		else:
			if int(addy,16) not in offsets:
				offsets.append(int(addy,16))
			dprint2("Not in offsets")
			# removeBadOffsets(addy)
			modifyShByRange(data, int(addy,16)-2, int(addy,16),"d")

def anaFindShortJumps(data, start, current):
	global offsets
	global labels
	dprint2 ("anna2: " + " "  + str(hex(start)) + " " + str(hex(current)) )
	OP_SHORT_JUMP =  b"\xeb"
	OP_SHORT_JUMP_NEG =  b"\xe9"
	OP_ff =  b"\xff"
	dprint2 (binaryToStr(data[start:current]))
	t=0
	destination=99999999
	searchFor=[]
	for opcode in data[start:current]:
		test=int(data[start+t])
		# print ("sj", hex(start+t), ": ", hex(test), hex(ord(OP_SHORT_JUMP)))
		# IT IS A POSITIVE JUMP
		if test==ord(OP_SHORT_JUMP):
			dprint2("FOUND 0xeb!", hex(start+t))
			ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
			dprint2 (ans, valb_1, valb_2)
			dprint2 ("ans:",ans)
			if valb_1=="jmp":
				dprint2 ("checking short jump")
				modifyShByRange(data, start+t,start+t+num_bytes,"i")
				destination = (start+t) + int(valb_2,16)
				dprint2("eb destination: " + str(hex(destination)))
				if str(hex(destination)) not in labels:
					labels.append(str(hex(destination)))
					dprint2  ("3 appending label " + str(hex(destination)))

				
				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))
		# FINE, IT IS NEGATIVE
		if test==ord(OP_SHORT_JUMP_NEG):
			dprint2("FOUND 0xe9!")
			ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
			dprint2 (ans, valb_1, valb_2)
			dprint2 ("ans:",ans)
			if valb_1=="jmp":
				modifyShByRange(data, start+t,start+t+num_bytes,"i")
				dprint2 ("checking short jump negative")
				destination = (start+t) + int(valb_2,16)
				dprint2("neg e9 destination: " + str(hex(destination)))
				if str(hex(destination)) not in labels:
					labels.append(str(hex(destination)))
					# print  ("4 appending label " + str(hex(destination)))

				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))




		t+=1
	for addy in searchFor:
		if int(addy,16) in offsets:
			dprint2("In offsets")
		else:
			dprint2("Not in offsets")
			dprint2 ("addy", addy)
			offsets.append(int(addy, 16))
			removeBadOffsets(addy)
			# print (type(each))
			modifyShByRange(data, int(addy,16)-1, int(addy,16),"d")
def disHereAnalysis(data,offset, end, mode, CheckingForDB): #
	global labels
	global offsets
	global labelOffsets
	global possibleBadLabelOffsets
	dprint2 ("disHereAnalysis - range  "  + str(offset) + " " + str(end))
	global o
	w=0

	try:
		address=offset
	except:
		address=0
	i=0
	# CheckingForDB=True   ### turns on or off special converting to DB of invalid instructions

	cs.skipdata = True
	cs.skipdata_setup = ("db", None, None)

	if offset==False:
		offset=0
	if end==False:
		end=len(data)-1
	CODED2=data[offset:end]
	val =""
	val2 = []
	val3 = []
	val5 =[]
	startAdd=[]
	nextAdd=[]
	bytesPerLine=[]
	cntLines=0
	bytesEachLine=[]
	asciiPerLine=[]
	CODED3 = CODED2

	t=0
	for i in cs.disasm(CODED3, address):
		cntLines+=1
		val=i.mnemonic + " " + i.op_str 
		offsets.append((int(i.address)))
		controlFlow= re.match( r'\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bja\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', val, re.M|re.I)
		if controlFlow:
			val=i.op_str
			isHex= re.match( "^[0-9][x]*[A-Fa-f0-9 -]*",val, re.M|re.I)
			if isHex:
				dprint2("addlabel:  " + val)
				is0x=re.match("0x*",val, re.M|re.I)
				if not is0x:
					# print ("isnotx")
					val="0x"+val
					# print (val)

				# labels.append(val)
				# print  ("5 appending label ", val, hex(t))
				# print (i.mnemonic, i.op_str)
				# labelOffsets.append(int(i.op_str, 16))
		t+=1

	current=0
	for i in cs.disasm(CODED3, address):
		if current>0:
			nextAd=sadd1
			nextAdd.append(nextAd)
		sadd1=int(i.address )

		startAdd.append(int(sadd1))
		current+=1

	for labOff in labelOffsets:
		if labOff not in offsets:
			# print ("bad " + str(hex(labOff)))
			if str(hex(labOff)) not in possibleBadLabelOffsets:
				possibleBadLabelOffsets.append((str(hex(labOff))))
				# modifyShByRange(data, labOff,labOff+1,"d")
	dprint2 (possibleBadLabelOffsets)
	t=0
	ans=0
	total=0
	for each in startAdd:
		try:
			ans=int(startAdd[t+1]) - int(each)
			bytesPerLine.append(ans)
			total+=ans
		except:
			ans2= hex(len(data)-total)
			bytesPerLine.append(int(ans2,16))
		t+=1
	cnt=0
	t=0
	for i in cs.disasm(CODED3, address): 
		ans= binaryToStr(CODED3[cnt:cnt+bytesPerLine[t]]) #+ " " + str(t) + "\n"
		res=""
		for y in CODED3[cnt:cnt+bytesPerLine[t]]:
			yy=ord2(y) 
			zz=show1(yy) 
			old="nope"
			if ((yy > 31) & (yy < 127)):
				try: 
					zz=int(zz,16)
					zz = chr(zz)
				except:
					zz = chr(zz)
			else:
				zz="."
			old=zz
			res += zz # stripWhite(zz)#chr(zz)
		asciiPerLine.append(res)
		bytesEachLine.append(ans)
		cnt+=bytesPerLine[t]
		t+=1	
	t=0
	try:
		add = hex(int(i.address))
	except:
		pass
	cs.skipdata = True
	sizeShell=len(CODED2)
	for i in cs.disasm(CODED2, address):
		CantSkip=True
		add = hex(int(i.address))
		addb = hex(int(i.address))
		add2 = str(add)
		# add3 = hex (int(i.address + section.startLoc	))
		add3=0
		add4 = str(add3)
		#  testing=('{:20s} {:20s} {:20s}'.format(a,b,c))
		val_a=addb#"\t"#\t"
		val_b=i.mnemonic + " " + i.op_str 
		val_b1=i.mnemonic
		val_b2=i.op_str
		num_bytes=0
		try:
			val_c= bytesEachLine[t] 
			val_d=asciiPerLine[t] 
		except:
			val_c=""
			val_d=""
		if CheckingForDB:
			try:
				num_bytes=int(len(val_c)/4)
			except:
				num_bytes=1
			val_b, num_bytes =checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, possibleBadLabelOffsets,data,num_bytes)
		if mode=="ascii":
			val =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(val_a, val_b, val_c, val_d))
		else:
			val = addb + ":\t" + i.mnemonic + " " + i.op_str+"\n"
			val=('{:<10s} {:<35s}\n'.format(val_a, val_b))
		truth,res=checkForLabel(addb,labels)
		if truth:
			val=res+val
		valCheck=i.mnemonic + " " + i.op_str 
		controlFlow= re.match( r'\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bja\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bret\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', valCheck, re.M|re.I)
		if controlFlow:
			val=val+"\n"
		while (num_bytes>0):	
			if num_bytes>0:
				val, num_bytes,val_c =makeDBforUnknownBytes(num_bytes, val_c, addb)
				dprint2 ("truth check " + addb)
				truth,res=checkForLabel(addb,labels)
				if truth:
					val=res+val
				valCheck=i.mnemonic + " " + i.op_str 
				addb=str(hex(int(addb,16)+1))
				dprint2("final val_c")
				dprint2(type(val_c))
				val2.append(val)
				val3.append(add2)
				val5.append(val)
				CantSkip=False
		if CantSkip:
			val2.append(val)
			val3.append(add2)
			val5.append(val)
		t+=1
	returnString=""
	for y in val5:
		returnString+=y
	return returnString


def disHereShell_old2(data,offset, end, mode, CheckingForDB, bit): #
	global labels
	global offsets
	global labelOffsets
	global possibleBadLabelOffsets
	global bit32
	printAllShByRange(offset,end)
	dprint2 ("dis: dishereshell - range  "  + str(hex(offset)) + " " + str(hex(end)))
	dprint2(binaryToStr(data[offset:end]))
	dprint2(binaryToStr(data))
	nada=""
	
	callCS = cs
	if(bit32):
		callCS = cs
	else:
		callCS = cs64

	global o
	w=0

	try:
		address=offset
	except:
		address=0
	i=0
	callCS.skipdata = True
	callCS.skipdata_setup = ("db", None, None)
	if offset==False:
		offset=0
	if end==False:
		end=len(data)-1
	CODED2=data[offset:end]
	val =""
	val2 = []
	val3 = []
	val5 =[]
	startAdd=[]
	nextAdd=[]
	bytesPerLine=[]
	cntLines=0
	bytesEachLine=[]
	asciiPerLine=[]
	CODED3 = CODED2
	current=0

	for i in callCS.disasm(CODED3, address):
		cntLines+=1
		if current>0:
			nextAd=sadd1
			nextAdd.append(nextAd)
		sadd1=int(i.address )

		startAdd.append(int(sadd1))
		current+=1
		val=i.mnemonic + " " + i.op_str 
		offsets.append((int(i.address)))
		controlFlow= re.match( r'\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bja\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', val, re.M|re.I)
		if controlFlow:
			val=i.op_str
			isHex= re.match( "^[0-9][x]*[A-Fa-f0-9 -]*",val, re.M|re.I)
			if isHex:
				dprint2("addlabel: shell call " + val)
				is0x=re.match("0x*",val, re.M|re.I)
				if not is0x:
					val="0x"+val
				dprint2  ("6 appending label " + val)

				labels.append(val)
				labelOffsets.append(int(i.op_str, 16))
	
	for labOff in labelOffsets:
		if labOff not in offsets:
			# print ("bad " + str(hex(labOff)))
			if str(hex(labOff)) not in possibleBadLabelOffsets:
				possibleBadLabelOffsets.append((str(hex(labOff))))
				# modifyShByRange(data, labOff,labOff+1,"d")
	dprint2 (possibleBadLabelOffsets)
	t=0
	ans=0
	total=0
	for each in startAdd:
		try:
			ans=int(startAdd[t+1]) - int(each)
			bytesPerLine.append(ans)
			total+=ans
		except:
			ans2= hex(len(data)-total)
			bytesPerLine.append(int(ans2,16))
		t+=1
	cnt=0
	t=0
	for i in callCS.disasm(CODED3, address): 
		ans= binaryToStr(CODED3[cnt:cnt+bytesPerLine[t]]) #+ " " + str(t) + "\n"
		res=""
		for y in CODED3[cnt:cnt+bytesPerLine[t]]:
			yy=ord2(y) 
			zz=show1(yy) 
			old="nope"
			if ((yy > 31) & (yy < 127)):
				try: 
					zz=int(zz,16)
					zz = chr(zz)
				except:
					zz = chr(zz)
			else:
				zz="."
			old=zz
			res += zz # stripWhite(zz)#chr(zz)

		asciiPerLine.append(res)
		bytesEachLine.append(ans)
		cnt+=bytesPerLine[t]
		t+=1	
	t=0
	try:
		add = hex(int(i.address))
	except:
		dprint2 ("weird error - investigate")
		pass
	callCS.skipdata = True
	sizeShell=len(CODED2)
	for i in callCS.disasm(CODED2, address):
		CantSkip=True
		add = hex(int(i.address))
		addb = hex(int(i.address))
		add2 = str(add)
		# add3 = hex (int(i.address + section.startLoc	))
		add3=0
		add4 = str(add3)
		#  testing=('{:20s} {:20s} {:20s}'.format(a,b,c))
		val_a=addb#"\t"#\t"
		val_b=i.mnemonic + " " + i.op_str 
		val_b1=i.mnemonic
		val_b2=i.op_str
		num_bytes=0
		try:
			val_c= bytesEachLine[t] 
			val_d=asciiPerLine[t] 
		except:
			val_c=""
			val_d=""
		# CheckingForDB=False
		if CheckingForDB:
			try:
				num_bytes=int(len(val_c)/4)
			except:
				num_bytes=1
			val_b, num_bytes =checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, possibleBadLabelOffsets,data,num_bytes)

		if mode=="ascii":
			val =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(val_a, val_b, val_c, val_d))
			addDis(int(val_a, 16), "*"+val, i.mnemonic, i.op_str)
		else:
			val = addb + ":\t" + i.mnemonic + " " + i.op_str+"\n"
			val=('{:<10s} {:<35s}\n'.format(val_a, val_b))

		####ADD COMMENTS
		if shBy.comments[int(addb,16)] !="":
			val_b=shBy.comments[int(addb,16)]
			val_comment =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(nada, val_b, nada, nada))
			val+=val_comment
		#### ADD COMENTS END
		truth,res=checkForLabel(addb,labels)
		if truth:
			val=res+val
		valCheck=i.mnemonic + " " + i.op_str 
		controlFlow= re.match( r'\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bja\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bret\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', valCheck, re.M|re.I)

		if controlFlow:
			val=val+"\n"
		# while (num_bytes>0):	
		# 	if num_bytes>0:
		# 		val, num_bytes,val_c =makeDBforUnknownBytes(num_bytes, val_c, addb)
		# 		dprint ("truth check " + addb)
		# 		truth,res=checkForLabel(addb,labels)
		# 		if truth:
		# 			val=res+val
		# 		valCheck=i.mnemonic + " " + i.op_str 
		# 		addb=str(hex(int(addb,16)+1))
		# 		dprint("final val_c")
		# 		dprint(type(val_c))
		# 		val2.append(val)
		# 		val3.append(add2)
		# 		val5.append(val)
		# 		CantSkip=False

		############Stack strings begin
		try:
			cur=int(add,16)
			# print (hex(shBy.pushStringEnd[cur]), add, "pushending")
			if (shBy.pushStringEnd[cur]-2) == cur:
				dprint2 ("push match", shBy.pushStringValue[cur])
				nada=""
				msg="; "+shBy.pushStringValue[cur] + " - Stack string"
				newVal =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(nada, msg, nada, nada))
				val= newVal+val
				dprint2 (val)
		except Exception as e:
			# print ("weird error", e)
			pass
		##### Stack Strings End

		####ADD COMMENTS
		# if shBy.comments[int(addb,16)] !="":
		# 	val=val+shBy.comments[int(addb,16)]
		#### ADD COMENTS END
		if CantSkip:
			val2.append(val)
			val3.append(add2)
			val5.append(val)


		# if shBy.pushStringEnd[t]==:
		t+=1
	returnString=""
	for y in val5:
		returnString+=y


	dprint2 ("possibleBadLabelOffsets")
	dprint2 (possibleBadLabelOffsets)
	return returnString



def disHereShell(data,offset, end, mode, CheckingForDB, bit): #
	global labels
	global offsets
	global labelOffsets
	global possibleBadLabelOffsets
	global bit32
	printAllShByRange(offset,end)
	dprint2 ("dis: dishereshell - range  "  + str(hex(offset)) + " " + str(hex(end)))
	dprint2(binaryToStr(data[offset:end]))
	dprint2(binaryToStr(data))
	nada=""
	
	callCS = cs
	if(bit32):
		callCS = cs
	else:
		callCS = cs64

	global o
	w=0

	try:
		address=offset
	except:
		address=0
	i=0
	callCS.skipdata = True
	callCS.skipdata_setup = ("db", None, None)
	if offset==False:
		offset=0
	if end==False:
		end=len(data)-1
	CODED2=data[offset:end]
	val =""
	val2 = []
	val3 = []
	val5 =[]
	startAdd=[]
	nextAdd=[]
	bytesPerLine=[]
	cntLines=0
	bytesEachLine=[]
	asciiPerLine=[]
	CODED3 = CODED2
	for i in callCS.disasm(CODED3, address):
		cntLines+=1
		val=i.mnemonic + " " + i.op_str 
		offsets.append((int(i.address)))
		controlFlow= re.match( r'\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bja\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', val, re.M|re.I)
		if controlFlow:
			val=i.op_str
			isHex= re.match( "^[0-9][x]*[A-Fa-f0-9 -]*",val, re.M|re.I)
			if isHex:
				dprint2("addlabel: shell call " + val)
				is0x=re.match("0x*",val, re.M|re.I)
				if not is0x:
					val="0x"+val
				dprint2  ("6 appending label " + val)

				labels.append(val)
				labelOffsets.append(int(i.op_str, 16))
	current=0
	for i in callCS.disasm(CODED3, address):
		if current>0:
			nextAd=sadd1
			nextAdd.append(nextAd)
		sadd1=int(i.address )
		startAdd.append(int(sadd1))
		current+=1
	for labOff in labelOffsets:
		if labOff not in offsets:
			# print ("bad " + str(hex(labOff)))
			if str(hex(labOff)) not in possibleBadLabelOffsets:
				possibleBadLabelOffsets.append((str(hex(labOff))))
				# modifyShByRange(data, labOff,labOff+1,"d")
	dprint2 (possibleBadLabelOffsets)
	t=0
	ans=0
	total=0
	for each in startAdd:
		try:
			ans=int(startAdd[t+1]) - int(each)
			bytesPerLine.append(ans)
			total+=ans
		except:
			ans2= hex(len(data)-total)
			bytesPerLine.append(int(ans2,16))
		t+=1
	cnt=0
	t=0
	for i in callCS.disasm(CODED3, address): 
		ans= binaryToStr(CODED3[cnt:cnt+bytesPerLine[t]]) #+ " " + str(t) + "\n"
		res=""
		for y in CODED3[cnt:cnt+bytesPerLine[t]]:
			yy=ord2(y) 
			zz=show1(yy) 
			old="nope"
			if ((yy > 31) & (yy < 127)):
				try: 
					zz=int(zz,16)
					zz = chr(zz)
				except:
					zz = chr(zz)
			else:
				zz="."
			old=zz
			res += zz # stripWhite(zz)#chr(zz)
		asciiPerLine.append(res)
		bytesEachLine.append(ans)
		cnt+=bytesPerLine[t]
		t+=1	
	t=0
	try:
		add = hex(int(i.address))
	except:
		dprint2 ("weird error - investigate")
		pass
	callCS.skipdata = True
	sizeShell=len(CODED2)
	for i in callCS.disasm(CODED2, address):
		CantSkip=True
		add = hex(int(i.address))
		addb = hex(int(i.address))
		add2 = str(add)
		# add3 = hex (int(i.address + section.startLoc	))
		add3=0
		add4 = str(add3)
		#  testing=('{:20s} {:20s} {:20s}'.format(a,b,c))
		val_a=addb#"\t"#\t"
		val_b=i.mnemonic + " " + i.op_str 
		val_b1=i.mnemonic
		val_b2=i.op_str
		num_bytes=0
		try:
			val_c= bytesEachLine[t] 
			val_d=asciiPerLine[t] 
		except:
			val_c=""
			val_d=""
		# CheckingForDB=False
		if CheckingForDB:
			try:
				num_bytes=int(len(val_c)/4)
			except:
				num_bytes=1
			val_b, num_bytes =checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, possibleBadLabelOffsets,data,num_bytes)

		if mode=="ascii":
			val =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(val_a, val_b, val_c, val_d))
			addDis(int(val_a, 16), "*"+val, i.mnemonic, i.op_str)
		else:
			val = addb + ":\t" + i.mnemonic + " " + i.op_str+"\n"
			val=('{:<10s} {:<35s}\n'.format(val_a, val_b))

		####ADD COMMENTS
		if shBy.comments[int(addb,16)] !="":
			val_b=shBy.comments[int(addb,16)]
			val_comment =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(nada, val_b, nada, nada))
			val+=val_comment
		#### ADD COMENTS END
		truth,res=checkForLabel(addb,labels)
		if truth:
			val=res+val
		valCheck=i.mnemonic + " " + i.op_str 
		controlFlow= re.match( r'\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bja\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bret\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', valCheck, re.M|re.I)

		if controlFlow:
			val=val+"\n"
		# while (num_bytes>0):	
		# 	if num_bytes>0:
		# 		val, num_bytes,val_c =makeDBforUnknownBytes(num_bytes, val_c, addb)
		# 		dprint ("truth check " + addb)
		# 		truth,res=checkForLabel(addb,labels)
		# 		if truth:
		# 			val=res+val
		# 		valCheck=i.mnemonic + " " + i.op_str 
		# 		addb=str(hex(int(addb,16)+1))
		# 		dprint("final val_c")
		# 		dprint(type(val_c))
		# 		val2.append(val)
		# 		val3.append(add2)
		# 		val5.append(val)
		# 		CantSkip=False

		############Stack strings begin
		try:
			cur=int(add,16)
			# print (hex(shBy.pushStringEnd[cur]), add, "pushending")
			if (shBy.pushStringEnd[cur]-2) == cur:
				dprint2 ("push match", shBy.pushStringValue[cur])
				nada=""
				msg="; "+shBy.pushStringValue[cur] + " - Stack string"
				newVal =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(nada, msg, nada, nada))
				val= newVal+val
				dprint2 (val)
		except Exception as e:
			# print ("weird error", e)
			pass
		##### Stack Strings End

		####ADD COMMENTS
		# if shBy.comments[int(addb,16)] !="":
		# 	val=val+shBy.comments[int(addb,16)]
		#### ADD COMENTS END
		if CantSkip:
			val2.append(val)
			val3.append(add2)
			val5.append(val)


		# if shBy.pushStringEnd[t]==:
		t+=1
	returnString=""
	for y in val5:
		returnString+=y


	dprint2 ("possibleBadLabelOffsets")
	dprint2 (possibleBadLabelOffsets)
	return returnString
def disHereTiny(data): #
	address=0
	i=0
	CODED2=data
	val =""
	val2 = []
	val3 = []
	val5 =[]
	dprint2 ("disheretiny")
	binStr=(binaryToStr(data))
	dprint2(binStr)
	first_val_b=""
	first_val_b1=""
	first_val_b2=""
	first=True
	second=0
	num_bytesLine1=0
	nop="90"
	nop1=fromhexToBytes(nop)
	dprint2 (binaryToStr(nop1))
	for i in cs.disasm(CODED2 + nop1, address):
		add = hex(int(i.address))
		addb = hex(int(i.address))
		add2 = str(add)
		add3=0
		add4 = str(add3)
		val_a=addb#"\t"#\t"
		val_b=i.mnemonic + " " + i.op_str 
		val_b1=i.mnemonic
		val_b2=i.op_str
		num_bytes=0
		val2.append(val)
		val3.append(add2)
		val5.append(val_b)
		if first:
			first=False
			first_val_b=val_b
			first_val_b1=val_b1
			first_val_b2=val_b2
		second+=1
		if second == 2:
			num_bytesLine1=int(i.address)
			dprint2 ("num_bytes", num_bytesLine1)
	if num_bytesLine1==0:
		pass
	returnString=""
	for y in val5:
		returnString+=y+"\n"
	dprint2 ("\n")
	dprint2 (returnString + "rs\n")
	return first_val_b, first_val_b1, first_val_b2, num_bytesLine1


def disHereCheck(data): #
	address=0
	i=0
	CODED2=data
	val =""
	val2 = []
	val3 = []
	val5 =[]
	dprint2 ("disHereCheck")
	binStr=(binaryToStr(data))
	dprint2(binStr)
	first_val_b=""
	first_val_b1=""
	first_val_b2=""
	first=True
	second=0
	num_bytesLine1=0
	nop="90"
	nop1=fromhexToBytes(nop)
	dprint2 (binaryToStr(nop1))
	for i in cs.disasm(CODED2 + nop1, address):
		add = hex(int(i.address))
		addb = hex(int(i.address))
		add2 = str(add)
		add3=0
		add4 = str(add3)
		val_a=addb#"\t"#\t"
		val_b=i.mnemonic + " " + i.op_str 

		controlFlow= re.match( r'\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bja\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', val_b, re.M|re.I)
		if controlFlow:
			val=i.op_str
			isHex= re.match( "^[0-9][x]*[A-Fa-f0-9 -]*",val, re.M|re.I)
			if isHex:
				dprint2("removLab:  " + val)
				
				removeLabels(val_b, val)
				dprint2("done")

		val_b1=i.mnemonic
		val_b2=i.op_str
		num_bytes=0
		val2.append(val)
		val3.append(add2)
		val5.append(val_b)

	returnString=""
	for y in val5:
		returnString+=y+"\n"
	dprint2 ("\n")
	dprint2 (returnString + "rs\n")
	# return returnString


def modifyShByRangeUser():
	print ("Type x to exit")
	global shBy
	valInput=""	
	typeBy=""
	start=0
	end=0
	while (valInput !="x"):
		skip=False
		print ("Range of offsets to modify?")
		rangeOff=input()
		valInput=rangeOff
		valInput.lower()
		array = rangeOff.split("-")
		try:
			start=int(array[0],16)
			end=int(array[1],16)
		except:
			start=99999999
			end=99999999
		if (start > end):
			print ("Invalid range!")
			skip=True
		
		if not skip:
			if (valInput!="x"):
				print ("Type? Data (d) or instructions (i)?")
				typeBy=input()
				valInput=typeBy
				valInput.lower()	

			print (start, end, typeBy)
			typeBy.lower()
			BytesBool=False
			t=0
		
			if typeBy=="d":
				BytesBool=False
			if typeBy=="i":
				BytesBool=True
			for x in shBy.bytesType:
				if (t>=start) and (t < end):
					shBy.bytesType[t]=BytesBool
					# dprint2("changing value @ " + str(t))
				t+=1

		print (shBy.bytesType)


def modifyShByRange(data, start,end, dataType):
	dprint2 ("modRange ", hex(start),hex(end),dataType)
	global shBy
	BytesBool=False
	t=0
	if dataType=="d":
		BytesBool=False
	if dataType=="i":
		BytesBool=True

	if dataType=="d":
		dprint2 ("magic")
		out=disHereCheck(data[start:end])
		dprint2(out)
	for x in shBy.bytesType:
		if (t>=start) and (t < end):
			dprint2 ("before", shBy.bytesType[t])
			shBy.bytesType[t]=BytesBool
			
			# dprint2("changing value @ " + str(hex(t)))
			dprint2 (shBy.bytesType[t], " value: ", hex(shBy.values[t]))
			if BytesBool:
				shBy.boolspecial[t]=False
		t+=1



def modifyShBySpecial(data, start,end, dataType):
	dprint2 ("modRangeSpecial ", hex(start),hex(end),dataType)
	global shBy
	BytesBool=False
	t=0
	spec=""
	if dataType=="al":
		spec="align"
	if dataType=="ff":
		spec="ff"

	for x in shBy.bytesType:
		if (t>=start) and (t < end):
			dprint2 ("before", shBy.specialVal[t])
			shBy.specialVal[t]=spec
			shBy.specialStart[t]=start
			shBy.specialEnd[t]=end
			shBy.boolspecial[t]=True
			dprint2("changing value align @ " + str(hex(t)))
			dprint2 (shBy.specialVal[t], " value: ", hex(shBy.values[t]))
			dprint2(shBy.boolspecial[t], hex(shBy.specialStart[t]), hex(shBy.specialEnd[t]) )
		t+=1

	# dprint2 (shBy.bytesType)
def modifyStringsRange(start,end, dataType, word):
	dprint2 ("modStrings " )
	dprint2 (hex(start),hex(end),dataType)
	global shBy
	BytesBool=False
	t=0
	if dataType=="ns":
		BytesBool=False
	if dataType=="s":
		BytesBool=True
	for x in shBy.bytesType:
		if (t>=start) and (t < end):
			# dprint2 (shBy.strings[t])
			shBy.strings[t]=BytesBool
			shBy.stringsStart[t]=(tuple((start, end-start)))
			shBy.stringsValue[t]=word
			dprint2("changing Strings value @ " + str(hex(t)))
			dprint2 (shBy.strings[t], " value: ", hex(shBy.values[t]))
			dprint2 (hex(t))
			# dprint2 (shBy.stringsValue[t])

			# dprint2 (hex(shBy.stringsStart[t]), " value: ", hex(shBy.values[t]))
			x,y=shBy.stringsStart[t]
			dprint2 (x,y)
		t+=1
	# dprint2 (shBy.bytesType)

def modifyPushStringsRange(start,end, dataType, word):
	dprint2 ("modStringPush " )
	# dprint2 (hex(start),hex(end),datfaType)
	global shBy
	BytesBool=False
	t=0
	if dataType=="ns":
		BytesBool=False
	if dataType=="s":
		BytesBool=True
	for x in shBy.bytesType:
		if (t>=start) and (t < end):
			# dprint2 (shBy.strings[t])
			shBy.strings[t]=False
			shBy.stringsStart[t]=(tuple((0, 0)))
			shBy.stringsValue[t]=""
			shBy.pushStringEnd[t]= end
			shBy.pushStringValue[t]=word
			shBy.boolPushString[t]=BytesBool
			dprint2("changing StringsPush value @ " + str(hex(t)))

			dprint2 (shBy.boolPushString[t], " value: ", hex(shBy.values[t]))
			dprint2 ("end", shBy.pushStringEnd[t])
			dprint2 (hex(t))
			# dprint2 (shBy.stringsValue[t])

			# dprint2 (hex(shBy.stringsStart[t]), " value: ", hex(shBy.values[t]))
			x,y=shBy.stringsStart[t]
			dprint2 (x,y)
		t+=1
	# dprint2 (shBy.bytesType)
def printAllShBy():
	dprint2("printAllShBy")
	t=0
	out=""
	d=0
	for off in shBy.offsets:
		out+= (str(hex(off )) + ": " + str(shBy.bytesType[t])) + " ("+str(hex(shBy.values[t])) +")\t"
		t+=1
		d+=1
		if d==5:
			out+="\n"
			d=0
	dprint2 (out)


def printAllShByStrings():
	dprint2("printAllShByStrings")
	t=0
	out=""
	d=0
	for off in shBy.offsets:
		sVal=""
		if shBy.strings[t]:
			sVal="ST"
		else:
			sVal="NO"
		out+= str(hex(off )) + ": " + sVal + " ("+str(hex(shBy.values[t])) +")\t"
		t+=1
		d+=1
		if d==5:
			out+="\n"
			d=0
	dprint2 (out)

def printAllShByRange(start,end):
	dprint2("printAllShBy " + str(hex(start)) + " "  + str(hex(end) ))
	t=0
	out=""
	d=0
	t=0
	for off in shBy.offsets:
		if (t >= start) and (t<end):
			out+= (str(hex(off )) + ": " + str(shBy.bytesType[t])) + " ("+str(hex(shBy.values[t])) +")\t"
			d+=1
			if d==5:
				out+="\n"
				d=0
		t+=1
	dprint2 (out)

def findTargetAddressReturnPrior(targetAddress, linesGoBack, l1, l2):
	tl1=[]
	tl2=[]
	linesGoBack=linesGoBack-1
	# targetAddress=0x0
	try:
		index = l1.index(targetAddress)
	except ValueError:
		dprint2 ("Target Index not found")
		return False, tl1, tl2
	dprint2 ("my own index", index)
	dprint2 (index - linesGoBack)
	if (index - linesGoBack) < 0:
		dprint2 ("ok")
		linesGoBack= index-0
		dprint2 ("linesGoBack", linesGoBack)

	tl1=l1[index-linesGoBack:index+1]
	tl2=l2[index-linesGoBack:index+1]
	t=0
	dprint2 ("size", len(tl1))
	# for each in tl1:
	# 	print (hex(each), tl2[t]) 
	# 	t+=1
	# print ("\n\n\n")
	return True,tl1, tl2


def preSyscalDiscovery(startingAddress, targetAddress, linesGoBack):
	global filename
	global rawData2
	global shBy
	global FindStringsStatus
	FindStringsStatus2 =	FindStringsStatus 

	FindStringsStatus2 = False
	clearTempDis()
	if rawBin:
		shellBytes=rawData2
	if not rawBin:
		# print ("ffffilename", filename)
		# print("read shellcode Start: ", start)
		# print("Filename: ", filename)
		rawBytes=readShellcode(filename) 
		# print("read shellcode end: ", time.time() - start)

		rawData2=rawBytes
		# print(rawBytes.hex())
		shellBytes=rawData2
	i=startingAddress
	for x in shellBytes:
		shBy.offsets.append(i)
		shBy.values.append(x)
		shBy.bytesType.append(True) # True = instructions
		shBy.strings.append(False)
		shBy.stringsStart.append(0xffffffff)
		shBy.stringsValue.append("")
		shBy.pushStringEnd.append(-1)
		shBy.pushStringValue.append("")
		shBy.boolPushString.append(False)
		shBy.specialVal.append("")
		shBy.boolspecial.append(False)
		shBy.specialStart.append(0)
		shBy.specialEnd.append(0)
		shBy.comments.append("")
		i+=1
	if FindStringsStatus2:
		findStrings(shellBytes,3)
		findStringsWide(shellBytes,3)
		findPushAsciiMixed(shellBytes,3)
	anaFindFF(shellBytes)

	out=findRange(shellBytes, startingAddress)  #1st time helps do corrections

	anaFindFF(shellBytes)

	l1, l2=createDisassemblyLists()

	# saveDB()

	clearDisassBytClass()

	truth, tl1, tl2= findTargetAddressReturnPrior(targetAddress, linesGoBack, l1, l2)


	dprint2("sizetl1 ", len(tl1))
	return truth, tl1, tl2, l1,l2

def takeBytes(shellBytes,startingAddress):
	global shBy
	global FindStringsStatus
	# print ("take bytes")

	#FindStringsStatus=False
	i=startingAddress
	for x in shellBytes:
		shBy.offsets.append(i)
		shBy.values.append(x)
		# shBy.instructions.append(True)
		# shBy.data.append(False)
		shBy.bytesType.append(True) # True = instructions
		shBy.strings.append(False)
		shBy.stringsStart.append(0xffffffff)
		shBy.stringsValue.append("")
		shBy.pushStringEnd.append(-1)
		shBy.pushStringValue.append("")
		shBy.boolPushString.append(False)
		shBy.specialVal.append("")
		shBy.boolspecial.append(False)
		shBy.specialStart.append(0)
		shBy.specialEnd.append(0)
		shBy.comments.append("")
			
		i+=1
	#rhere
	# modifyShByRange(data, 0x14, 0x19, "d")
	# print ("FindStringsStatus", FindStringsStatus)
	if FindStringsStatus:
		# import sharem
		findStrings(shellBytes,3)
		findStringsWide(shellBytes,3)
		findPushAsciiMixed(shellBytes,3)
	anaFindFF(shellBytes)
	addComments()

	# print ("***lenthShellBytes", len(shellBytes))
	out=findRange(shellBytes, startingAddress)  #1st time helps do corrections
	
	anaFindFF(shellBytes)
	clearTempDis()   # we must call this function before making new diassembly
	out=findRange(shellBytes, startingAddress) # makes sure all corrections fully implemented # this creates final disassembly
	# printAllShBy()
	# print ("printing final\n")
	l1, l2=createDisassemblyLists()

	t=0
	# for each in l1:
	# 	print (str(hex(each)) + "\t"+ l2[t])
	# 	t+=1
	# print (l1, l2)

	# i.mnemonic + " " + i.op_str

	# for x,y, mnemonic, op_str in zip(l1, l2, tempMnemonic, tempOp_str):

	for x,y, mnemonic, op_str in zip(tempAddresses, tempDisassembly, tempMnemonic, tempOp_str):
		# print (hex(x), y ," [",mnemonic,"] [", op_str ,"]")
		# print ((x), y ," [",mnemonic,"] [", op_str ,"]")
		print ((x), y )
	
	assembly=binaryToText(shellBytes)   # this creates the string literal, raw hex, etc.
	return out+assembly

def addComments():

	for item in m[o].save_PEB_info:
		tib=item[5]
		shBy.comments[int(tib,16)] = "; load TIB"
		ldr=item[6]
		shBy.comments[int(ldr,16)] = "; load PEB_LDR_DATA LoaderData"
		mods=item[7]
		modAdd=mods[0]
		modText=mods[1]
		# shBy.comments[int(mods,16)] = "; LIST_ENTRY InMemoryOrderModuleList"
		shBy.comments[int(modAdd,16)] = "; "+ modText

		adv=item[8]
		for each in adv:
			try:
				if each != -1:
					shBy.comments[int(each,16)] = "; advancing DLL flink"
			except:

				print (type(each))
				print (each)
	for item in m[o].save_PushRet_info:

		#(495, 4, 'rawHex', -1, 0, ('0x1ef', 'ebx'), '0x1f0')
		push=item[5]
		pushOffset=push[0]
		pushReg=push[1]
		retOffset=item[6]
		shBy.comments[int(pushOffset,0)] = "; pushing return address "
		shBy.comments[int(retOffset,0)] = "; returning to " + pushReg


	for item in m[o].save_Callpop_info:
		call_offset = item[0]
		pop_offset=item[5]
		# shBy.comments[int(call_offset,16)] = " ; using call for GetPC"
		shBy.comments[int(pop_offset,16)] = " ; GetPC"

	for item in m[o].save_FSTENV_info:
		FPU_offset = item[5]
		FSTENV_offset = item[6]
		shBy.comments[int(FPU_offset,16)] = " ; floating point to set up GetPC"
		shBy.comments[int(FSTENV_offset,16)] = " ; GetPC"

	for item in m[o].save_Heaven_info:
		heaven_offset = item[5]
		pushOffset=item[6]
		destLocation=item[7]
		shBy.comments[int(heaven_offset,16)]= " ; invoking Heaven's Gate technique"
		try:
			shBy.comments[(pushOffset)]= " ; Heaven's gate destination address: " + str(destLocation)
		except:
			shBy.comments[int(pushOffset,16)]= " ; Heaven's gate destination address: " + str(destLocation)
	for item in m[o].save_Egg_info:
		eax = item[5]
		c0_offset = item[6]
		
		shBy.comments[int(c0_offset	,16)] = " ; Calling Windows syscall - value: " + eax 

	
		# print ("index of tib is", tib)
		# print ("index of ldr is", ldr)
		# print ("index of mods is", mods)
# ; PEB_LDR_DATA LoaderData
	  # mov ebp,[eax+1ch]		  ; LIST_ENTRY InMemoryOrderModuleList
def findInList(listPeb, address):
	t=0
	for x in listPeb:
		if listPeb[t]==address:
			# dprint2 ("found", t)
			return t, True
		t+=1
	return 0, False

def findRangeUpdate(data, startingAddress):
	a = 1 #blank functions cause errors
	# TODO update, without calling the analysis functions
	pass

def findRange(data, startingAddress):
	global bit32
	global FindStringsStatus
	if bit32:
		bit=32
	else:
		bit=64
	current=0
	start=startingAddress
	max=len(shBy.bytesType)-1
	finalPrint=""
	analysis= disHereAnalysis(data, False, False, "ascii", True)

	analysisFindHiddenCalls(data, startingAddress)

	analysisConvertBytes(data, startingAddress)

	analysisFindHiddenCalls(data, startingAddress)
	if FindStringsStatus:
		anaFindStrings(data,startingAddress)
	while current < max:
		start, current, distance, typeBytes = findRange2(current)
		finalPrint0=""
		dprint2 ("max: " + str(hex(max)) + " "+str(hex(current)))
		if max==current:
			current+=1
		dprint2(binaryToStr(data[start:current]))
		if typeBytes:

			dprint2 ("above is instructions")

			finalPrint0+= (disHereShell(data, start, current, "ascii", True, bit))

		if not typeBytes:
			dprint2 ("above is data")

			finalPrint0+= (disHereMakeDB2(data, start, current, "ascii", True))

		dprint2 (finalPrint0)
		finalPrint+=finalPrint0
		# analysisFindHiddenCalls(data, startingAddress)
	dprint2 ("\n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n"+finalPrint)
	dprint2 ("\n\n")
	dprint2 (binaryToStr(data))
	return finalPrint
def findRange2(current):
	dprint2("findrange2 ", hex(current))
	t=0
	typeBytes=True
	old=""
	start = current
	first=True
	done=False
	dataWatcher=False
	instWatcher=False
	inProgress=False
	typeData=""
	begin=current
	dprint2 ("size", len(shBy.bytesType))
	if shBy.bytesType[begin]==False:
		typeData="data"
		# dprint2 ("*********making data" )
	else:
		typeData="inst"
		# dprint2 ("********making inst")
	if typeData=="data":
		for x in shBy.bytesType:
			if t > current:
				if x == False: # until no longer false (i.e. NOT DATA)
					if first:
						start=current
					first=False
					typeBytes=False
					current=t 
				if x==True:
					current+=1
					dprint2 ("FIN: data done!")
					distance=current-start
					dprint2 ("r d-:",hex(start), hex(current), hex(distance), typeBytes)
					return start, current, distance, typeBytes
			t+=1
	t=0
	if typeData=="inst":
		# dprint2 ("ins")
		for x in shBy.bytesType:
			if t > current:	
				if x == True:  # until no longer true (i.e. IS NOT INSTRUCTIONS)
					if first:
						start=current
					first=False
					typeBytes=True
					current=t 
				if x==False: # & inProgress:
					current+=1
					dprint2("FIN: instructions done!")
					distance=current-start
					dprint2 ("r: i-",hex(start), hex(current), hex(distance), typeBytes)
					return start, current, distance, typeBytes
			t+=1
	distance=current-start
	dprint2 ("r: -end", hex(start), hex(current), hex(distance), (typeBytes))
	return start, current, distance, typeBytes

FindStrings=True

def anaFindStrings(data, startingAddress):
	# global FFInstructions
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp
	dprint2("anaFindStrings")
	# dprint2 (sharem.stringsTemp)
	OP_FF=b"\xff"

	for word,offset,distance  in stringsTemp:# and stringsTemp:
		dprint2 ("\t"+ str(word) + "\t" + str(hex(offset)) + "\t" + str(hex(distance))) 
		if goodString(data,word,6):
			modifyShByRange(data, offset, offset+distance, "d")
			modifyStringsRange(offset, offset+distance, "s", word)
			total=0			
			v=1
			w=0
			test=b"\xff"
			while (test == OP_FF):
				dprint2(word, "2binaryToStrCheck", binaryToStr(data[offset+distance:offset+distance+v]))
				test=(data[offset+distance+w:offset+distance+v])
				test2=(data[offset+distance+w:offset+distance+v+1])
				dprint2 ("test2", len(test2), hex(offset+distance+w), hex(offset+distance+v+1))
				if test==(OP_FF) and (test2 not in FFInstructions):
					dprint2("gots one") # this just counts how many FF's there are that are not part of a more import instruciton'
					total+=1
				v+=1
				w+=1
			dprint2 ("fftotal",total)
			if total > 1:
				modifyShByRange(data, offset, offset+distance+total, "d")
				# modifyStringsRange(offset, offset+distance+total, "s", word)

	##WIDE			
	dprint2 ("wideStringsStart")	
	try:
		for word,offset,distance  in stringsTempWide:# and stringsTemp:
			dprint2 ("ok")
			dprint2 (type(word), type(offset), type(distance))
			dprint2 ("\t"+ str(word) + "\t" + str(hex(offset)) + "\t" + str(hex(distance))) 

			# dprint2 (word, offset, distance, "before modify range")
			# modifyStringsRange(offset, offset+distance, "s", word)
			# dprint2 (goodString(data,word,6),"goodstring", word)
			# if goodString(data,word,5):
			if goodStringWide(data,word,5):
				modifyShByRange(data, offset, offset+distance, "d")
				modifyStringsRange(offset, offset+distance, "s", word)
				total=0			
				v=1
				w=0
			### start
				test=b"\xff"
				while (test == OP_FF):
					dprint2(word, "2binaryToStrCheck", binaryToStr(data[offset+distance:offset+distance+v]))
					test=(data[offset+distance+w:offset+distance+v])
					test2=(data[offset+distance+w:offset+distance+v+1])
					# if test==(OP_FF) and (test2 != inc_esi):
					dprint2 ("test2", len(test2), hex(offset+distance+w), hex(offset+distance+v+1))
					if test==(OP_FF) and (test2 not in FFInstructions):
						dprint2("gots one") # this just counts how many FF's there are that are not part of a more import instruciton'
						total+=1
					v+=1
					w+=1
				dprint2 ("fftotal",total)
				if total > 1:
					modifyShByRange(data, offset, offset+distance+total, "d")
					# modifyStringsRange(offset, offset+distance+total, "s", word)
	except Exception as e:
		print ("Exception")
		print (e)
		print(traceback.format_exc())
		input()
		pass
	###   end
	dprint2 ("end wideStrings")
	# pushStringsTemp.append(tuple((word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength)))
	dprint2("pushmixed")
	for word, offset, wordLength,instructionsLength in pushStringsTemp:
		try:
			dprint2 ("word", word, "starting offset:", hex(offset), "; ending offset:", hex(offset+instructionsLength))
		except:
			word="error"
			dprint2 ("word", word, "starting offset:", hex(offset), "; ending offset:", hex(offset+instructionsLength))
			dprint2 ("pushmixed error")
	distance=0
	for word, offset, wordLength,instructionsLength in pushStringsTemp:
		# offset=ofset-2
		try:
			dprint2 ("word", word, "starting offset", hex(offset), "ending offset", hex(offset+instructionsLength))
		except:
			word="error"
			dprint2 ("pushmixed error2")
		distance=instructionsLength
		dprint2 ("instructionsLength", instructionsLength, type(instructionsLength))
		if goodString(data,word,4):
			dprint2 ("push mixed change", word, hex(offset), hex(offset+distance), hex(len(data)))
			modifyShByRange(data, offset-2, offset+distance, "i") # -2 is a correction
			modifyPushStringsRange(offset, offset+distance, "s", word)
			total=0			
			v=1
			w=0
			test=b"\xff"
			while (test == OP_FF):
				dprint2(word, "pushstrings", binaryToStr(data[offset+distance:offset+distance+v]))
				test=(data[offset+distance+w:offset+distance+v])
				test2=(data[offset+distance+w:offset+distance+v+1])
				dprint2 ("test2", len(test2), hex(offset+distance+w), hex(offset+distance+v+1))
				if test==(OP_FF) and (test2 not in FFInstructions):
					dprint2("gots one PS") # this just counts how many FF's there are that are not part of a more import instruciton'
					total+=1
				v+=1
				w+=1
			dprint2 ("PS fftotal",total)
			if total > 1:
				modifyShByRange(data, offset, offset+distance+total, "d")
				# modifyStringsRange(offset, offset+distance+total, "s", word)


	###$$$$$$$$$$$$$$$$$$4 END STUFF

	current=0
	start=startingAddress
	max=len(shBy.bytesType)-1
	start, current, distance, typeBytes = findRange2(current)
	reset = False
	while current < max:
		if max==current:
			current+=1
		dprint2(binaryToStr(data[start:current]))
		if not typeBytes:
			dprint2 ("AFS: above is data", hex(start))
			if shBy.strings[start]==True:
				xStart, ydis=shBy.stringsStart[start]
				dprint2 (hex(start))
				dprint2 ("AFS: strings ", hex(xStart), hex(ydis), shBy.stringsValue[start])
		start, current, distance, typeBytes = findRange2(current)
		##reset once done - do analysis again to catch any changes 
		if (current) == max and reset != True:
			reset=True
			dprint2 ("reset")
			current=0
	dprint2 (shBy.stringsValue)




def anaFindFF(data):
	# global FFInstructions
	dprint2("anaFindFF")
	OP_FF=b"\xff"
	OP_00=b"\x00"

	offset=0
	maxV=len(data)
	escape=False
	while offset < maxV:
	# for datum in data:
		# dprint2 ("ff:\t"+ str(binaryToStr(data[offset:offset+1])) + "\t" + str(hex(offset)))
		escape=False
		total=0			
		total2=0
		v=1
		w=0
		vv=1
		ww=0
		distance=0
		# dprint2 ("total", total)
		# test=b"\xff"
		test=(data[offset+distance+w:offset+distance+v])
		while (test == OP_FF):
			# dprint2 ("w", hex(w), "v", hex(v), "offset", hex(offset))
			# dprint2( "2binaryToStrCheck", binaryToStr(data[offset+distance:offset+distance+v]))
			test=(data[offset+distance+w:offset+distance+v])
			test2=(data[offset+distance+w:offset+distance+v+1])
			# if test==(OP_FF) and (test2 != inc_esi):
			if test==(OP_FF) and (test2 not in FFInstructions):
				total+=1
				dprint2(" OP_FF, total, gots one", total, hex(offset)) # this just counts how many FF's there are that are not part of a more import instruciton'
				
			v+=1
			w+=1
			escape=True

		test=(data[offset+distance+ww:offset+distance+vv])
		while (test == OP_00):

			dprint2 ("op_00", "ww", hex(w), "vv", hex(v), "offset", hex(offset+distance+ww))
			dprint2( "2binaryToStrCheck", binaryToStr(data[offset+distance+ww:offset+distance+vv]))
			test=(data[offset+distance+ww:offset+distance+vv])
			# if test==(OP_FF) and (test2 != inc_esi):
			if test==(OP_00): #and (test2 not in FFInstructions):
				# dprint2("gots one") # this just counts how many FF's there are that are not part of a more import instruciton'
				total2+=1
				dprint2 ("total2", total2)
				dprint2 (hex(offset), hex(offset+distance+ww))
			vv+=1
			ww+=1
			escape=True
		# dprint2 ("ffcount",total)
		if total > 3:
			dprint2 (total, "ffTotal2")
			modifyShByRange(data, offset, offset+distance+total, "d")
			modifyShBySpecial(data, offset, offset+distance+total, "ff")
			# modifyStringsRange(offset, offset+distance+total, "s", word)
		if total2 > 4:
			dprint2 (total2, "00Total2")
			modifyShByRange(data, offset+4, offset+distance+total2, "d")
			modifyShBySpecial(data, offset+4, offset+distance+total2, "al")

			checkForBad00(data, offset, offset+distance+total2)
			# modifyStringsRange(offset, offset+distance+total, "s", word)
		if escape:
			# dprint2 ("inc offset", escape, hex(offset))
			if total >1 or total2> 1:
				offset+=total
				offset +=total2
			else:
				offset+=1

		if not escape:
			# dprint2 ("inc offset, not", escape, hex(offset))
			offset+=1




# >>> bin(0b1111 ^ 0b1111)
# '0b0'
# >>> bin(0b1111 ^ 0b0000)
# '0b1111'
# >>> bin(0b0000 ^ 0b1111)
# '0b1111'
# >>> bin(0b1010 ^ 0b1111)
# '0b101'

def encodeShellcode_aus(data):
	print ("encodeShellcode")
	global rawData2
	# print (binaryToStr(rawData2))
	shells=""
	for each in rawData2:
		new=each+0x10&255
		new = (new ^ 5)&255
		new=each-0x13&255
		# shells+=str(hex(new)) +" "

		if len(str(hex(new))) % 2 !=0:
			# print ("got one")
			new2=str(hex(new))
			new2="0x0"+new2[2:]
			shells+=new2 + " "
		else:
			shells+=str(hex(new)) + " "
	shells=split0x(shells)
	# print(shells)
	shells=fromhexToBytes(shells)
	print("ENCODE BYTES")
	print (binaryToStr(shells))
	return shells

def encodeShellcodeTesting(data, values):
	print ("encodeShellcode")
	a = values[0]
	b = values[1]
	c = values[2]
	# global rawData2
	# print (binaryToStr(rawData2))
	shells=""
	data = bytearray(data)
	for i in range(len(data)):
		data[i]=(data[i]+a)&255
		data[i] = (data[i]^b)&255
		data[i]=(data[i]-c)&255
		# shells+=str(hex(new)) +" "

	# 	if len(str(hex(new))) % 2 !=0:
	# 		# print ("got one")
	# 		new2=str(hex(new))
	# 		new2="0x0"+new2[2:]
	# 		shells+=new2 + " "
	# 	else:
	# 		shells+=str(hex(new)) + " "
	# shells=split0x(shells)
	# # print(shells)
	# shells=fromhexToBytes(shells)
	print("ENCODE BYTES")
	print (binaryToStr(data))
	return data





def encodeShellcode(data):
	print ("encodeShellcode")
	global rawData2
	# print (binaryToStr(rawData2))
	shells=""
	for each in data:
		new=each^0x3&255 #3
		new = (new + 2)&255 #4
		new= new ^ 0x1&255 #8
		# shells+=str(hex(new)) +" "

		if len(str(hex(new))) % 2 !=0:
			# print ("got one")
			new2=str(hex(new))
			new2="0x0"+new2[2:]
			shells+=new2 + " "
		else:
			shells+=str(hex(new)) + " "
	shells=split0x(shells)
	# print(shells)
	shells=fromhexToBytes(shells)
	# print("ENCODE BYTES")
	print (binaryToStr(shells))
	return shells

def tohexStr(num, bits):
	return hex((num + (1 << bits)) % (1 << bits))\

def tohex(num, bits):
	v= hex((num + (1 << bits)) % (1 << bits))
	return int(v,16)

def truncateTobyte(val):
	print("truncateTobyte", hex(val))
	if (val > 255): # and (val < 65536):  # WORD
		print ("truncating")
		test=str(hex(val))
		if val < (0xfff + 1):
			test=test[3:]
			return int(test,16)
		elif (val > 0xfff ) and (val < (0xffff+1)):
			test=test[4:]
			# print("g 4")
			return int(test,16)
		elif (val > 0xffff ) and (val < (0xfffff+1)):
			test=test[5:]
			# print ("g 5")
			return int(test,16)
		elif (val > 0xfffff ) and (val < (0xffffff+1)):
			test=test[6:]
			# print("g 6")
			return int(test,16)
		elif (val > 0xffffff ) and (val < (0xfffffff+1)):
			test=test[7:]
			# print("g 7")
			return int(test,16)
		elif (val > 0xfffffff ) and (val < (0xffffffff+1)):
			test=test[8:]
			# print("g 8")
			return int(test,16)
		else:
			print ("XOR value too large, error.")
			return None
	return val



def truncateToWord(val):
	print("truncateToWord", hex(val))
	if (val > 255): # and (val < 65536):  # WORD
		print ("truncating")
		test=str(hex(val))
		if (val <= 0xffff ):
			return val
		if (val > 0xffff ) and (val < (0xfffff+1)):
			test=test[3:]
			# print ("gg 3")
			return int(test,16)
		elif (val > 0xfffff ) and (val < (0xffffff+1)):
			test=test[4:]
			# print("gg 4")
			return int(test,16)
		elif (val > 0xffffff ) and (val < (0xfffffff+1)):
			test=test[5:]
			# print("gg 5")
			return int(test,16)
		elif (val > 0xfffffff ) and (val < (0xffffffff+1)):
			test=test[6:]
			# print("gg 6")
			return int(test,16)
		else:
			# pass
			# print ("XOR value too large, error.")
			return None
	return val

def encodeShellcode2(data):
	print ("encodeShellcode2")
	global rawData2
	print (binaryToStr(rawData2))
	shells=""

	encodeBytes=bytearray()
	for each in rawData2:
		new=each^0x55
		print (1, hex(new), (hex(each), 0x55))
		# new=truncateTobyte(new)
		# new=new + 1
		print (2, hex(new))
		new=truncateTobyte(new)
		# if (new > 255):
		# 	test=str(hex(new))
		# 	test=test[3:]
		# 	print ("test", test, int(test,16))
		new= new ^ 0x11
		new=truncateTobyte(new)
		new=new
		print (3, hex(new))
		# if (new > 255):
		# 	test=str(hex(new))
		# 	test=test[3:]
		# 	print ("test2", test, int(test,16))
		print (new, hex(new))
		encodeBytes.append(new)
		# shells+=str(hex(new)) +" "

		if len(str(hex(new))) % 2 !=0:
			print ("got one")
			new2=str(hex(new))
			new2="0x0"+new2[2:]
			shells+=new2 + " "
		else:
			shells+=str(hex(new)) + " "
	shells=split0x(shells)
	print(shells)
	shells=fromhexToBytes(shells)
	print (binaryToStr(shells))

	bytesStr = bytes(encodeBytes)
	print ("\n\n\n\n\nencoder2 new", binaryToStr(bytesStr))
	return bytesStr



def decodeShellcode2(data):
	print ("decodeShellcode2")
	shells=""

	decodedBytes=bytearray()
	for each in data:
		new=each^0x11
		new=truncateTobyte(new)
		# new=new-1
		# new=truncateTobyte(new)
		new=new^0x55
		new=truncateTobyte(new)
		print ("cur", hex(new))
		decodedBytes.append(new)
		# shells+=str(hex(new)) + " "

		if len(str(hex(new))) % 2 !=0:
			print ("got one")
			new2=str(hex(new))
			new2="0x0"+new2[2:]
			shells+=new2 + " "
		else:
			shells+=str(hex(new)) + " "
	shells=split0x(shells)
	print(shells)
	shells=fromhexToBytes(shells)
	print ("shells",binaryToStr(shells))

	bytesStr = bytes(decodedBytes)
	print ("original", binaryToStr(data))
	print ("\n\n\n\n\ndecoder2 new", binaryToStr(bytesStr))
	return bytesStr

def encodeShellcode3(data):
	print ("encodeShellcode3")
	global rawData2
	print (binaryToStr(rawData2))
	encodeBytes=bytearray()
	for each in rawData2:
		new=each
		new= tohex((new^0x55), 8)
		new= tohex((new ^ 0x11), 8)
		new= tohex((new + 0x43), 8)
		new=tohex((~new), 8)
		new=tohex((new<<1), 8)
		encodeBytes.append(new)
	bytesStr = bytes(encodeBytes)
	print ("\n\n\n\n\nencoder3 new", binaryToStr(bytesStr))
	print ("old", binaryToStr(data))
	return bytesStr

def encodeShellcode3(data):
	print ("encodeShellcode3")
	global rawData2
	print (binaryToStr(rawData2))
	encodeBytes=bytearray()
	t=0
	rawData3=rawData2
	for each in rawData3:
		new=each
		new= tohex((new^0x55), 8)
		new= tohex((new ^ 0x11), 8)
		new= tohex((new + 0x43), 8)
		new=tohex((~new), 8)
		new=tohex((new<<1), 8)
		# encodeBytes.append(new)
		rawData3[t]=new
		t+=1

	bytesStr = bytes(encodeBytes)
	print ("\n\n\n\n\nencoder3 new", binaryToStr(bytesStr))
	print ("old", binaryToStr(data))
	return bytesStr

def decodeShellcode3(data, old):
	print ("decodeShellcode3")
	shells=""

	decodedBytes=bytearray()
	for each in data:
		new=each
		new=tohex((new >>1), 8)
		new=tohex((~new), 8)
		new= tohex((new - 0x43), 8)
		new= tohex((new^0x11), 8)
		new= tohex((new^0x55), 8)
		decodedBytes.append(new)

	bytesStr = bytes(decodedBytes)
	print ("original", binaryToStr(data))
	print ("\n\n\n\n\ndecoder2 new", binaryToStr(bytesStr))
	if old == bytesStr:
		print("\n\n\nIT IS THE SAME!!\n")
	return bytesStr
def decodeShellcode(data):
	shells=""
	for each in data:
		new=each^0x11
		new=new-1
		new=new^0x55
		# shells+=str(hex(new)) + " "

		if len(str(hex(new))) % 2 !=0:
			print ("got one")
			new2=str(hex(new))
			new2="0x0"+new2[2:]
			shells+=new2 + " "
		else:
			shells+=str(hex(new)) + " "
	shells=split0x(shells)
	print(shells)
	shells=fromhexToBytes(shells)
	print (binaryToStr(shells))


def encodeShellcodeProto(target,XORval, addVAl, XORval2):
	print ("encodeShellcode ", XORval, addVAl, XORval2)
	print (binaryToStr(target))
	shells=""
	encodedBytes=bytearray()
	for each in target:
		##XOR operation
		new=each^XORval
		new+=addVAl
		new= new ^ XORval2
		# try:
		# 	encodedBytes.append(new)
		# except:

		# 	byte = new.to_bytes(2, 'little')
		# 	encodedBytes.append(byte)
		#FINAL PORTION

		if len(str(hex(new))) % 2 !=0:
			print ("got one")
			new2=str(hex(new))
			new2="0x0"+new2[2:]
			shells+=new2 + " "
		else:
			shells+=str(hex(new)) + " "
	shells=split0x(shells)
	print(shells)
	shells=fromhexToBytes(shells)
	print (binaryToStr(shells))
	print ("new",binaryToStr(encodedBytes))
	return shells


def decodeShellcodeProto(target,XORval, addVAl, XORval2):
	print ("decodeShellcode ", XORval, addVAl, XORval2)
	print (binaryToStr(target))
	shells=""
	for each in target:
		##XOR operation
		new=each^XORval2
		new-=addVAl
		new=new^XORval

		#FINAL PORTION

		if len(str(hex(new))) % 2 !=0:
			print ("got one")
			new2=str(hex(new))
			new2="0x0"+new2[2:]
			shells+=new2 + " "
		else:
			shells+=str(hex(new)) + " "
	shells=split0x(shells)
	print(shells)
	shells=fromhexToBytes(shells)
	print (binaryToStr(shells))
	return shells


def decodeShellcodeXOR(target,XORval):
	print ("decodeShellcode ", XORval)
	print (binaryToStr(target))
	shells=""
	for each in target:
		##XOR operation
		new=each^XORval
		
		#FINAL PORTION

		if len(str(hex(new))) % 2 !=0:
			print ("got one")
			new2=str(hex(new))
			new2="0x0"+new2[2:]
			shells+=new2 + " "
		else:
			shells+=str(hex(new)) + " "
	shells=split0x(shells)
	print(shells)
	shells=fromhexToBytes(shells)
	print (binaryToStr(shells))
	return shells
######
# printFromArrayLiteralToHex(ArrayLiteral)

# printFromhexToBytes(rawHex)
# printFromStringLiteralToBytes(stringLiteral)


# ans=fromArrayLiteralToHex(ArrayLiteral)

# ans2=fromhexToBytes(rawHex)

def splitDirectory(filename):
	# print("filenamesplit", filename)
	array=[]
	
	try:
		array = filename.split("\\")
	except Exception as e:
		print(e)
		# filename=filename.decode()
		# array = filename.split("\\")
		filename="shellcode.txt"
	new = ""
	
	if len(array) ==1:
		relFilename=array[len(array)-1]
		array.pop()
		for word in array:
			new +=  word
		return new+"\\", relFilename
	else:
		filename="shellcode.txt"
		return "", filename


def bramwellstart4():
	readRegs()
	ObtainAndExtractSections()
	getPushStrings(5)
	printStrings()


def bramwellStart():
	global realEAX2
	global realEAX

	# ObtainAndExtractDlls()
	# runIt()
	readRegs()
	showBasicInfo()
	ObtainAndExtractSections()
	print ("basic info")
	print (showBasicInfoSections())


	OP_SPECIAL = b"\x8d\x4c\xff\xe2\x01\xd8\x81\xc6\x34\x12\x00\x00"
	# print(binaryToStrSp(s[3].data2))
	print(binaryToStr(OP_SPECIAL))


	# op_test =b"\x00\x44\x44\x44\x44\x44\x44\x00\x00\x42\x42\x42\x42\x42\x42\x43\x00\x00\x00\x00\x00\x00\x42\x42\x42\x43\x43\x00"
	# findStrings(op_test, 5)

	newBin = open(directory+"outputs\\currentBinary.bin", "wb")
	newBin.write(s[0].data2)

	findStrings(s[0].data2,5)

	# print "start getstrings"

	getStringsOnSections(7)

	getPushStrings(5)
	showAllRegs()
	# op_test2 = b"\x00\x40\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x00"
	# findStringsWide(s[0].data2, 6)
	printStrings()
	# findEvilImports()
	# print(showImports())

	# getDLLs()
	# digDeeper(PE_DLLS)
	# digDeeper2()


	# InMem2()


def bramwellStart2():
	mode=""
	findAllPebSequences(mode)

	printSavedPEB()

def bramwellStart3():

	showBasicInfo()
	ObtainAndExtractSections()
	print ("basic info")
	print (showBasicInfoSections())



	# findStrings(s[0].data2,5)

	getStringsOnSections(7)

	print ("start pushStrings")
	# getPushStrings(5)
	# op_test2 = b"\x00\x40\x00\x41\x00\x42\x00\x43\x00\x44\x00\x45\x00\x00"
	# findStringsWide(s[0].data2, 6)
	printStrings()


	print ("start findEvilImports")
	

	print ("start InMemoryOrderModuleList getDLLs")
	getDLLs()
	digDeeper(PE_DLLS)
	print ("start digDeeper2")
	digDeeper2()

	print ("start InMem2")
	InMem2()
	print ("end InMem2")


	findEvilImports()
	print(showImports())

##### START
def init1():
	global rawData2
	if(not rawHex):
		ObtainAndExtractSections()
		# print (showBasicInfoSections())
	if (rawHex):#(rawBin == False) and not isPe: 
		rawBytes=readShellcode(filename) 
		rawData2=rawBytes


def init2(filename):
	# print("init2")
	global rawData2
	if(not rawHex):
		ObtainAndExtractSections()
		# print (showBasicInfoSections())
	if (rawHex):#(rawBin == False) and not isPe: 
		# print("in rawhex part")
		# print(filename)
		# print(filename[-4:])
		if(filename[-4:] == ".txt"): #don't need to call readShellcode if it is a binary file
			rawData2=readShellcode(filename) 


# Extraction()

# starting()
# AustinStart()
# AustinTesting()


# bramwellStart()
# testing8Start()


# testing8Start()

def saveBinAscii():


	init2(filename)
	# print (binaryToStr(rawData2))
	if not os.path.exists(directory+'bins'):
		os.makedirs(directory+'bins')
	assembly=binaryToText(rawData2)
	newBin = open(directory+"bins\\"+filename[:-4]+".bin", "wb")
	newBin.write(rawData2)
	newBin.close()
	newDis = open(directory+"bins\\ascii-"+filename[:-4]+".txt", "w")
	print (directory+"bins\\ascii-"+filename[:-4]+".txt")
	print (directory+"bins\\"+filename[:-4]+".bin")
	newDis.write(assembly)
	newDis.close()

def bramwellEncodeDecodeWork(shellArg):
	global filename
	global rawData2
		
	if rawBin == False:
		filename=shellArg
		rawBytes=readShellcode(shellArg) 

		rawData2=rawBytes
		# printBytes(rawBytes)
		# print (disHereShell(rawBytes, False, False, "ascii", True))




	print ("SizeRawdata2", len(rawData2))
	rawBytes=rawData2
	print ("rawbytes class", type(rawBytes))
	encoded=encodeShellcode(rawData2)
	old=rawData2
	decoded=decodeShellcode(encoded)

	t=0
	# for x in range (1000):
	# 	encoded=encodeShellcodeProto(rawData2, 32, t, 55)
	# 	t+=1
	print ("new\n\n\n\n")
	r=encodeShellcodeProto(rawData2, 32,2,55)
	r=decodeShellcodeProto(r, 32,2,55)
	rawData2=r
	mode=""
	# findAllPebSequences(mode)
	# printSavedPEB()

	encoded=encodeShellcode2(old)
	decodeShellcode2(encoded)
	# print ("encoding done")
	# testing4=0xff ^ 0x2445
	# testing4=truncateTobyte(testing4)
	# print ("final", hex(testing4))

	new="\b"
	ans=[]
	xorKey=0
	for x in range (0x100):
		print ("checking XOR")
		new=decodeShellcodeXOR(old, x) # 0x73
		rawData2=new
		print (binaryToStr(new))
		mode="decrypt"
		ans =findAllPebSequences(mode)
	
		if ans is not None:
			print ("\nDID IT! XOR Key:", hex(x), ans)
			xorKey=x
			break
			print (ans)


	print ("old-saved", hex(xorKey))
	new=decodeShellcodeXOR(old, xorKey) # 0x73
	print ("rawbytes class", type(new))
	rawData2=new
	mode=""
	findAllPebSequences(mode)
	disassembly=takeBytes(new,0)
	print ("decrypted disassembly")
	print (disassembly)
	if not os.path.exists(directory+'outputs'):
		os.makedirs(directory+'outputs')
	print (directory+"outputs\\"+filename[:-4]+".bin")
	newBin = open(directory+"outputs\\decrypted-"+filename[:-4]+".bin", "wb")
	newBin.write(rawBytes)
	newBin.close()
	newDis = open(directory+"outputs\\decrypted-"+filename[:-4]+"-disassembly.txt", "w")
	newDis.write(disassembly)
	newDis.close()



	### example of shellcode from ML - combining decoder + decoded
	yes=3
	if yes==2:
		disassembly=takeBytes(old,0)
		print ("old disassembly")
		print (disassembly)
		final=old[:0x23] +new[0x23:]
		clearDisassBytClass()
		disassembly=takeBytes(final,0)

		print ("combined")
		print (disassembly)


	##### end example


	yes=5
	if yes==3:

		encoded=encodeShellcode3(old)
		print ("encoding done")
		decoded=decodeShellcode3(encoded,old)
		print ("decoding done")
		clearDisassBytClass()
		disassembly=takeBytes(decoded,0)
		print ("old disassembly")
		print (disassembly)

	# disassembly=takeBytes(rawBytes,0)


	# ### Saving disassembly and .bin
	# print (filename)
	# print ("before split")
	# directory, filename= (splitDirectory(filename))




#operations: enter as a list of characters EX: ["^", "+", "~"]
#findAll: whether or not to stop once a set of values works -- false stops after the first match
#distributed: toggle on distributed computing
#nodesFiles: txt file containing IPs for each node to be used for distributed computing
#cpuCount: auto to use max available, otherwise it can be limited
#outputFile: will spit out a file containing results
#fastMode: only check small portion of the shellcode for peb walking for efficiency. findAll disabled automatically for this one


# TODO:
	# shellEntry
	# clean up abc values DONE 
	# can print order as list, separate each DONE
	# get name of file for the outputFile DONE
	# output file true default(?)
	# save peb offset DONE
	# fix distance in callPopRawHex
	# test inloadorder stuff DONE
	# save peb list as tuple with offset then order of list DONE 
	# fix 64 bit savebasepebwalk and both versions of printsavedpeb
	# save name of register for pushret, same thing w/ tuple DONE 
	# fix syscall saving fs:[0x30] in labelTest.bin --- should only be reg or 0xc0 DONE
	
	# fstenv problem may have to do with - numopsback - back in str creation # DONE? ask tarek how many fstenv should be there.
	# 		saves less than before but this is due to removing duplicates properly I think.
	# 64 bit peb instr only print first line found
	# no 64bit findallpeb # tarek should have this covered
	#issue in uiDiscover w/ peb (see email) # fixed
	# adjustable points in disherepeb # DONE
	# fix 64 bit issue with peb -- 
	# fix callpop issues # FIXED for .exe -- printing still odd? do we want pop spot or call spot? does it matter?
	#		bin issues still exist # DONE
	# add support for int 0x2e and syscall instruction(?) DONE
	# callpop should print starting at call and ending in pop # DONE
	# fix weird issues in pushret -- dont save on retf, and push offset AFTER ret offset saving sometimes # FIXED these two issues -- still some odd printing
	# fix extra printing 
	#in uidiscover -- findallpebseqold is still being used for shellcode -- why? fix for new one to work with both

	#start printing at "address" in printsavedpushret() and have check for when to start
	#check callpop print ending when using .exe and in diff sections - different sections still need to check
	# check 64bit peb logic -- finding only 1 point where it should 2???
	#fix numoperations in ui to be autogenerated
	#check specialencoder5 maybe test list comprehension in decrypt?
	# take a look through the decrypt for globals
	# try using threading instead of parallel
	# try to optimize decoder
	# fix the int/str issues in analyzedecoder

#done
############## output file complete for decrypt stuff -- still needs formatting maybe
############## inloadorder stuff verified working
############## syscall issue with 0x30 fixed
############## fstenv issue fixed
############## disherepeb has global var named pebPoints for adjustment of sensitivity -- email name
############## callpop .exe issue fixed with addresses being wrong
############## decoder stub analysis finds operations and numbers
############## decryption now supports 1 and 2 operations 
############## integration of decoder stub results into searching
############## various decrypt bug fixes
############## fixed testing function for decrypt for accurate
############## 


def decryptShellcode(encodedShell, operations,  findAll = False, fastMode = False, distributed = False, cpuCount = "auto", nodesFile = "nodes.txt", outputFile = True, mode = "default", stubParams = ([],[]), listComp = False):

	global shellEntry
	global decodedBytes	
	global filename

	# print("ENCODED HERE: \n", encodedShell)

	strAdd="new=(new +VALUE) & 255\n" 
	strSub="new=(new -VALUE) & 255\n"
	strXor="new=(new ^ VALUE) & 255\n"
	strNot="new=~(new) & 255\n"
	strRol="new=rol(new,VALUE,8)\n"
	strRor="new=ror(new,VALUE,8)\n"
	strShRight="new=(new << VALUE) & 255\n"

	decodeOps = []
	# print("OPERATIONS:")
	# print(operations)
	for symbol in operations:
		if(symbol == "+"):
			decodeOps.append(strAdd)
		elif(symbol == "-"):
			decodeOps.append(strSub)
		elif(symbol == "^"):
			decodeOps.append(strXor)
		elif(symbol == "~"):
			decodeOps.append(strNot)
		elif(symbol == "rl"):
			decodeOps.append(strRol)
		elif(symbol == "rr"):
			decodeOps.append(strRor)
		elif(symbol == "<"):
			decodeOps.append(strShRight)
		else:
			print("Operation \"" + symbol + "\" not recognized. Returning.")
			return
	opsLen = len(decodeOps)

	# print("DECODEOPS : ", decodeOps)

	if(fastMode):
		originalEncoded = encodedShell
		encodedShell = encodedShell[:40] #opt ion for distance

	if(distributed):
			nodeIPs = []
			with open(nodesFile, 'r') as f:
			    for row in f:
			        nodeIPs.append(row.rstrip('\n'))
			# print("NODES HERE", nodeIPs)
			
			# decodeOps_aus = [strXor, strAdd, strSub]
			# decodeOps = [strXor, strXor, strSub]

			# run decoding func
			decodeInfo = doDistr(decodeOps, encodedShell,2, nodeIPs, findAll = findAll)

			if(fastMode):
				# to get full decrypted shellcode we need to do a single pass with full encodedShell using correct vals we found during fastmode run
				decodeInfo = decodeInfo[0][0]
				# print("TESTD IS =", testd)
				# print("DECODEINFO IS = ", decodeInfo)
				singleVals = decodeInfo[2]
				order = decodeInfo[3]
				# print("GOT SINGLEVALS = ", singleVals)
				# print("GOT ORDER = ", order)

				outputs,earlyFinish,startVals = austinDecode(decodeOps, originalEncoded	, findAll = findAll, mode = "single", starts = singleVals, order = order)
				decodeInfo = outputs
				#parse returned data structure
				

				for item in decodeInfo:
					print("############# DECODED ################")
					try:
						print("Decoded Bytes: ")
						print(binaryToStr(item[0]))
						decodedBytes = item[0]
						print("\n")
					except:
						print(item[0])
					i = 1

					# decodeValues = re.match("^a[0-9]+b[0-9]+c[0-9]+(d[0-9]+)?(e[0-9]+)?", item[1], re.IGNORECASE)
					# if(decodeValues):
						# decodeValues = decodeValues.group()
						# print("DECODE VALUES: ", decodeValues)
					# print("decode presplit: ", item[1])

					print("DECODE VALUES: ")
					decodeValues = item[1].splitlines()
					decodeValues = decodeValues[-1]
					isNum = False
					for item2 in decodeValues:
						if(not isNum):
							print(item2, "= ", end="")
						else:
							print(item2)
						isNum = not isNum
					# print("Decoding Values: ", decodeValues)
					operationOrder = item[3]
					# print("Operations: ", operationOrder)
					print("\nOperations: ")
					for item2 in operationOrder:
						print(item2, end="")
					# for x in item[1:]:
					# 	print("item[",i,"]")
					# 	print(x)
					# 	i +=1
					print("\n\n")
				# return

			#only runs if we didn't do fastmode
			else:
				for item in decodeInfo:
					c = 0
					print("############# DECODED ################")
					for x in item:
						try:
							# x[0] = binaryToStr(x[0])
							# print("Decoded item info:")
							# for i in range(len(x)):
								# print("PRINTING I = ", i, " C = ", c)
								# if(i == 0):
							print("Decoded Bytes: ")
							print(binaryToStr(x[0]))
							decodedBytes = x[0]
							print("\n")
		
							decodeValues = x[1].splitlines()
							print("DECODE VALUES: ")
							decodeValues = decodeValues[-1]
							isNum = False
							for item2 in decodeValues:
								if(not isNum):
									print(item2, "= ", end="")
								else:
									print(item2)
								isNum = not isNum
							operationOrder = x[3]
							# print("Decoding Values: ", decodeValues)
							# print("Operations: ", operationOrder)
							print("\nOperations: ")
							for item2 in operationOrder:
								print(item2, end="")
						except Exception as e:
							print("Error: " + str(e))
							print(x)
						print("\n\n")
						c += 1


					print("\n\n")
				# return

	# non-distributed
	elif(mode == "stub"):
		if(opsLen >= 1 and opsLen <= 5):
			outputs,earlyFinish,startVals = austinDecode(decodeOps, encodedShell, findAll = findAll, cpuCount = cpuCount, mode = "stub", stubParams = stubParams)
			decodeInfo = outputs

			for item in decodeInfo:
					print("############# DECODED ################")
					try:
						print("Decoded Bytes: ")
						print(binaryToStr(item[0]))
						decodedBytes = item[0]
						print("\n")
					except:
						print(item[0])
					i = 1

					# decodeValues = re.match("^a[0-9]+b[0-9]+c[0-9]+(d[0-9]+)?(e[0-9]+)?", item[1], re.IGNORECASE)
					# if(decodeValues):
						# decodeValues = decodeValues.group()
						# print("DECODE VALUES: ", decodeValues)
					decodeValues = item[1].splitlines()
					decodeValues = decodeValues[-1]
					# print("Decoding Values: ", decodeValues)
					print("Decoding Values: ")
					# decodeValues = re.split("\d+", decodeValues)
					decodeValues = re.findall('(\d+|[A-Za-z]+)', decodeValues)
					isNum = False
					for item2 in decodeValues:
						if(not isNum):
							print(item2, "= ", end="")
						else:
							print(item2)
						isNum = not isNum
						# print(item2)
					operationOrder = item[3]
					print("\nOperations: ")
					for item2 in operationOrder:
						print(item2, end="")
					# for x in item[1:]:
					# 	print("item[",i,"]")
					# 	print(x)
					# 	i +=1
					print("\n\n")
	else:
		if(opsLen >= 1 and opsLen <= 5):
			if(listComp):
				outputs,earlyFinish,startVals = austinListComp(decodeOps, encodedShell, findAll = findAll, cpuCount = cpuCount)
				decodeInfo = outputs
			else:
				outputs,earlyFinish,startVals = austinDecode(decodeOps, encodedShell, findAll = findAll, cpuCount = cpuCount)
				decodeInfo = outputs

			# print("DECODEINFO MANUAL ATTEMPT")
			# print("STARTVALS: ",decodeInfo[0][2])
			# print("ORDER: ", decodeInfo[0][3])



			if(fastMode):

				if(len(decodeInfo) > 0):
					# print("DECODEINFO HERE", decodeInfo)
					decodeInfo = decodeInfo[0]

					singleVals = decodeInfo[2]
					order = decodeInfo[3]
					# singleVals = []
					# order = item[3]
					# # print("ORDERHERE")
					# # print(order)
					# for val in item[2]:
					# 	singleVals.append(val)
					#only save the first output of decode -- it won't end early and startvals doesn't matter either
					outputs,earlyFinish,startVals = austinDecode(decodeOps, originalEncoded	, findAll = findAll, mode = "single", starts = singleVals, order = order)
					#parse returned data structure
					decodeInfo = outputs	


			for item in decodeInfo:
					print("############# DECODED ################")
					try:
						print("Decoded Bytes: ")
						print(binaryToStr(item[0]))
						decodedBytes = item[0]
						print("\n")
					except:
						print(item[0])
					i = 1

					# decodeValues = re.match("^a[0-9]+b[0-9]+c[0-9]+(d[0-9]+)?(e[0-9]+)?", item[1], re.IGNORECASE)
					# if(decodeValues):
						# decodeValues = decodeValues.group()
						# print("DECODE VALUES: ", decodeValues)
					decodeValues = item[1].splitlines()
					decodeValues = decodeValues[-1]
					# print("Decoding Values: ", decodeValues)
					print("Decoding Values: ")
					# decodeValues = re.split("\d+", decodeValues)
					decodeValues = re.findall('(\d+|[A-Za-z]+)', decodeValues)
					isNum = False
					for item2 in decodeValues:
						if(not isNum):
							print(item2, "= ", end="")
						else:
							print(item2)
						isNum = not isNum
						# print(item2)
					operationOrder = item[3]
					print("\nOperations: ")
					for item2 in operationOrder:
						print(item2, end="")
					# for x in item[1:]:
					# 	print("item[",i,"]")
					# 	print(x)
					# 	i +=1
					print("\n\n")
			# return			

	

			# for item in decodeInfo:
			# 	print("############# DECODED ################")
			# 	try:
			# 		print("item[0]")
			# 		print(binaryToStr(item[0]))
			# 	except:
			# 		print(item[0])
			# 	i = 1
			# 	for x in item[1:]:
			# 		print("item[",i,"]")
			# 		print(x)
			# 		i +=1
			# 	print("\n\n")
			# return
	if(outputFile and (len(decodeInfo) > 0)):
		disassembly=takeBytes(decodedBytes, shellEntry)
		rawBytes = decodedBytes	
		directory = ".\\"
		print ("decrypted disassembly")
		print (disassembly)
		if not os.path.exists(directory+'outputs'):
			os.makedirs(directory+'outputs')
		print (directory+"outputs\\"+"decoded"+".bin")
		newBin = open(directory+"outputs\\decrypted-"+filename+".bin", "wb")
		newBin.write(rawBytes)
		newBin.close()
		newDis = open(directory+"outputs\\decrypted-"+filename+"-disassembly.txt", "w")
		newDis.write(disassembly)
		newDis.close()

decryptInput = "default"
decryptNumOps = 3
decryptOpTypes = ["^", "-", "+"]
decryptEncodingVals = [3,3,3]
decryptFile = filename
decryptBytes = b""



dFastMode = False
dFindAll = False
dDistr = False
dCPUcount = "auto"
dNodesFile = "nodes.txt"
dOutputFile = False

#initialize decryptFile to be the name of rawData2 arg by default DONE
#same w/ decryptBytes
#if they change inputfile, set rdata2 again
def decryptUI():
	global decodedBytes
	global decryptInput
	global decryptNumOps
	global decryptOpTypes
	global decryptEncodingVals
	global dFastMode
	global dFindAll
	global dDistr
	global dCPUcount
	global dNodesFile
	global dOutputFile
	global decryptBytes	
	global decryptFile
	global filename
	global stubFile

	try:
		decryptFile = filename	
		decryptBytes = readShellcode(decryptFile) 
	except:
		print("Couldn't read command line input file, reverting to default...")
		decryptBytes = b''
		decryptFile = "default.txt"

	while(True):
		printDecryptHelpUI()
		print(cya + "\n Sharem>" + yel + "Decoder> "+res, end="")
		entry = input()

		if(entry == "i"):
			print(cya + "Enter input file: " + res, end="")

			decryptFile = input()
			try:
				decryptBytes = readShellcode(decryptFile)
			except:
				print(red + "Invalid file." + res)
				pass
		elif(entry == "x"):
			return
		

		elif(entry == "o"):
			#TODO: this should match num of operations selected, use that param for a for loop or something instead of current way
			#		separate my spaces OR commas
			print("\n\nVALID OPERATIONS:\n")
			print("+ | add")
			print("- | subtract")
			print("^ | xor")
			print("~ | not")
			print("rl | rotate left")
			print("rr | rotate right")
			print("< | shift right")

			invalid = True
			while(invalid):
				ops = input("\n\nEnter 1-5 operations, separated by commas [E.g. +,-,^]: \n> ")
				ops = ops.split(",")
				decryptOpTypes = ops
				invalid = False
				print("Selected: ")
				for item in decryptOpTypes:
					if(item == "+" ):
						print("add")
					elif(item == "-"):
						print("subtract")
					elif(item == "^"):
						print("xor")
					elif(item == "~"):
						print("not")
					elif(item == "rl"):
						print("rotate left")
					elif(item == "rr"):
						print("rotate right")
					elif(item == "<"):
						print("shift right")
					else:
						print("Invalid selection.")
						invalid = True
				decryptNumOps = len(decryptOpTypes)

		elif(entry == "d"):
			advancedDecryptMenu()
		elif(entry == "h"):
			printDecryptHelpUI()
		elif(entry == "c"):
			decryptEncodingVals	= []
			invalid = True
			while(invalid):
				invalid = False
				try:
					num = int(input("Enter value 1: "))
				except:
					invalid = True
					print("Invalid input.")
			decryptEncodingVals.append(num)

			invalid = True
			while(invalid):
				invalid = False
				try:
					num = int(input("Enter value 2: "))
				except:
					invalid = True
					print("Invalid input.")
			decryptEncodingVals.append(num)

			invalid = True
			while(invalid):
				invalid = False
				try:
					num = int(input("Enter value 3: "))
				except:
					invalid = True
					print("Invalid input.")
			decryptEncodingVals.append(num)


		elif(entry == "e"):
			print("Encoding...")
			decryptBytes = encodeShellcodeTesting(decryptBytes, decryptEncodingVals)

		elif(entry == "s"):
			
			print("Entering decoder stub mode...")
			sameFile = True
			altFile = input("Use different file for decoder stub? y/n: ")
			if(altFile == 'n'):
				stubFile = decryptFile
			else:
				sameFile = False
				stubFile = input("Enter decoder stub filename: ")

			stubEntry = input("Enter entrypoint: ")
			stubEnd = '-1' #leaving it on default (autodetect) for now.
			# stubEnd = input("Enter offset for end of stub: ")
			


			numVals,opTypes,stubEnd = analyzeDecoderStubs(shellArg = stubFile, entryPoint = stubEntry, stubEnd = stubEnd)
			if(sameFile):
				decryptBytes = decryptBytes[stubEnd:]
			print("Got these values from stub: ", numVals)
			print("Got these operations from stub: ", opTypes)
			print("Got stubEnd offset: ", stubEnd)
			input("press enter to proceed...")
			decodedBytes = decryptShellcode(decryptBytes, decryptOpTypes, findAll = dFindAll, fastMode = dFastMode, distributed = dDistr, cpuCount = dCPUcount, nodesFile = dNodesFile, outputFile = dOutputFile, mode = "stub", stubParams = (numVals,opTypes))

		elif(entry == "g"):
			print(cya + " Operations: ", gre + str(decryptOpTypes) + res)
			print(cya + " FindAll: ", gre + str(dFindAll) + res)
			print(cya + " FastMode: ", gre + str(dFastMode) + res)
			print(cya + " Distributed: ", gre + str(dDistr) + res)
			print(cya + " CPUs: ", gre + str(dCPUcount) + res)
			print(cya + " Nodes File: ", yel + str(dNodesFile) + res)
			print(cya + " OutputFile: ", gre + str(dOutputFile) + res)

			confirm = print(yel + "\n Run decryption with these settings "+ res + gre + "[y/n] ? "+res, end="")

			confirm = input()
			if(confirm == "y"):
				decodedBytes = decryptShellcode(decryptBytes, decryptOpTypes, findAll = dFindAll, fastMode = dFastMode, distributed = dDistr, cpuCount = dCPUcount, nodesFile = dNodesFile, outputFile = dOutputFile)
				return

		elif(entry == "l"):
			confirm = print("Run listcomp decryption with these settings?")
			print("Operations: ", decryptOpTypes)
			print("FindAll: ", dFindAll)
			print("FastMode: ", dFastMode)
			print("Distributed: ", dDistr)
			print("CPUs: ", dCPUcount)
			print("Nodes File: ", dNodesFile)
			print("OutputFile: ", dOutputFile)
			confirm = input("y/n? >")
			if(confirm == "y"):
				decodedBytes = decryptShellcode(decryptBytes, decryptOpTypes, findAll = dFindAll, fastMode = dFastMode, distributed = dDistr, cpuCount = dCPUcount, nodesFile = dNodesFile, outputFile = dOutputFile, listComp = True)
				return

		else:
			print("Invalid selection.")



	


def advancedDecryptMenu():
	global dFastMode
	global dFindAll
	global dDistr
	global dCPUcount
	global dNodesFile
	global dOutputFile
	global decryptInput
	global decryptNumOps
	global decryptOpTypes
	global decryptEncodingVals
	global decryptBytes	
	global decryptFile	


	printAdvDecryptHelp()
	while(True):
		print(cya + "\n Sharem>" + yel + "Decoder>" + gre + "Advanced> "+res, end="")
		entry = input()

		if(entry == "fm"):
			dFastMode = not dFastMode
			printAdvDecryptHelp()
		elif(entry == "fa"):
			dFindAll = not dFindAll	
			printAdvDecryptHelp()
		elif(entry == "d"):
			dDistr = not dDistr	
			printAdvDecryptHelp()
		elif(entry == "c"):
			while(True):
				dCPUcount = input("\nEnter amount of CPUs to use (\"auto\" to automatically use max): ")
				if(dCPUcount == "auto"):
					break
				else:
					try:
						dCPUcount = int(dCPUcount)
						if(dCPUcount < 1):
							print("Please enter a positive whole number.")
						else:
							break
					except:
						print("Invalid entry.")
						pass


			printAdvDecryptHelp()
		elif(entry == "n"):
			dNodesFile = input("\nEnter name of nodes config file: ")
			printAdvDecryptHelp()
		elif(entry == "o"):
			dOutputFile	= not dOutputFile
			printAdvDecryptHelp()
		elif(entry == "h"):
			printAdvDecryptHelp()
		elif(entry == "x"):
			return

def printAdvDecryptHelp():
	global dFastMode
	global dFindAll
	global dDistr
	global dCPUcount
	global dNodesFile
	global dOutputFile
	global decryptInput
	global decryptNumOps
	global decryptOpTypes
	global decryptEncodingVals
	global decryptBytes	
	global decryptFile	

	print(yel + "\n\n ....................\n    Advanced menu\n ...................." + res)
	print("\n\n {} - Toggle fast mode [{}]".format(cya + "fm" + res, gre + str(dFastMode)+res))
	print(" {} - Toggle find all [".format(cya + "fa" + res), gre + str(dFindAll)+res, "]")
	print(" {}  - Toggle distributed mode [".format(cya + "d" + res), gre + str(dDistr)+res, "]")
	print(" {}  - Enter CPU count [".format(cya + "c" + res), gre + str(dCPUcount) + res, "]")
	print(" {}  - Enter nodes file for distributed [".format(cya + "n" + res), gre + str(dNodesFile) + res,"]")
	print(" {}  - Toggle separate file output for decrypt function [".format(cya + "o" + res), gre+ str(dOutputFile) + res, "]")
	print(" {}  - Help (show this screen)".format(cya + "h" + res))
	print(" {}  - Exit".format(cya + "x" + res))


def printDecryptHelpUI():
	global dFastMode
	global dFindAll
	global dDistr
	global dCPUcount
	global dNodesFile
	global dOutputFile
	global decryptInput
	global decryptNumOps
	global decryptOpTypes
	global decryptEncodingVals
	global decryptBytes	
	global decryptFile	

	print(yel + "\n\n .....................\n     Decrypt menu\n .....................\n"+ res)
	print(" {} - Set input file {}".format(cya + "i" + res,  gre+"["+decryptFile+"]"+res))

	# print(" {} - Set input file [".format(cya + "i" + res), gre+decryptFile+res,"]")
	# print(" {} - Set number of operations {:>20}".format(cya + "n" + res, gre + "["+str(decryptNumOps) +"]"+ res))
	print(" {} - Set operation types ".format(cya + "o" + res), gre + str(decryptOpTypes)+res)
	print(" {} - Advanced settings menu".format(cya + "d" + res))
	print(" {} - Decoder stub testing".format(cya + "s" + res))

	print(" {} - Go (run decrypt function)".format(cya + "g" + res))
	print(" {} - Help (show this screen)".format(cya + "h" + res))
	print(" {} - Exit".format(cya + "x" + res))

	print(yel + "\n .....................\n     Testing\n .....................\n"+ res)

	# print(yel + "\n+----------------Testing-----------------+\n"+res)
	print(" {} - Apply encoding to input".format(cya + "e" + res))
	print(" {} - Change encoding values ".format(cya + "c" + res), gre + str(decryptEncodingVals)+res)

	

#stubEnd goes to end of file by default
#returns: 1. list of detected values | 2. list of detected operations | 3. offset for the end of the decoder stub portion 
def analyzeDecoderStubs(shellArg="default", entryPoint = 0, stubEnd = -1):
	
	entryPoint = int(entryPoint,0)
	#handle type issues with param
	try:
		stubEnd = int(stubEnd,0)
	except:
		pass
	rawBytes = b''

	if(shellArg == "default"):
		print(yel + " Enter decoder stub file: " + res, end="")
		shellArg = input()

		try:
			rawBytes=readShellcode(shellArg)
		except:
			print(red + " Error: Couldn't read file."+res)
			return -1, -1
	else:
		try:
			rawBytes=readShellcode(shellArg)
		except:
			print(red + " Error: Couldn't read file." + res)
			return -1, -1
	if(stubEnd == -1):
		stubEnd = len(rawBytes)
	CODED3 = rawBytes[entryPoint:stubEnd]

	val =""
	val2 = []
	val3 = []
	val5 =[]

	disString = ""
	numVals = []
	opTypes = []

	for i in cs.disasm(CODED3, entryPoint):

		add4 = hex(int(i.address))
		addb = hex(int(i.address))
		size = hex(int(i.size))
		val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
		# val2.append(val)
		# val3.append(add2)
		disString += val


		# print("checking this one: ", i.op_str)
		numeric = re.search("(0x)?([0-9a-f]+)$", i.op_str, re.IGNORECASE)
		bad = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(int)|(retf)|(db)|(hlt)|(loop)|(ret)|(leave)|(int3)|(insd)|(enter)|(jns))", i.mnemonic, re.M|re.I)
		
		if(numeric and not bad):
			numVals.append(numeric.group())
		elif(bad):
			print("Decoder disasm: ")
			print(disString)
			#return if we hit a jump -- this is probably the loop portion of our stub
			#add size of loop instruction with offset to start of the instruction to get offset to first encoded byte
			return (numVals, opTypes, (int(addb, 16) + int(size, 16)))

		isXor = re.search("^(xor)", i.mnemonic, re.IGNORECASE)
		isAdd = re.search("^(add)|(adc)", i.mnemonic, re.IGNORECASE)
		isSub = re.search("^(sub)|(sbb)", i.mnemonic, re.IGNORECASE)
		isRol = re.search("^(rol)", i.mnemonic, re.IGNORECASE)
		isRor = re.search("^(ror)", i.mnemonic, re.IGNORECASE)
		isNot = re.search("^(not)", i.mnemonic, re.IGNORECASE)
		isShr = re.search("^(shr)", i.mnemonic, re.IGNORECASE)

		if(isXor):
			opTypes.append("^")
		elif(isAdd):
			opTypes.append("+")
		elif(isSub):
			opTypes.append("-")
		elif(isRor):
			opTypes.append("rr")
		elif(isRol):
			opTypes.append("rl")
		elif(isNot):
			opTypes.append("~")
		elif(isShr):
			opTypes.append("<")



	print("Decoder disasm: ")
	print(disString)
	# print("numVals here: ")
	# print(numVals)
	# print("opTypes here: ")
	# print(opTypes)
	return (numVals, opTypes,  (int(addb, 16) + int(size, 16)))

def austinEncodeDecodeWork(shellArg, operations = []):
	#DONE: 	4&5 ops support for everything
	#TODO: 	clean up unused code
	#		make sure outputFile part works
	#		test fastMode
	#		make interface better (options for everything including node IPs, distr or not, etc)
	#		make sure big runs still work with 4/5 for parr and distr
	#		speedtests with bunch of nodes

	if __name__ == "__main__":
		global filename
		global rawData2
		global fastMode	

		testSingle = False
		staticOps = False
		fastMode = False
		outputFile = False
		distrTest = True
		findAll = False

		if rawBin == False:
			filename=shellArg
			rawBytes=readShellcode(shellArg) 

			rawData2=rawBytes
			# printBytes(rawBytes)
			# print (disHereShell(rawBytes, False, False, "ascii", True))


		

		print ("SizeRawdata2", len(rawData2))
		rawBytes=rawData2
		print("NORMAL BYTES")
		print(binaryToStr(rawBytes))
		print ("rawbytes class", type(rawBytes))
		print("RAWDATA2 BEFORE ENCODE IN WORKING FUNC: ", rawData2)
		encoded=encodeShellcode(rawData2)

		print("ENCODED HERE: \n", encoded)

		strAdd="new=(new +VALUE) & 255\n" 
		strSub="new=(new -VALUE) & 255\n"
		strXor="new=(new ^ VALUE) & 255\n"
		strNot="new=~(new) & 255\n"
		strRol="new=rol(new,VALUE,8)\n"
		strRor="new=ror(new,VALUE,8)\n"
		strShRight="new=(new << VALUE) & 255\n"

		decodeOps = []
		print("OPERATIONS:")
		print(operations)
		for symbol in operations:
			if(symbol == "+"):
				decodeOps.append(strAdd)
			elif(symbol == "-"):
				decodeOps.append(strSub)
			elif(symbol == "^"):
				decodeOps.append(strXor)
			elif(symbol == "~"):
				decodeOps.append(strNot)
			elif(symbol == "rl"):
				decodeOps.append(strRol)
			elif(symbol == "rr"):
				decodeOps.append(strRor)
			elif(symbol == "<"):
				decodeOps.append(strShRight)
			else:
				print("Operation \"" + symbol + "\" not recognized. Returning.")
				return
		opsLen = len(decodeOps)
		

	###################### vvv TEST vvv ###################### 

		if(distrTest):
			# decodeOps_aus = [strXor, strAdd, strSub]
			# decodeOps = [strXor, strXor, strSub]
			decodeInfo = doDistr(decodeOps, encoded,2, findAll = findAll)
			for item in decodeInfo:
				print("############# DECODED ################")
				for x in item:
					try:
						# x[0] = binaryToStr(x[0])
						print("Decoded item info:")
						for i in range(len(x)):
							if(i == 0):
								print(binaryToStr(x[i]))
							else:
								print(x[i])
					except Exception as e:
						print("Error: " + str(e))
						print(x)
					print("\n\n")


				print("\n\n")
			return

	######################## END TEST ######################## 

		if(fastMode):
			originalEncoded = encoded
			encoded = encoded[:40] #option for distance

	###################### vvv TEST vvv ###################### 

		if(staticOps):
			decodeOps = [strXor, strSub, strXor]
			# outputs, earlyFinish,startVals =austinDecodeDistributed_new(decodeOps, encoded,5)
			outputs, earlyFinish, startVals =austinDecode(decodeOps, encoded, findAll = findAll)
		else:
	######################## END TEST ########################
			print("OPSLEN = ", opsLen)
			if(opsLen == 3 or opsLen == 4 or opsLen == 5):
				outputs,earlyFinish,startVals = austinDecode(decodeOps, encoded, findAll = findAll)
				decodeInfo = outputs

				for item in decodeInfo:
					print("############# DECODED ################")
					try:
						print(binaryToStr(item[0]))
					except:
						print(item[0])
					for x in item[1:]:
						# print("NEW X")
						print(x)
						# try:
						# 	x = binaryToStr(x)
						# except Exception as e:
						# 	print("Error: " + str(e))
						# 	print(x)
						# print("\n\n")


					print("\n\n")
				return


			elif(opsLen == 4):
				outputs,earlyFinish,startVals = austinDecode(decodeOps, encoded, findAll = findAll)
			elif(opsLen == 5):
				outputs,earlyFinish,startVals = austinDecode(decodeOps, encoded, findAll = findAll)
		# print("FIRST DONE")

		while(earlyFinish):
			# print("IN EARLY")
			# print("outputs here")
			# print(len(outputs))

			# print("DECODED HERE")
			for item in outputs:

				# if(binaryToStr(item[0]) == binaryToStr(rawBytes)):
					# print("\n\ngot a match")
					# print(item[1])
					# print(binaryToStr(item[0]))


				# print ("checking decoded")
				new=item[0]
				rawData2=new
				# print (binaryToStr(new))
				if(fastMode):
					rawData2 = rawData2[:40]
				mode="decrypt"
				ans =findAllPebSequences(mode)

				if ans is not None:
					print ("\n\n**************DID IT!*******************")
					print(item[1])
					if(fastMode):
						singleVals = []
						order = item[3]
						# print("ORDERHERE")
						# print(order)
						for val in item[2]:
							singleVals.append(val)
						#only save the first output of decode -- it won't end early and startvals doesn't matter either
						if(staticOps):
							singleOut = austinDecode(decodeOps, originalEncoded, "single", singleVals, order)[0]

						else:
							if(opsLen == 3):
								singleOut = austinDecode(decodeOps, originalEncoded, singleVals, order, "single")[0]
							elif(opsLen == 4):
								singleOut = austinDecode(decodeOps[0], decodeOps[1], decodeOps[2], decodeOps[3], originalEncoded, singleVals, order, "single")[0]
							elif(opsLen == 5):
								singleOut = austinDecode(decodeOps[0], decodeOps[1], decodeOps[2], decodeOps[3], decodeOps[4], originalEncoded, singleVals, order, "single")[0]
						new = singleOut[0] #this would normally be the list of different decoded shellcode attempts. here, the list only has one item.
						new = new[0] #grab said first item
						# print("SINGLEOUT")
						# print(singleOut)
						# print("NEWHERE")
						# print(new)
						rawData2 = new
						
						# print("EACHHERE")
						# print(item[3])
						# print("CONVERTED SINGLE HERE")
						# print(binaryToStr(rawData2))

						disassembly=takeBytes(new,0)
					if(outputFile):
						print ("decrypted disassembly")
						print (disassembly)
						if not os.path.exists(directory+'outputs'):
							os.makedirs(directory+'outputs')
						print (directory+"outputs\\"+filename[:-4]+".bin")
						newBin = open(directory+"outputs\\decrypted-"+filename[:-4]+".bin", "wb")
						newBin.write(rawBytes)
						newBin.close()
						newDis = open(directory+"outputs\\decrypted-"+filename[:-4]+"-disassembly.txt", "w")
						newDis.write(disassembly)
						newDis.close()
					

			outputs = []
			if(staticOps):
				outputs, earlyFinish, startVals = austinDecode(decodeOps, encoded, "continue", startVals, findAll = findAll)
			else:
				if(opsLen == 3):
					outputs,earlyFinish,startVals = austinDecode(decodeOps, encoded, "continue", startVals, findAll = findAll)
				elif(opsLen == 4):
					outputs,earlyFinish,startVals = austinDecode(decodeOps[0], decodeOps[1], decodeOps[2], decodeOps[3], encoded, startVals, "continue")
				elif(opsLen == 5):
					outputs,earlyFinish,startVals = austinDecode(decodeOps[0], decodeOps[1], decodeOps[2], decodeOps[3], decodeOps[4], encoded, startVals, "continue")





		# UNCOMMENT BELOW ###########################  !!!!!!!!!!!!!!!!!!!!!!!!

		#print("SEQ SECTION OUTPUTS HERE")
		#print(outputs)

		for item in outputs:

			# if(binaryToStr(item[0]) == binaryToStr(rawBytes)):
			# 	print("\n\ngot a match")
			# 	print(item[1])
			# 	print(binaryToStr(item[0]))


			# print ("checking decoded")
			new=item[0]
			rawData2=new
			if(fastMode):
					rawData2 = rawData2[:40]
			# print (binaryToStr(new))
			mode="decrypt"
			ans =findAllPebSequences(mode)

			if ans is not None:
				print ("\n\n**************DID IT!*******************")
				print(item[1])
				if(fastMode):
						singleVals = []
						order = item[3]
						# print("ORDERHERE")
						# print(order)
						for val in item[2]:
							singleVals.append(val)
						#only save the first output of decode -- it won't end early and startvals doesn't matter either
						if(staticOps):
							singleOut = austinDecode(decodeOps, originalEncoded, "single", singleVals, order)[0]
						else:
							if(opsLen == 3):
								singleOut = austinDecode(decodeOps[0], decodeOps[1], decodeOps[2], originalEncoded, singleVals, order, "single")[0]
							elif(opsLen == 4):
								singleOut = austinDecode(decodeOps[0], decodeOps[1], decodeOps[2], decodeOps[3], originalEncoded, singleVals, order, "single")[0]
							elif(opsLen == 5):
								singleOut = austinDecode(decodeOps[0], decodeOps[1], decodeOps[2], decodeOps[3], decodeOps[4], originalEncoded, singleVals, order, "single")[0]
						new = singleOut[0] #this would normally be the list of different decoded shellcode attempts. here, the list only has one item.
						new = new[0] #grab said first item
						# print("SINGLEOUT")
						# print(singleOut)
						# print("NEWHERE")
						# print(new)
						rawData2 = new
						
						# print("EACHHERE")
						# print(item[3])
						# print("CONVERTED SINGLE HERE")
						# print(binaryToStr(rawData2))
				if(outputFile):
					disassembly=takeBytes(new,0)
					print ("decrypted disassembly")
					print (disassembly)
					if not os.path.exists(directory+'outputs'):
						os.makedirs(directory+'outputs')
					print (directory+"outputs\\"+filename[:-4]+".bin")
					newBin = open(directory+"outputs\\decrypted-"+filename[:-4]+".bin", "wb")
					newBin.write(rawBytes)
					newBin.close()
					newDis = open(directory+"outputs\\decrypted-"+filename[:-4]+"-disassembly.txt", "w")
					newDis.write(disassembly)
					newDis.close()


		# for x in range (len(decoded)):
		# 	if(decoded[x] == encoded):
		# 		print("\n\ngot a match")
		# 		print(decodedInfo[x])


			# print ("checking decoded")
			# new=decoded[x]
			# rawData2=new
			# print (binaryToStr(new))
			# mode="decrypt"
			# ans =findAllPebSequences(mode)
		
			# if ans is not None:
			# 	print ("\nDID IT!")
			# 	xorKey=x
			# 	break
			# 	print (ans)


		# t=0
		# # for x in range (1000):
		# # 	encoded=encodeShellcodeProto(rawData2, 32, t, 55)
		# # 	t+=1
		# print ("new\n\n\n\n")
		# r=encodeShellcodeProto(rawData2, 32,2,55)
		# r=decodeShellcodeProto(r, 32,2,55)
		# rawData2=r
		# mode=""
		# # findAllPebSequences(mode)
		# # printSavedPEB()

		# encoded=encodeShellcode2(old)
		# decodeShellcode2(encoded)
		# # print ("encoding done")
		# # testing4=0xff ^ 0x2445
		# # testing4=truncateTobyte(testing4)
		# # print ("final", hex(testing4))

		# new="\b"
		# ans=[]
		# xorKey=0
		# for x in range (0x100):
		# 	print ("checking XOR")
		# 	new=decodeShellcodeXOR(old, x) # 0x73
		# 	rawData2=new
		# 	print (binaryToStr(new))
		# 	mode="decrypt"
		# 	ans =findAllPebSequences(mode)
		
		# 	if ans is not None:
		# 		print ("\nDID IT! XOR Key:", hex(x), ans)
		# 		xorKey=x
		# 		break
		# 		print (ans)


		# print ("old-saved", hex(xorKey))
		# new=decodeShellcodeXOR(old, xorKey) # 0x73
		# print ("rawbytes class", type(new))
		# rawData2=new
		# mode=""
		# findAllPebSequences(mode)
		# disassembly=takeBytes(new,0)
		# print ("decrypted disassembly")
		# print (disassembly)
		# if not os.path.exists(directory+'outputs'):
		# 	os.makedirs(directory+'outputs')
		# print (directory+"outputs\\"+filename[:-4]+".bin")
		# newBin = open(directory+"outputs\\decrypted-"+filename[:-4]+".bin", "wb")
		# newBin.write(rawBytes)
		# newBin.close()
		# newDis = open(directory+"outputs\\decrypted-"+filename[:-4]+"-disassembly.txt", "w")
		# newDis.write(disassembly)
		# newDis.close()



		# ### example of shellcode from ML - combining decoder + decoded
		# yes=3
		# if yes==2:
		# 	disassembly=takeBytes(old,0)
		# 	print ("old disassembly")
		# 	print (disassembly)
		# 	final=old[:0x23] +new[0x23:]
		# 	clearDisassBytClass()
		# 	disassembly=takeBytes(final,0)

		# 	print ("combined")
		# 	print (disassembly)


		# ##### end example


		# yes=5
		# if yes==3:

		# 	encoded=encodeShellcode3(old)
		# 	print ("encoding done")
		# 	decoded=decodeShellcode3(encoded,old)
		# 	print ("decoding done")
		# 	clearDisassBytClass()
		# 	disassembly=takeBytes(decoded,0)
		# 	print ("old disassembly")
		# 	print (disassembly)

		# # disassembly=takeBytes(rawBytes,0)


		# # ### Saving disassembly and .bin
		# # print (filename)
		# # print ("before split")
		# # directory, filename= (splitDirectory(filename))




def shellDisassemblyStart(shellArg):
	global filename
	global rawData2
	#print("File name in shellDisassemblyStart ", filename)
	filename=shellArg
	if not rawBin:
		rawBytes=readShellcode(shellArg) 
		rawData2=rawBytes
	mode=""
	
	# printBytes(rawBytes)
	# print (disHereShell(rawBytes, False, False, "ascii", True))
	# print ("SizeRawdata2", len(rawData2)) 
	rawBytes=rawData2
	findAllPebSequences(mode)
	print ("rawbytes class", type(rawBytes))
	disassembly=takeBytes(rawBytes,0)
	
	print ("final output:\n" + disassembly)
	printAllShBy()
	printAllShByStrings()

	### Saving disassembly and .bin
	print (filename)
	print ("before split")
	directory, filename= (splitDirectory(filename))
	directory = ""
	print (directory)
	print (filename)
	directory=""

	if not os.path.exists(directory+'outputs'):
		os.makedirs(directory+'outputs')
	print (directory+"outputs\\"+filename[:-4]+".bin")
	newBin = open(directory+"outputs\\"+filename[:-4]+".bin", "wb")
	newBin.write(rawBytes)
	newBin.close()
	newDis = open(directory+"outputs\\"+filename[:-4]+"-disassembly.txt", "w")
	newDis.write(disassembly)
	newDis.close()
	# binaryToText(rawBytes)



def shellDisassemblyInit(shellArg):
	global filename
	global rawData2
	global gDisassemblyText
	global save_bin_file
	global shellEntry

	startAddress=shellEntry

	# print("ShellArg ----> ", shellArg)
	# input()
	# print ()

	# filename=shellArg
	# rawBytes=readShellcode(shellArg) 
	# print("Shell Disassembly", shellArg.hex())
	# input()
	# rawData2=rawBytes
	# # # printBytes(rawBytes)
	# print (disHereShell(rawBytes, False, False, "ascii", True))
	# print ("SizeRawdata2", len(rawData2))
	# rawBytes=rawData2
	# print ("rawbytes class", type(rawBytes))

	# filename=shellArg
	# print ("size shellArg", len(shellArg) )
	mode=""

	findAllPebSequences(mode)
	findAllCallpop(shellArg, "noSec")
	findAllPushRet(shellArg, "noSec")
	findAllFSTENV(shellArg, "noSec")
	getSyscallRawHex(startAddress, 8, "noSec", shellArg)
	getHeavenRawHex(startAddress, 8, "noSec", shellArg)

	print ("find peb results:")
	printSavedPEB()
	#parameterize
	disassembly=takeBytes(shellArg,startAddress)
	   # main one
	gDisassemblyText = disassembly

	
	printAllShBy()
	printAllShByStrings()
	### Saving disassembly and .bin

	# print (filename)

	# print ("before split")
	# print("File name: ", filename)
	# print("Full path: ", filename.split("/"))
	# input()
	# directory, filename= (splitDirectory(filename))
	dirPath = '\\'.join(filename.split("\\")[:-1])
	filename = os.path.basename(filename)

	directory = ""
	# print (directory)
	# print (filename)
	directory=""

	bytesOutput=shellArg
	# import os
	if not os.path.exists(directory+'disassembly'):
		os.makedirs(directory+'disassembly')
	# print (directory+"outputs\\"+filename[:-4]+".bin")
	# newBin = open(directory+"outputs\\"+filename[:-4]+".bin", "wb")
	# newBin.write(rawBytes)
	# newBin.close()
	txtDis = open(directory+"disassembly\\"+filename[:-4]+"-disassembly.txt", "w")
	if save_bin_file:
		binDis = open(directory+"disassembly\\"+filename[:-4]+"-disassembly.bin", "wb")
		binDis.write(bytesOutput)
		binDis.close()


	txtDis.write(disassembly)

	txtDis.close()
	# print("After shell disas init ", shellArg.hex())
	# input()
	# binaryToText(rawBytes)



def bramwellDisassembly():
	global shellcode4
	global filename
	testing="shellcodes\\testing.txt"
	print ("numargs" , numArgs)
	if numArgs==1:
		shellcode4='shellcode4.txt'
		# filename=shellcode4
	shellDisassemblyStart(filename)
	# shellDisassemblyStart(shellcode4)


def disassembleSubMenu():

	#disToggleMenu()
	global rawData2
	global bDisassemblyFound
	while True:
		print(cya + " Sharem>" + yel + "Disasm> " + res, end="")
		choice = input()
		choice = choice.lower()
		if choice == "":
			continue
		elif choice == "x":
			#print("\nGoing back to main menu..\n")
			break
		elif choice == "m":
			modifyShByRangeUser()
		elif choice == "h" or choice == "help":
			disToggleMenu(toggList)
			disassembleUiMenu(shellEntry)
		elif choice == "g":

			disassembleToggles()
		elif choice == "e":
			changeEntryPoint()
		elif choice == "j":
			raw_shellcode = binaryToText(rawData2, "json")
			Text2Json(raw_shellcode)
		elif choice == "z":
			if rawHex:
				if bfindShell:
					dontPrint()
					shellDisassemblyInit(rawData2)
					allowPrint()
					if gDisassemblyText == "":
						print("\nUnable to find any disassembly.\n")
					else:
						print("\nFound disassembly instructions.\n")
						bDisassemblyFound = True
			else:
				print("\nThis option is for shellcode only")
			

			#print(gDisassemblyText)

		else:
			print("Invalid input")

def checkHex(s):
	for ch in s:
		if ((ch < '0' or ch > '9') and (ch < 'a'  or ch > 'f')):
			return False

	return True

def changeEntryPoint():
	global shellEntry
	result = False
	while result != True:
		entrypoint = input("Enter entry point as hex: ")
		entrypoint = entrypoint.lower()
		if "0x" in entrypoint:
			entrypoint = entrypoint.split("0x")[1]
		result = checkHex(entrypoint)
		if not result:
			print("Please enter a valid hex address")
	shellEntry = int(entrypoint, 16)

	print("\nEntry point: " + str(hex(shellEntry))+"\n")



def disassembleToggles():
	global bPushRet
	global bdeobfCode
	global bfindString
	global bComments
	global bfindShell


	#toggList = {'string':True, 
	#			'deobfcode':False}

	print("Enter input delimited by commas or spaces. (x to exit)")
	print("\tE.g. s, d, p\n")
	while True:
		togg = input("Sharem>Disasm> ")
		togg = togg.lower()
		if togg == "x":
			break
		elif togg =="h":
			print("Enter input delimited by commas or spaces. (x to exit)\n")
			continue
		togg = togg.replace(",", " ")
		togg = re.sub(' +', ' ', togg)
		toggOptions = togg.split(" ")


		for t in toggOptions:
			if t == "s":
				temp = toggList['findString']
				if temp == True:
					toggList['findString'] = False

				else:
					toggList['findString'] = True
					bfindString = True
					
			elif t == "d":
				if bdeobfCode == False:
					bdeobfCode = True
					
				else:
					bdeobfCode = False

				temp = toggList['deobfCode']
				if temp == True:
					toggList['deobfCode'] = False
				else:
					toggList['deobfCode'] = True
			elif t == "c":

				temp = toggList['comments']
				if temp == True:
					toggList['comments'] = False
					bComments = False
					

				else:
					toggList['comments'] = True
					
					bComments = True
					
			elif t == "p":
				temp = toggList['findShell']
				if temp == True:
					toggList['findShell'] = False
				else:
					toggList['findShell'] = True
					bfindShell = True



		disToggleMenu(toggList)
		return
		

	

def bramwellDisassembly2():
	# global shellcode4
	# global filename
	global rawData2
	global shellEntry
	# print ("rawData2 a", len(rawData2))
	# print (shellEntry)
	shellDisassemblyInit(rawData2)  #shellcode data, start address

def initSysCallSelect(): #Initialize our list of syscalls to print
	global syscallSelection
	global syscallPrintBit
	global shellBit
	global bit32
	global os
	syscallPrintBit = 64
	syscallSelection = []

	#Read our syscall file to find OS versions
	if(bit32):
		with open('nt64.csv', 'r') as file:
				nt64Csv = csv.reader(file)
				versions = next(nt64Csv)
				versions = versions[1:]
	else:
		with open('nt.csv', 'r') as file:
				nt32Csv = csv.reader(file)
				versions = next(nt32Csv)
				versions = versions[1:]



	#Loop through the list of versions
	for version in versions:
		obj = OSVersion()
		t = 0
		code = "new"

		#Get the version from the list
		for char in version:
			if char == '(':
				break
			t+=1
		w = 0
		for char in version:
			if char == ')':
				break
			w+=1
		name = version[t+1:w]
		#Get the category from the list
		category = version[0:t-1]

		#Setup our category's opcode
		if(category == "Windows XP"):
			code = "xp"
		elif(category == "Windows Vista"):
			code = "v"
		elif(category == "Windows 7"):
			code = "w7"
		elif(category == "Windows 8"):
			code = "w8"
		elif(category == "Windows 10"):
			code = "w10"
		elif(category == "Windows Server 2003"):
			code = "s3"
		elif(category == "Windows Server 2008"):
			code = "s8"
		elif(category == "Windows Server 2012"):
			code = "s12"
		elif(category == "Windows NT"):
			code = "nt"
		elif(category == "Windows 2000"):
			code = "w20"

		#See if our category exists in the list
		categoryFound = False
		for osv in syscallSelection:
			if osv.category == category:
				categoryFound = True
				break

		#If not, put it in
		if not categoryFound:
			obj._init_(category, category, False, code)
			syscallSelection.append(obj)
			obj = OSVersion()
		if category == "Windows 10":
			name = "release " + name

		#Set the code (no way around hardcoded here)
		#Defaults to "new" otherwise
		#For selecting
		if(version == "Windows XP (SP1)"):
			code = "xp1"
		elif(version == "Windows XP (SP2)"):
			code = "xp2"
		elif(version == "Windows Vista (SP0)"):
			code = "v0"
		elif(version == "Windows Vista (SP1)"):
			code = "v1"
		elif(version == "Windows Vista (SP2)"):
			code = "v2"
		elif(version == "Windows 7 (SP0)"):
			code = "w70"
		elif(version == "Windows 7 (SP1)"):
			code = "w71"
		elif(version == "Windows 8 (8.0)"):
			code = "w80"
		elif(version == "Windows 8 (8.1)"):
			code = "w81"
		elif(version == "Windows 10 (1507)"):
			code = "r0"
		elif(version == "Windows 10 (1511)"):
			code = "r1"
		elif(version == "Windows 10 (1607)"):
			code = "r2"
		elif(version == "Windows 10 (1703)"):
			code = "r3"
		elif(version == "Windows 10 (1709)"):
			code = "r4"
		elif(version == "Windows 10 (1803)"):
			code = "r5"
		elif(version == "Windows 10 (1809)"):
			code = "r6"
		elif(version == "Windows 10 (1903)"):
			code = "r7"
		elif(version == "Windows 10 (1909)"):
			code = "r8"
		elif(version == "Windows 10 (2004)"):
			code = "r9"
		elif(version == "Windows 10 (20H2)"):
			code = "r10"
		elif(version == "Windows Server 2003 (SP0)"):
			code = "s30"
		elif(version == "Windows Server 2003 (SP2)"):
			code = "s32"
		elif(version == "Windows Server 2003 (R2)"):
			code = "s3r"
		elif(version == "Windows Server 2003 (R2 SP2)"):
			code = "s3r2"
		elif(version == "Windows Server 2008 (SP0)"):
			code = "s80"
		elif(version == "Windows Server 2008 (SP2)"):
			code = "s82"
		elif(version == "Windows Server 2008 (R2)"):
			code = "s8r"
		elif(version == "Windows Server 2008 (R2 SP1)"):
			code = "s8r1"
		elif(version == "Windows Server 2012 (SP0)"):
			code = "s120"
		elif(version == "Windows Server 2012 (R2)"):
			code = "s12r"
		elif(version == "Windows 2000 (SP0)"):
			code = "w200"
		elif(version == "Windows 2000 (SP1)"):
			code = "w201"
		elif(version == "Windows 2000 (SP2)"):
			code = "w202"
		elif(version == "Windows 2000 (SP3)"):
			code = "w203"
		elif(version == "Windows 2000 (SP4)"):
			code = "w204"
		elif(version == "Windows NT (SP3 TS)"):
			code = "nt3t"
		elif(version == "Windows NT (SP3)"):
			code = "nt3"
		elif(version == "Windows NT (SP4)"):
			code = "nt4"
		elif(version == "Windows NT (SP5)"):
			code = "nt5"
		elif(version == "Windows NT (SP6)"):
			code = "nt6"
		obj._init_(name, category, False, code)
		syscallSelection.append(obj)

	#Add our multiselect objects
	# print("########## OS initsyscall ###########", os)

	category = "server Column multiselect variables"
	obj = OSVersion()
	obj._init_("All releases", category, False, "all")
	syscallSelection.append(obj)
	obj = OSVersion()
	obj._init_("Only latest releases", category, False, "l")
	syscallSelection.append(obj)
	obj = OSVersion()
	obj._init_("Current Windows 10", category, False, "d")
	syscallSelection.append(obj)
	obj = OSVersion()
	obj._init_("Current Windows 10 and Windows 7", category, False, "D")
	syscallSelection.append(obj)

	#Set Win10 Default
	t = len(syscallSelection) - 1
	for osv in syscallSelection:
		if(syscallSelection[t].category == "Windows 10"):
			syscallSelection[t].toggle = False
			break
		t-=1

def modConf():
	global bPushRet
	global bCallPop
	global bFstenv
	global bSyscall
	global bHeaven
	global bPEB
	global bDisassembly
	global pebPresent
	global pebPoints
	global configOptions
	global p2screen
	global bytesForward
	global bytesBack
	global linesForward
	global linesBack
	global bPushStackStrings
	global bWideCharStrings
	global bAsciiStrings
	global syscallSelection
	global dFastMode
	global dFindAll
	global dDistr
	global dCPUcount
	global dNodesFile
	global dOutputFile
	global decryptOpTypes
	global decryptFile
	global stubFile
	global sameFile
	global stubEntry
	global stubEnd

	listofStrings = ['pushret', 'callpop', 'fstenv', 'syscall', 'heaven', 'peb', 'disassembly', 'pebpresent', 'bit32','max_bytes_forward','max_bytes_backward','max_lines_forward', 'max_lines_backward','print_to_screen', 'push_stack_strings', 'ascii_strings', 'wide_char_strings', 'fast_mode', 'find_all', 'dist_mode', 'cpu_count', 'nodes_file', 'output_file', 'dec_operation_type', 'decrypt_file', 'stub_file', 'use_same_file', 'stub_entry_point', 'stub_end', 'shellEntry']
	listofBools = [bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, pebPresent, bit32, bytesForward, bytesBack, linesForward, linesBack,p2screen, bPushStackStrings, bAsciiStrings, bWideCharStrings, dFastMode, dFindAll, dDistr, dCPUcount, dNodesFile, dOutputFile, decryptOpTypes, decryptFile, stubFile, sameFile, stubEntry, stubEnd, shellEntry]

	listofSyscalls = []
	for osv in syscallSelection:
		if osv.toggle == True:
			listofSyscalls.append(osv.code)
	listofStrings.append('selected_syscalls')
	listofBools.append(listofSyscalls)
	for booli, boolStr in zip(listofBools, listofStrings):

		configOptions[boolStr] = booli






def readConf():
	global bPushRet
	global bCallPop
	global bFstenv
	global bSyscall
	global bHeaven
	global bPEB
	global bDisassembly
	global pebPresent
	global pebPoints
	global bit32
	global p2screen
	global bytesForward
	global bytesBack
	global linesForward
	global linesBack
	global bPushStackStrings
	global bWideCharStrings
	global bAsciiStrings
	global syscallSelection
	global shellBit
	global print_style
	global dFastMode
	global dFindAll
	global dDistr
	global dCPUcount
	global dNodesFile
	global dOutputFile
	global decryptOpTypes
	global decryptFile
	global stubFile
	global sameFile
	global stubEntry
	global stubEnd
	global save_bin_file
	global shellEntry
	# global os

	con = Configuration(conFile)
	conr = con.readConf()
	initSysCallSelect()

	
	startupBool = conr.getboolean('SHAREM STARTUP','startup_enabled')
	
	

# Reading decryption variables from config

	dFastMode = conr.getboolean('SHAREM DECRYPT','fast_mode')
	dFindAll = conr.getboolean('SHAREM DECRYPT','find_all')
	dDistr = conr.getboolean('SHAREM DECRYPT','dist_mode')
	dCPUcount = int(conr['SHAREM DECRYPT']['cpu_count'])
	dNodesFile = conr['SHAREM DECRYPT']['nodes_file']
	if not (os.path.exists(dNodesFile)):
		print(red +"\n\nConfig file Error:", yel + dNodesFile + res, red + "doesn't exist!!" + res)
	dOutputFile = conr['SHAREM DECRYPT']['output_file']
	decryptOpTypes = conr['SHAREM DECRYPT']['dec_operation_type']
	try:
		 decryptOpTypes = ast.literal_eval(decryptOpTypes)
	except:
		print(yel + "The value of", red + decryptOpTypes, yel + "is not correct or malformed!!"+ res)
		sys.exit()
	decryptFile = conr['SHAREM DECRYPT']['decrypt_file']
	if not (os.path.exists(decryptFile)):
		print(red +"\n\nConfig file Error:", yel + decryptFile + res, red + "doesn't exist!!" + res)
	stubFile = conr['SHAREM DECRYPT']['stub_file']
	if not (os.path.exists(stubFile)):
		print(red +"\n\nConfig file Error:", yel + stubFile + res, red + "doesn't exist!!" + res)

	sameFile = conr.getboolean('SHAREM DECRYPT','use_same_file')
	stubEntry = int(conr['SHAREM DECRYPT']['stub_entry_point'])
	stubEnd = int(conr['SHAREM DECRYPT']['stub_end'])


	# print(dFastMode, dFindAll, dDistr, dCPUcount, dNodesFile, dOutputFile, decryptOpTypes, decryptFile, stubFile, sameFile, stubEntry, stubEnd)





#===============================================


	bPushRet= conr.getboolean('SHAREM SEARCH','pushret')
	bCallPop= conr.getboolean('SHAREM SEARCH','callpop')
	bFstenv= conr.getboolean('SHAREM SEARCH','fstenv')
	bSyscall= conr.getboolean('SHAREM SEARCH','syscall')
	bHeaven= conr.getboolean('SHAREM SEARCH','heaven')
	bPEB= conr.getboolean('SHAREM SEARCH','peb')
	save_bin_file = conr.getboolean('SHAREM SEARCH','save_bin_file')
	bDisassembly= conr.getboolean('SHAREM SEARCH','disassembly')
	pebPresent = conr.getboolean('SHAREM SEARCH','pebpresent')
	if rawHex and not bit32_argparse:
		bit32 = conr.getboolean('SHAREM SEARCH','bit32')

		if bit32:
			shellBit = 32
		else:
			shellBit = 64



	p2screen =  conr.getboolean('SHAREM SEARCH','print_to_screen')
	bPushStackStrings =  conr.getboolean('SHAREM STRINGS','push_stack_strings')

	bAsciiStrings =  conr.getboolean('SHAREM STRINGS','ascii_strings')
	bWideCharStrings =  conr.getboolean('SHAREM STRINGS','wide_char_strings')

	# malformed = "print('malformed')"
	pebPoints = int(conr['SHAREM SEARCH']['pebpoints'])
	shellEntry = int(conr['SHAREM SEARCH']['shellEntry'])
	bytesForward = int(conr['SHAREM SEARCH']['max_bytes_forward'])
	bytesBack = int(conr['SHAREM SEARCH']['max_lines_backward'])
	linesForward = int(conr['SHAREM SEARCH']['max_lines_forward'])
	linesBack = int(conr['SHAREM SEARCH']['max_lines_backward'])
	print_style = conr['SHAREM SEARCH']['print_format_style']
	if print_style != "right" and print_style != "left":
		print(yel + "\n\nError: format style in config file is not correct."+ res, red + print_style+res , yel +"<-- should be either right, or left." +res)
		sys.exit()
	list_of_syscalls = str(conr['SHAREM SYSCALLS']['selected_syscalls'])

	try:
		list_of_syscalls = ast.literal_eval(list_of_syscalls)
		if(type(list_of_syscalls) != list):
			print("Error:", list_of_syscalls, "<-- this should be a list.")
		# print(list_of_syscalls)

	except:
		print(yel + "The value of", red + list_of_syscalls, yel + "is not correct or malformed!!"+ res)
		sys.exit()
	# list_of_syscalls = list_of_syscalls[1:-1].replace(" ", "").replace("'", "").split(",")

	for selected in list_of_syscalls:
		for osv in syscallSelection:
			if osv.code == selected:
				osv.toggle = True

	if not startupBool:
		return False
	else:
		return True
			# print(os.code, os.name, os.category, os.toggle)



def isFound():
	global bPushRetFound
	global bCallPopFound
	global bDisassemblyFound
	global bFstenvFound
	global bSyscallFound
	global bPEBFound


	if bPushRetFound:
		print('Pushret instructions found')
	else:
		print('Pushret instructions Not found')

	if bCallPopFound:
		print('Callpop instructions found')
	else:
		print('Callpop instructions Not found')


	if bDisassemblyFound:
		print('Disassembly found')
	else:
		print('Disassembly Not found')

	if bFstenvFound:
		print('Fstenv instructions found')
	else:
		print('Fstenv instructions Not found')

	if bSyscallFound:
		print('Syscall instructions found')
	else:
		print('Syscall instructions Not found')

	if bPEBFound:
		print('Peb instructions found')
	else:
		print('Peb instructions Not found')




def startupPrint():
	global bPushRetFound
	global bCallPopFound
	global bDisassemblyFound
	global bFstenvFound
	global bSyscallFound
	global bHeavenFound
	global bPEBFound
	global rawData2
	global bAsciiStrings
	global bWideCharStrings
	global bPushStackStrings
	global bStringsFound
	global bTempWideString
	global bPushStringsFound
	global minStrLen
	global bpAll
	global bpPushRet
	global bpFstenv
	global bpSyscall
	global bpHeaven
	global bpPEB
	global bpCallPop
	global bpStrings
	global bpPushStrings
	global bpEvilImports
	global bpModules



	bPushRetFound = bCallPopFound = bDisassemblyFound = bFstenvFound = bHeavenFound = bPEBFound = bStringsFound = bTempWideString = bPushStringsFound = False
	minStrLen = 7

	l_of_strings = ["Finding Strings..", "Finding unicode strings..", "Finding pushstack strings..","Searching for disassembly..", "Searching for Fstenv instructions..", "Searching for pushret instructions..", "Searching for callpop instructions..", "Searching for heaven's gate instructions..", "Searching for syscall instructions..", "Searching for peb instructions.."]

	max_len = get_max_length(l_of_strings)
	if rawHex:

		print(cya + "\n\n Finding shellcode Strings\n\n" + res)
		
		if bAsciiStrings and bStringsFound:
			print(yel + " Finding Strings..", end="")
			findStrings(rawData2,3)
			curLen = len("Finding Strings..")

			if (len(stringsTemp) > 0):
				# print(gre + "[Found]".rjust(max_len) + res)
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))
				# print({>30}).format(gre +"[Found]"+res)
				bStringsFound = True
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print(red + "[Not Found]".rjust(max_len) + res)


		if bWideCharStrings and not bTempWideString:
			print(yel + " Finding unicode strings..", end="")

			findStringsWide(rawData2,3)
			curLen = len("Finding unicode strings..")

			if (len(stringsTempWide) > 0):
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print(gre + "[Found]".rjust(max_len) + res)
				bTempWideString = True

			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print(red + "[Not Found]".rjust(max_len) + res)

		if bPushStackStrings and not bPushStringsFound:
			print(yel + " Finding pushstack strings..", end="")

			findPushAsciiMixed(rawData2,3)
			curLen = len("Finding pushstack strings..")
			if (len(pushStringsTemp) > 0):
				
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print(gre + "[Found]".rjust(max_len) + res)
				bPushStringsFound = True
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print(red + "[Not Found]".rjust(max_len) + res)



		print(cya + "\n\n Finding Shellcode instructions\n\n" + res)
		if bDisassembly and not bDisassemblyFound:
			print(yel + " Searching for disassembly..", end="")
			curLen = len("Searching for disassembly..")

			dontPrint()
			shellDisassemblyInit(rawData2)
			allowPrint()
			colorama.init()
			if gDisassemblyText != "":
				bDisassemblyFound = True
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(30) + res)
			else:
				print("\n")
		if bFstenv and not bFstenvFound:
			print(yel + " Searching for Fstenv instructions..", end="")
			curLen = len("Searching for Fstenv instructions..")

			findAllFSTENV(rawData2, 'noSec')
			if len(m[o].save_FSTENV_info) > 0:
				bFstenvFound = True
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(22) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(22) + res)


		if bPushRet and not bPushRetFound:
			print(yel + " Searching for pushret instructions..", end="")
			curLen = len("Searching for pushret instructions..")

			if bit32:
				findAllPushRet(rawData2, 'noSec')
			else: 
				findAllPushRet64(rawData2, 'noSec')

			if len(m[o].save_PushRet_info) > 0:
				bPushRetFound = True
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(21) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(21) + res)



		if bCallPop and not bCallPopFound:
			print(yel + " Searching for callpop instructions..", end="")
			curLen = len("Searching for callpop instructions..")
			if bit32:
				findAllCallpop(rawData2, 'noSec')
			else: 
				findAllCallpop64(rawData2, 'noSec')
			if len(m[o].save_Callpop_info) > 0:
				bCallPopFound = True
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(21) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(21) + res)



		if bHeaven and not bHeavenFound:
			print(yel + " Searching for heaven's gate instructions..", end="")
			curLen = len("Searching for heaven's gate instructions..")
			getHeavenRawHex(0, linesBack, 'noSec', rawData2)
			if len(m[o].save_Heaven_info) > 0:
				bHeavenFound = True
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + "[Found]".rjust(19) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(19) + res)



		if bSyscall and not bSyscallFound:
			print(yel + " Searching for syscall instructions..", end="")
			curLen = len("Searching for syscall instructions..")

			getSyscallRawHex(0, linesBack, 'noSec', rawData2)
			if len(m[o].save_Egg_info) > 0:
				bSyscallFound = True
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(21) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(21) + res)



		if bPEB and not bPEBFound:
			print(yel + " Searching for peb instructions..", end="")
			curLen = len("Searching for peb instructions..")

			findAllPebSequences("normal", rawData2, 'noSec')
			if len(m[o].save_PEB_info) > 0:
				bPEBFound = True
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(25) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(25) + res)

# PE Sections
	else:
		print(cya + "\n\n Finding PE Strings\n\n" + res)

		t=0
		for sec in pe.sections:
			if bAsciiStrings and not bStringsFound:
				findStrings(s[t].data2,minStrLen)
			if bWideCharStrings and not bTempWideString:
				findStringsWide(s[t].data2,minStrLen)
			if bPushStackStrings and not bPushStringsFound:
				findPushAsciiMixed(s[t].data2,5, t)
			t+=1
		t = 0
		bTempWideString = False
			#print("{:>{x}}".format("[Found]    ", x=15+(maxLen-curLen)))
		for sec in pe.sections:
			if (len(s[t].Strings) > 0):
				bStringsFound = True
			
			if (len(s[t].wideStrings) > 0):
				bTempWideString = True
				
			if (len(s[t].pushStrings) > 0):
				bPushStringsFound = True

			t+=1

		curLen = len("Finding strings..")
		print(yel + " Finding strings.."+res, end="")

		if bStringsFound:

			# curLen = len("Finding strings..")
			print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

			# print(yel + "Finding strings.."+gre+"[Found]".rjust(40) + res)
		else:
			print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

			# print(yel + "Finding strings.."+red+"[Not Found]".rjust(40) + res)

		curLen = len("Finding unicode strings..")
		print(yel + " Finding unicode strings.."+res, end="")

		if bTempWideString:
			print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

			# print(yel + "Finding unicode strings.."+gre+"[Found]".rjust(32) + res)
		else:
			print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

			# print(yel + "Finding unicode strings.."+red+"[Not Found]".rjust(32) + res)


		curLen = len("Finding pushstack strings..")
		print(yel + " Finding pushstack strings.."+res, end="")
		if bPushStringsFound:
			print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

			# print(yel + "Finding pushstack strings.."+gre+"[Found]".rjust(34) + res)
		else:
			print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

			# print(yel + "Finding pushstack strings.."+red+"[Not Found]".rjust(34) + res)



		print(cya + "\n\nFinding PE instructions\n\n" + res)



		if bFstenv and not bFstenvFound:
			print(yel + " Searching for Fstenv instructions..", end="")
			curLen = len("Searching for Fstenv instructions..")
			for secNum in range(len(s)):
				data2 = s[secNum].data2

				findAllFSTENV(data2, secNum)
			for i in s:
				if (len(i.save_FSTENV_info) > 0):
					bFstenvFound = True
			if bFstenvFound:
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(26) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(26) + res)

		if bPushRet and not bPushRetFound:
			print(yel + " Searching for pushret instructions..", end="")
			curLen = len("Searching for pushret instructions..")

			for secNum in range(len(s)):
				data2 = s[secNum].data2
				if bit32:
					findAllPushRet(data2, secNum)
				else:
					# pass
					findAllPushRet64(data2, secNum)

			for i in s:
				if (len(i.save_PushRet_info) > 0):
					bPushRetFound = True
			if bPushRetFound:
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(21) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(21) + res)

		if bCallPop and not bCallPopFound:
			print(yel + " Searching for callpop instructions..", end="")
			curLen = len("Searching for callpop instructions..")

			for secNum in range(len(s)):
				data2 = s[secNum].data2
				if bit32:
					findAllCallpop(data2, secNum)

				else:
					findAllCallpop64(data2, secNum)
			for i in s:
				if (len(i.save_Callpop_info) > 0):
					bCallPopFound = True
			if bCallPopFound:
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(25) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(25) + res)

		if bHeaven and not bHeavenFound:
			print(yel + " Searching for heaven's gate instructions..", end="")
			curLen = len("Searching for heaven's gate instructions..")

			for secNum in range(len(s)):
				data2 = s[secNum].data2
				findAllHeaven(data2, secNum)
			for i in s:
				if (len(i.save_Heaven_info) > 0):
					bHeavenFound = True
			if bHeavenFound:
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(15) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(15) + res)

		if bSyscall and not bSyscallFound:
			print(yel + " Searching for syscall instructions..", end="")
			curLen = len("Searching for syscall instructions..")

			for secNum in range(len(s)):
				data2 = s[secNum].data2
				for match in EGGHUNT.values():
					optimized_find(20, match, secNum, data2, "disHereSyscall")
			for i in s:
				if (len(i.save_Egg_info) > 0):
					bSyscallFound = True
			if bSyscallFound:
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(21) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(21) + res)

		if bPEB and not bPEBFound:
			print(yel + " Searching for peb instructions..", end="")
			curLen = len("Searching for peb instructions..")

			if shellBit == 64:
						
				data2 = 0
				secNum = 0
				#npeb
				findAllPebSequences("normal", data2, secNum)
			else:
				secNum = 0
				data2 = 0
				findAllPebSequences("normal", data2, secNum)
			for i in s:
				if (len(i.save_PEB_info) > 0):
					bPEBFound = True

			if bPEBFound:
				print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))

				# print( gre + '[Found]'.rjust(25) + res)
			else:
				print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

				# print( red + '[Not Found]'.rjust(29) + res)



	#Saving data
	bpPushRet = bpSyscall = bpHeaven = bpFstenv = bpPEB = bpStrings = bpCallPop = bpEvilImports = bpModules = True
	outputData = generateOutputData()
	print(cya + "\n\nSaving to Json.." , end='')
	printToJson(False, outputData)
	print(gre + 'Done' + res)
	print(cya + "\nSaving to Text.." , end='')
	printToText(outputData)
	print(gre + 'Done\n\n' + res)

def saveConf(con):
	try:
		con.changeConf(configOptions)
		con.save()
		print(yel + "Configuration has been Saved.\n" + res)
	except Exception as e:
		print(yel + "Could not save configuration." + res, e)

    	



def ui(): #UI menu loop
	global maxDistance #Max distance that a callpop can call
	#Disassembly option variables
	global linesForward
	global linesBack
	global bytesForward
	global bytesBack
	global bit32
	global shellBit
	#Booleans to find shellcode instructions
	global bPushRet
	global bFstenv
	global bSyscall
	global bHeaven
	global bPEB
	global bCallPop
	global bStrings
	global bEvilImports
	global bDisassembly
	global bModules
	global bShellcodeAll
	#Booleans to print shellcode instructions
	global bpPushRet
	global bpFstenv
	global bpSyscall
	global bpHeaven
	global bpPEB
	global bpCallPop
	global bpEvilImports
	global bpModules
	global bpAll
	global bpStrings
	global bpPushStrings
	global syscallSelection #Array of osversions for syscall
	global showDisassembly  #Show dis on syscall submenu
	#Booleans to determine if instructions already found
	global bPushRetFound
	global bDisassemblyFound
	global bFstenvFound
	global bSyscallFound
	global bHeavenFound
	global bPEBFound
	global bCallPopFound
	global bStringsFound
	global bPushStringsFound
	global bModulesFound
	global bEvilImportsFound
	#Booleans to determine what types of strings we find
	global bAsciiStrings
	global bWideCharStrings
	global bPushStackStrings
	global bExportAll #whether or not we export everything or just selections
	global minStrLen #Min len of strings to search for
	global modulesMode #For option selection in uiModulesSubMenu()
	global pushStringRegisters #The register setup for pushString emulation
	global stringsDeeper #Do a deeper search for goodstrings
	global stringReadability #What % of string should be letters, numbers, or spaces
	global checkGoodStrings #Whether or not we check if a string is good
	global shellEntry
	global configOptions
	# bit32 = True
	# bPushRet = True
	# bFstenv = True
	# bSyscall = True
	# bHeaven = True
	# bPEB = True
	# bCallPop = True
	bStrings = True
	bModules = True
	bEvilImports = True
	bpPushRet = True
	bpFstenv = True
	bpSyscall = True
	bpHeaven = True
	bpPEB = True
	bpCallPop = True
	bpStrings = True
	bpPushStrings = True
	bpEvilImports = True
	bpModules = True
	bPushRetFound = False
	bFstenvFound = False
	bSyscallFound = False
	bHeavenFound = False
	bPEBFound = False
	bCallPopFound = False
	bStringsFound = False
	bPushStringsFound = False
	bModulesFound = False
	bEvilImportsFound = False
	# bAsciiStrings = True
	# bWideCharStrings = True
	# bPushStackStrings = True
	bPushStrings = True
	bShellcodeAll = True
	bExportAll = True
	bpAll = True
	stringsDeeper = False
	checkGoodStrings = True
	minStrLen = 7
	maxDistance = 15
	modulesMode = 3
	pushStringRegisters = 'unset'
	showDisassembly = True
	stringReadability = .65
	# print("----> bit", bit32)

	# print("OS ---> ui", os)

	#need this for selecting and printing syscalls
	# initSysCallSelect()

	x = ""
	con = Configuration(conFile)
	



	# 	for item in section.save_PushRet_info:
	# for item in m[o].save_PushRet_info:
	print("Bits: ", shellBit)
	showOptions(shellBit)
	while x != "e":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(cya + " Sharem> " + res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "x":
				print("\nExiting program.\n")
				break
			
			elif userIN[0:1] == "h":
				showOptions(shellBit)
			
			elif userIN[0:1] == "D":
				if not rawHex:
					print("\nThis option is for shellcode only.\n")
				else:
					shellDisassemblyInit(rawData2)
					bramwellStart2()
			elif userIN[0:1] == "d":
				disToggleMenu()
				disassembleUiMenu(shellEntry)
				disassembleSubMenu()
			elif userIN[0:1] == "s":	#We want to find
				uiDiscover()

			elif(re.match("^b$", userIN)):
				decryptUI()
			elif userIN[0:1] == "a":	#Set bits
				uiBits()
				initSysCallSelect()
				# print("\nReturning to main menu.\n")

			elif(re.match("^c$", userIN)):
				# print(configOptions)
				# if configOptions:
				modConf()
				saveConf(con)
					# configData = ",".join(configOptions)
					# print(configData)
					
			elif userIN[0:1] == "u":
				Text2Json(rawData2)
			elif userIN[0:1] == "p":	#We want to print
				uiPrint()
				# print("\nReturning to main menu.\n")
			elif userIN[0:1] == "i":
				if(rawHex):
					# info = showBasicInfo()
					print("No PE file selected.\n")
				else:
					info = showBasicInfoSections()
					print(info)
			elif userIN[0:1] == "k":
				uiFindStrings()
				# print("\nReturning to main menu.\n")
			elif userIN[0:1] == "j":
				uiShellcodeStrings()
				# print("\nReturning to main menu.\n")
			elif userIN[0:1] == "e":
				uiFindImports()
			elif userIN[0:1] == "q":
				findAll()
			elif userIN[0:1] == "o":
				saveBinAscii()
			elif userIN[0:1] == "m":	
				uiModulesSubMenu()
				# print("\nReturning to main menu.\n")
			else:
				print("\nInvalid input.\n")

		except Exception as e:
			print (e)
			print(traceback.format_exc())
			print ("exception")
			pass

def uiBits():	#Change the bit mode
	global bit32
	global shellBit
	print("\n ........\n Bit Mode\n ........")
	printBitMenu()
	bitIN = input("> ")
	y = ""
	while True:				#Loop until we break
		if bitIN == "32":
			bit32 = True
			shellBit = 32
			print("\nBits set to 32\n")
			break
		elif bitIN == "64":
			bit32 = False
			shellBit = 64
			print("\nBits set to 64\n")
			break
		elif bitIN == "x":
			break
		else:
			print("Invalid input...\n")
		print("\n ........\nBit Mode\n ........")
		bitIN = input("> ")

def get_max_length(list_of_strings):

	max_len =-1
	for i in list_of_strings:
		if (len(i) > max_len):
			max_len = len(i)
			res = len(i)
	return res



def uiDiscover(): 	#Discover shellcode instructions
	global bPushRet
	global bFstenv
	global bSyscall
	global bHeaven
	global bPEB
	global bCallPop
	global bShellcodeAll
	global bPushRetFound
	global bDisassembly
	global bDisassemblyFound
	global bFstenvFound
	global bSyscallFound
	global bHeavenFound
	global bPEBFound
	global bCallPopFound
	global minStrLen
	global elapsed_time
	global configOptions

	print(yel + "\n ...........................\n Find Shellcode Instructions\n ..........................." + res)
	instructionsMenu(bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, bShellcodeAll)

	x = ""
	while True:			#Loop until we break on x
		print(yel + " Sharem>" + res, end="")
		print(cya + "Shell> " + res, end="")
		listIN = input()
		if(re.match("^s$", listIN, re.IGNORECASE)):
			uiDiscoverTechMenu()

		elif(re.match("^h$", listIN, re.IGNORECASE)):
			instructionsMenu(bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, bShellcodeAll)
		elif(re.match("^all$", listIN, re.IGNORECASE)):
			bPushRet = True
			bFstenv = True
			bSyscall = True
			bHeaven = True
			bPEB = True
			bCallPop = True
			bDisassembly = True
			bShellcodeAll = True
			print("\n")
			print("Shellcode selections changed.\n")
			displayCurrentInstructions(bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, bShellcodeAll)
		elif(re.match("^c$", listIN)):
			bPushRet = False
			bFstenv = False
			bSyscall = False
			bHeaven = False
			bPEB = False
			bCallPop = False
			bDisassembly = False
			bShellcodeAll = False
			print("\n")
			print("Shellcode selections changed.\n")
			displayCurrentInstructions(bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, bShellcodeAll)
		elif(re.match("^r$", listIN)):
			clearInstructions()
			print("Found shellcode instructions cleared.\n")
		


		elif(re.match("^z$", listIN, re.IGNORECASE)):

			list_of_labels = ["Searching for disassembly", "Searching for fstenv instructions", "Searching for push ret instructions", "Searching for call pop instructions", "Searching for heaven's gate instructions", "Searching for windows syscall instructions", "Searching for PEB walking instructions"]
			maxLen = get_max_length(list_of_labels)
		#For each boolean set, we execute the finding functions
			if bDisassembly and not bDisassemblyFound:
				curLen = len("Searching for disassembly")
				print(cya + " Searching for disassembly..." + res, end="", flush=True)

				if rawHex:

					# print("Bit: ", bit32)
					if bit32:
						start = time.time()
						dontPrint()
						shellDisassemblyInit(rawData2)
						allowPrint()
						colorama.init()
						end = time.time()
						elapsed_time += end - start
				if gDisassemblyText != "":
					print("{:>{x}}[{}]".format("", gre + "Found"+res, x=15+(maxLen-curLen)))
					bDisassemblyFound = True
				else:
					print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))

					#print("{:>{x}}".format("[Not Found]", x=15+(maxLen-curLen)))
				
			if bFstenv and not bFstenvFound:

				curLen = len("Searching for fstenv instructions")
				print(cya + " Searching for fstenv instructions..."+res, end="", flush=True)
				start = time.time()
				if (rawHex):
					findAllFSTENV(rawData2, 'noSec')

				else:
					for secNum in range(len(s)):
						data2 = s[secNum].data2
						findAllFSTENV(data2, secNum)
				for i in s:
					if (len(i.save_FSTENV_info) > 0):
						bFstenvFound = True


				if rawHex:
					if len(m[o].save_FSTENV_info) > 0:
						bFstenvFound = True
				
				if(bFstenvFound):
					print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))

					#print("{:>{x}}".format("[Found]    ", x=15+(maxlen-curLen)))
				else:
					print("{:>{x}}[{}]".format("", red + "Not Found"+ res, x=15+(maxLen-curLen)))

					#print("{:>{x}}".format("[Not Found]", x=15+(maxLen-curLen)))
				end = time.time()
				elapsed_time += end - start
				# print("After fstenv search", rawData2.hex())
						
			if bPushRet and not bPushRetFound:

				start = time.time()
				curLen = len("Searching for push ret instructions")
				print(cya + " Searching for push ret instructions..." + res, end="", flush=True)
				if (rawHex):
					if bit32:
						findAllPushRet(rawData2, 'noSec')
					else: 
						findAllPushRet64(rawData2, 'noSec')

				else:
					for secNum in range(len(s)):
						data2 = s[secNum].data2
						if bit32:
							findAllPushRet(data2, secNum)
						else:
							# pass
							findAllPushRet64(data2, secNum)
				for i in s:
					if (len(i.save_PushRet_info) > 0):
						bPushRetFound = True

				if rawHex:
					if len(m[o].save_PushRet_info) > 0:

						bPushRetFound = True
				if(bPushRetFound):
					print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
				else:
					print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
				end = time.time()
				# print("After pushret search", rawData2.hex())

			if bCallPop and not bCallPopFound:
				start = time.time()
				curLen = len("Searching for call pop instructions")
				print(cya + " Searching for call pop instructions..."+res, end="", flush=True)
				if (rawHex):
					if bit32:
						findAllCallpop(rawData2, 'noSec')
					else: 
						findAllCallpop64(rawData2, 'noSec')

				else:
					for secNum in range(len(s)):
						data2 = s[secNum].data2
						if bit32:
							findAllCallpop(data2, secNum)
						else:
							findAllCallpop64(data2, secNum)
				for i in s:
					if (len(i.save_Callpop_info) > 0):
						bCallPopFound = True
				if  rawHex:
					if len(m[o].save_Callpop_info) > 0:
						bCallPopFound = True
				if(bCallPopFound):
					print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
				else:
					print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
				end = time.time()
				elapsed_time += end-start
			if bHeaven and not bHeavenFound:

				start = time.time()
				curLen = len("Searching for heaven's gate instructions")
				print(cya + " Searching for heaven's gate instructions..."+ res, end="", flush=True)
				if (rawHex):
					getHeavenRawHex(0, linesBack, 'noSec', rawData2)

				else:
					for secNum in range(len(s)):
							data2 = s[secNum].data2
							findAllHeaven(data2, secNum)
				for i in s:
					if (len(i.save_Heaven_info) > 0):
						bHeavenFound = True
				if  rawHex:
					if len(m[o].save_Heaven_info) > 0:
						bHeavenFound = True
				if(bHeavenFound):
					print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
				else:
					print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
				end = time.time()
				elapsed_time += end - start

			if bSyscall and not bSyscallFound:

				start = time.time()
				curLen = len("Searching for windows syscall instructions")
				print(cya + " Searching for windows syscall instructions..."+res, end="", flush=True)
				if (rawHex):
					# getSyscallPE(20, 20, match, 'noSec', rawData2)
					getSyscallRawHex(0, linesBack, 'noSec', rawData2)

				else:
					for secNum in range(len(s)):
							data2 = s[secNum].data2
							for match in EGGHUNT.values():
								optimized_find(20, match, secNum, data2, "disHereSyscall")
								# getSyscallPE(20, 20, match, secNum, data2)
				for i in s:
					if (len(i.save_Egg_info) > 0):
						bSyscallFound = True

				if  rawHex:
					if len(m[o].save_Egg_info) > 0:
						bSyscallFound = True
				if(bSyscallFound):
					print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
				else:
					print("{:>{x}}[{}]".format("", red + "Not Found"+ res, x=15+(maxLen-curLen)))
				end = time.time()
				elapsed_time += end - start

			if bPEB and not bPEBFound:

				start = time.time()
				curLen = len("Searching for PEB walking instructions")
				print(cya + " Searching for PEB walking instructions..."+res, end="", flush=True)
				if (rawHex):
					# findAllPebSequences_old(rawData2, 'noSec')
					findAllPebSequences("normal", rawData2, 'noSec')
					# findAllPebSequences(rawData2, 0, "decrypt")
				else:
					if shellBit == 64:
						
					# for secNum in range(len(s)):
						# data2 = s[secNum].data2
						data2 = 0
						secNum = 0
						#npeb
						findAllPebSequences("normal", data2, secNum)
					else:
						# for secNum in range(len(s)):
							# data2 = s[secNum].data2
						secNum = 0
						data2 = 0
						findAllPebSequences("normal", data2, secNum)
							# findAllPebSequences_old(data2, secNum)
				for i in s:
					if (len(i.save_PEB_info) > 0):
						bPEBFound = True
				if rawHex:
					if len(m[o].save_PEB_info) > 0:
						bPEBFound = True
				if(bPEBFound):
					print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
				else:
					print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
				end = time.time()
				elapsed_time += end - start
				# pass

		



			print(".........................\n")
			print(yel + " Search for shellcode instructions completed.\n"+res)

			print(yel + " Elapsed time:" +res, format(elapsed_time, ".5f"))
			
			# print("Exiting discovery menu\n")
			# break
		elif(re.match("^x$", listIN, re.IGNORECASE)):
			# print("\nReturning to main menu.\n")
			break
		elif(re.match("^g$", listIN, re.IGNORECASE)):
			print(" Enter input delimited by commas or spaces. (x to exit)\n\tE.g. pr, pb, hg\n")
			while x != 'e':
				instructionSelectIn = input("> ")
				if(re.match("^x$", instructionSelectIn, re.IGNORECASE)):
					break
				bPR = re.search("( |,|^)PR( |,|$)", instructionSelectIn, re.IGNORECASE)
				bFE = re.search("( |,|^)FE( |,|$)", instructionSelectIn, re.IGNORECASE)
				bCP = re.search("( |,|^)CP( |,|$)", instructionSelectIn, re.IGNORECASE)
				bSy = re.search("( |,|^)Sy( |,|$)", instructionSelectIn, re.IGNORECASE)
				bPB = re.search("( |,|^)PB( |,|$)", instructionSelectIn, re.IGNORECASE)
				bHG = re.search("( |,|^)HG( |,|$)", instructionSelectIn, re.IGNORECASE)
				bFD = re.search("( |,|^)FD( |,|$)", instructionSelectIn, re.IGNORECASE)

				bShellcodeAll = re.search("( |,|^)all( |,|$)", instructionSelectIn, re.IGNORECASE)
				print("\n")
				if bPR:
					bPushRet = False if bPushRet else True
				if bFE:
					bFstenv = False if bFstenv else True
				if bCP:
					bCallPop = False if bCallPop else True
				if bSy:
					bSyscall = False if bSyscall else True
				if bPB:
					bPEB = False if bPEB else True
				if bHG:
					bHeaven = False if bHeaven else True
				if bFD:
					bDisassembly = False if bDisassembly else True
				if bShellcodeAll:
					bPushRet= bPR = True
					bFstenv= bFE = True
					bCallPop= bCP = True
					bSyscall= bSy = True
					bPEB= bPB = True
					bHeaven= bHG = True
					bDisassembly= bFD = True
				if  bPushRet and bFstenv and bCallPop and bSyscall and bPEB and bHeaven and bDisassembly:
					bShellcodeAll = True
				if(bPR or bFE or bCP or bSy or bPB or bHG or bFD):
					print(" Shellcode selections changed.\n")
					displayCurrentInstructions(bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, bShellcodeAll)
					break
				else:
					print(" Input not recognized.\n")
		else:
			print("\n Input not recognized.\n")

		# modConf()

		# print("\n...........................\nFind Shellcode Instructions\n...........................")
		# 

		# listIN = input("> ")
		
def uiDiscoverTechMenu():	#Tech settings for shellcode discovery
	global linesForward
	global linesBack
	global bytesForward
	global bytesBack
	global minStrLen
	x=""
	print("\n ..................\n Technical Settings\n ..................\n")
	techSettingsMenu(bytesForward, bytesBack, linesForward, linesBack)
	
	while True:
		print(yel+ " Sharem>" + cya + "Shell>" + res+ red + "Tech> " + res, end="")
		techIN = input()
		if(techIN[0:1] == "x"):
			# print("Returning to find shellcode instructions menu.\n")
			break
		elif(techIN[0:1] == "g"):
			uiGlobalTechMenu()
			# print("Returning to tech settings submenu.\n")
		elif(techIN[0:1] == "c"):
			uiCPTechMenu()
			# print("Returning to tech settings submenu.\n")
		elif(techIN[0:1] == "p"):
			uiPebTechMenu()
			# print("Returning to tech settings submenu.\n")
		elif(techIN[0:1] == "k"):
			print("\nEnter minimum string length (current: " , minStrLen, ")\n")
			while x!='e':
				stLenIn = input("> ")
				if(re.match("^x$", stLenIn, re.IGNORECASE)):
					break
				elif not (re.match("^[0-9]*$", stLenIn, re.IGNORECASE)):
					print("Input not recognized\n")
				else:
					minStrLen = int(stLenIn)
					break
			print("\nMinimum string length changed to", minStrLen, ".\n")
			# print("\nReturning to tech settings submenu.\n")
		elif(techIN[0:1] == "h"):
			techSettingsMenu(bytesForward, bytesBack, linesForward, linesBack)
		else:
			print("Invalid input")
		# print("\n..................\nTechnical Settings\n..................\n")
		# techIN = input("> ")

def uiGlobalTechMenu(): 	
	global bytesForward
	global bytesBack
	global linesForward
	global linesBack
	x = ""
	# print("\n............................\nGlobal settings for PE files\n............................\n")
	globalTechMenu(bytesForward, bytesBack, linesForward, linesBack)
	while True:
		print(yel+ " Sharem>" + cya + "Shell>" + res+ red + "Tech>" + res + whi + "Global> " + res, end="")
		gtIN = input()
		if(gtIN == "x"):
			break
		elif gtIN == "":
			continue
		elif(gtIN == "fb"):
			bytesForward = int(input("Enter new value: "))
		elif(gtIN == "bb"):
			bytesBack = int(input("Enter new value: "))
		elif(gtIN == "fi"):
			linesForward = int(input("Enter new value: "))
		elif(gtIN == "bi"):
			linesBack = int(input("Enter new value: "))
		else:
			print("Invalid input. Type x to exit.")
		# print("\n............................\nGlobal settings for PE files\n............................\n")

def uiCPTechMenu(): 	#Tech settings for callpop
	global maxDistance
	cpTechMenu(maxDistance)
	x = ""
	while x != "e":
		cptIN = input("> ")
		if(re.match("^[0-9]*$", cptIN, re.IGNORECASE)):
			maxDistance = int(cptIN)
			break
		elif(cptIN == "x"):
			break
		else:
			print("\nInput invalid, please enter a decimal number, or x to exit: ")

def uiPebTechMenu(): 
	#Tech settings for peb
	global pebPoints
	# global pointsLimit
	pebTechMenu(pebPoints)
	x = ""
	print("Enter number of features")
	while True:
		pebtIN = input("> ")
		if(pebtIN.isnumeric()):
			pebPoints = int(pebtIN)
			break
		elif pebtIN == "x":
			break
		else:
			print("\nInput invalid, please enter a decimal number, or x to exit: ")

def pebTechMenu(pointsLimit):
	pebTMenu = "\nPEB Points Settings\n\n"
	pebTMenu += "Current minimum number of likely features: "
	pebTMenu += yel + str(pointsLimit) + res
	pebTMenu += "\n"	
	pebTMenu += cya + "\t*Note: These are unique features to identify PEB wakling.\n"
	pebTMenu += "\t*Note: Below 3 generally is not recommended\n" + res

	
	print (pebTMenu)

def uiPrint(): 	#Print instructions
	global bpPushRet
	global bpFstenv
	global bpSyscall
	global bpHeaven
	global bpPEB
	global bpCallPop
	global bpStrings
	global bpPushStrings
	global bpModules
	global bModulesFound
	global bpEvilImports
	global bPushRetFound
	global bDisassemblyFound
	global bDisassembly
	global bFstenvFound
	global bSyscallFound
	global bHeavenFound
	global bPEBFound
	global bCallPopFound
	global bStringsFound
	global bPushStringsFound
	global bModulesFound
	global bEvilImportsFound
	global syscallSelection
	global shellbit
	global bpAll
	global bExportAll
	global stringsTempWide
	global pushStringsTemp
	global stringsTemp
	global p2screen


	print(yel + "\n ..........\n Print Menu\n ..........\n" + res)
	printMenu(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bExportAll, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly, bpAll, p2screen)
	if (not bPushRetFound) and (not bFstenvFound) and (not bSyscallFound) and (not bHeavenFound) and (not bPEBFound) and (not bCallPopFound) and (not bStringsFound) and (not bPushStringsFound) and (not bModulesFound) and (not bDisassemblyFound):
		print("Warning: No selections have been discovered.\n")

	x=""

	while True:
		print(cya + " Sharem>" + gre + "Print> " + res, end="")
		listIN = input()
		# print("input is: ", listIN, "\n")
		# if(listIN[0:1] == "t"):
		# 	uiToggleMenu(True)
		if(re.match("^x$", listIN, re.IGNORECASE)):
			break
		elif(re.match("^p$", listIN, re.IGNORECASE)):
			if p2screen:
				print("Print to screen disabled")
				p2screen = False
			else:
				print("Print to screen enabled")
				p2screen = True
		elif(re.match("^z$", listIN, re.IGNORECASE)):
			if bDisassembly and p2screen:
				if bDisassemblyFound:
					print(cya + "\n***********\nDisassembly\n***********" + res)
					print(gDisassemblyText)
				else:
					print("\nNo disassembly found.\n")
			if bpPushRet and p2screen:
				if bPushRetFound:
					
					print(cya + "\n***********\nPush ret\n***********\n" + res)
					printSavedPushRet(shellBit)
				else:
					print("\nNo push ret instructions found.\n")


			if bpModules and bModulesFound and p2screen:
				print(cya + "\n\n*******\nModules\n*******\n\n" + res)
				t=0
				for x in IATs.foundDll:
					try:
						x = x.decode()
					except:
						pass
					try:
						IATs.path[t] = IATs.path[t].decode()
					except:
						pass
					try:
						IATs.originate[t] = IATs.originate[t].decode()
					except:
						pass
					print((('{:<15s} {:<40s} {:<5} {:<0}').format(x, IATs.path[t], " from ", IATs.originate[t])))
					t+=1
				print("\n")
			if bpStrings and p2screen:
				if bStringsFound:
					print("\n***********\nStrings\n***********\n")
					t=0
					try:
						if not rawHex:
							if (len(s[t].Strings)) or (len(s[t].wideStrings)) or (len(s[t].pushStrings)):
							#Tuesday                          Offset: 0x1a04       Address: 0x402a04 Size: 7.0
							#1P1X1`1h1p1x1          .text   0x401c2e (offset 0xc2e)  Size: 14  Ascii
							#for sec in pe.sections:
								for sec in range(len(s)):
									if len(s[t].Strings) > 0 or len(s[t].wideStrings) > 0:
										print (s[t].sectionName.decode('utf-8'))
									if (len(s[t].pushStrings)) or (len(s[t].Strings)) or (len(s[t].wideStrings)):


										for x,y,z  in s[t].Strings:
											x = cya + x + res
											#print ('{:<5} {:<32s} {:<20s} {:<11s} {:<4} {:<8}'.format("",str(x), "Offset: " + str(hex(y)), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"Size: "+ str(z) , "Ascii"))
											print ('{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<8}'.format("",str(x), s[t].sectionName.decode('utf-8'), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"(offset "+str(hex(y+ s[t].VirtualAdd))+")", yel + "Ascii"+res))

											#print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z))) 
										#for x,y in s[t].wideStrings:
										#	print ("\t"+ str(x) + "\t" + str(hex(y)))
										for x,y, z in s[t].wideStrings:
											x = cya + x + res
											#print ('{:<5} {:<32s} {:<20s} {:<11s} {:<4} {:<8}'.format("",str(word), "Offset: " + str(hex(offset)), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"Size: "+ str(int(wordSize)), "Unicode"))
											print ('{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<8}'.format("",str(x), s[t].sectionName.decode('utf-8'), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"("+str(hex(y+ s[t].VirtualAdd))+")" , red + "Unicode" + res))

											#print ("\t"+ str(word) + "\t" + hex(offset) + "\t" + str(wordSize))
										t+=1
						else:
							for x,y,z  in stringsTemp:
								x = cya + x + res
								# print('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(x), "Offset: " + str(hex(y)),"Size: "+ str(z)))
								print ('{:<5} {:<32s} {:<16s} {:<12}'.format("",str(x), "(offset "+str(hex(y))+")" , yel + "Ascii" + res))

								#print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
							for x,y,z  in stringsTempWide:
								x = cya + x + res
								# print('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(x), "Offset: " + str(hex(y)),"Size: "+ str(z)))
								print ('{:<5} {:<32s} {:<16s} {:<12}'.format("",str(x), "(offset "+str(hex(y))+")" , red + "Unicode" + res))

								#print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))

					except Exception as e:
						print(e)
				else:
					print("\nNo strings found.\n")

			if bpPushStrings and p2screen:
				if bPushStringsFound:
					print(cya + "\n************\nPush Strings\n************\n"+res)
					t=0
					try:
						if not rawHex:
							for sec in pe.sections:
								#print (s[t].sectionName)
								#word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength
								for word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength in s[t].pushStrings:
									word4 = cya + word4 + res
									#print ('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(word4), "Offset: " + str(hex(offset)),"Size: "+ str(wordLength)))
									print ('{:<5} {:<32s} {:<8s} {:<8s} {:<8s} {:<12}'.format("",str(word4), s[t].sectionName.decode('utf-8'), str(hex(offset + s[t].ImageBase + s[t].VirtualAdd)),"(offset "+str(hex(offset+ s[t].VirtualAdd))+")" , gre + "Stack String" + res))
								print ("\n")
								t+=1
						else:
							for word4,offset,wordLength, instLen  in pushStringsTemp:
								word4 = cya + word4 + res
								#print ("\t"+ str(word4) + "\t" + hex(offset) + "\t" + str(hex(wordLength)))
								print ('{:<5} {:<32s} {:<16s} {:<12}'.format("",str(word4), "(offset "+str(hex(offset))+")" , gre + "Stack String" + res))
								#print('{:<5} {:<32s} {:<20s} {:<11s}'.format("",str(word4), "Offset: " + str(hex(offset)),"Size: "+ str(wordLength)))

					except Exception as e:
						print(traceback.format_exc())
						print(e)
				else:
					print("\nNo push strings found.\n")
			if bpFstenv and p2screen:
				if bFstenvFound:
					print(cya + "\n***********\nFstenv\n***********\n" + res)
					printSavedFSTENV(shellBit)

				else:
					print("\nNo fstenv instructions found.\n")
			if bpCallPop and p2screen:
				if bCallPopFound:
					print(cya + "\n***********\nCall Pop\n***********\n" + res)
					printSavedCallPop(shellBit)
				else:
					print("\nNo call pop instructions found.\n")
			if bpSyscall and p2screen:
				if bSyscallFound:
					print(cya + "\n***************\nWindows syscall\n***************\n" + res)
					printSavedEgg(shellBit)
				else:
					print("\nNo syscall instructions found.\n")
			if bpPEB and p2screen:
				if bPEBFound:
					print(cya + "\n***************\nWalking the PEB\n***************\n" + res)
					if shellBit == 32:
						printSavedPEB()
					else:
						printSavedPEB_64()
					# if(bit32):
					# 	printSavedPEB()
					# elif not bit32:
					# 	printSavedPEB_64()
				else:
					print("\nNo peb walking instructions found.\n")
				
			if bpHeaven and p2screen:
				if bHeavenFound:
					print(cya + "\n***************\nHeaven's Gate\n***************\n" + res)
					printSavedHeaven(shellBit)
				else:
					print("No heaven's gate instructions found.\n")
			outputData = generateOutputData()

			printToJson(bpAll, outputData)
			printToText(outputData)
			if not p2screen:
				print("Data saved.")
		elif(re.match("^h$", listIN, re.IGNORECASE)):
			print("\n.......\n")
			printMenu(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bExportAll, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly, bpAll, p2screen)
		elif(re.match("^s$", listIN, re.IGNORECASE)):
			uiPrintSyscallSubMenu()
		elif(re.match("^j$", listIN, re.IGNORECASE)):
			if(bExportAll):
				bExportAll = False
				print("\nJSON export all disabled\n")
			else:
				bExportAll = True
				print("\nJSON export all enabled\n")
		elif(re.match("^c$", listIN, re.IGNORECASE)):
			bpPushRet = False
			bpFstenv = False
			bpCallPop = False
			bpSyscall = False
			bpPEB = False
			bpHeaven = False
			bpModules = False
			bpEvilImports = False
			bpStrings = False
			bpPushStrings = False
			bpAll = False
			bDisassembly = False
			print("Selections changed.\n")
			displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly, bpAll)
		elif(re.match("^all$", listIN, re.IGNORECASE)):
			bpPushRet = True
			bpFstenv = True
			bpCallPop = True
			bpSyscall = True
			bpPEB = True
			bpHeaven = True
			bpEvilImports = True
			bpModules = True
			bpStrings = True
			bpPushStrings = True
			bDisassembly = True
			bpAll = True
			print("Selections changed.\n")
			displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly, bpAll)


		elif(re.match("^g$", listIN, re.IGNORECASE)):
			print("Enter input delimited by commas or spaces. (x to exit)\n\tE.g. pr, pb, hg\n")
			while x != 'e':
				printSelectIn = input("> ")
				if (re.match("^x$", printSelectIn, re.IGNORECASE)):
					break
				bPR = re.search("( |,|^)PR( |,|$)", printSelectIn, re.IGNORECASE)
				bFE = re.search("( |,|^)FE( |,|$)", printSelectIn, re.IGNORECASE)
				bCP = re.search("( |,|^)CP( |,|$)", printSelectIn, re.IGNORECASE)
				bSy = re.search("( |,|^)Sy( |,|$)", printSelectIn, re.IGNORECASE)
				bPB = re.search("( |,|^)PB( |,|$)", printSelectIn, re.IGNORECASE)
				bHG = re.search("( |,|^)HG( |,|$)", printSelectIn, re.IGNORECASE)
				bpAll = re.search("( |,|^)all( |,|$)", printSelectIn, re.IGNORECASE)
				bNone = re.search("( |,|^)none( |,|$)", printSelectIn, re.IGNORECASE)
				bST = re.search("( |,|^)ST( |,|$)", printSelectIn, re.IGNORECASE)
				bPS = re.search("( |,|^)PS( |,|$)", printSelectIn, re.IGNORECASE)
				bLM = re.search("( |,|^)lm( |,|$)", printSelectIn, re.IGNORECASE)
				bIM = re.search("( |,|^)im( |,|$)", printSelectIn, re.IGNORECASE)
				bFD = re.search("( |,|^)FD( |,|$)", printSelectIn, re.IGNORECASE)

				print("\n")
				if bFD:
					bDisassembly = False if bDisassembly else True
				if bPR:
					bpPushRet = False if bpPushRet else True
				if bFE:
					bpFstenv = False if bpFstenv else True
				if bCP:
					bpCallPop = False if bpCallPop else True
				if bSy:
					bpSyscall = False if bpSyscall else True
				if bPB:
					bpPEB = False if bpPEB else True
				if bHG:
					bpHeaven = False if bpHeaven else True
				if bST:
					bpStrings = False if bpStrings else True
				if bPS:
					bpPushStrings = False if bpPushStrings else True
				if bIM:
					bpEvilImports = False if bpEvilImports else True
				if bLM:
					bpModules = False if bpModules else True
				if bpAll:
					bpPushRet = True
					bpFstenv = True
					bpCallPop = True
					bpSyscall = True
					bpPEB = True
					bpHeaven = True
					bpStrings = True
					bpPushStrings = True
					bpEvilImports = True
					bpModules = True
					bDisassembly = True
				if bNone:
					bpPushRet = False
					bpFstenv = False
					bpCallPop = False
					bpSyscall = False
					bpPEB = False
					bpHeaven = False
					bpStrings = False
					bpPushStrings
					bpEvilImports = False
					bpModules = False
					bDisassembly = False
				if bpPushRet and bpFstenv and bpCallPop and bpSyscall and bpPEB and bDisassembly and bpHeaven and bpStrings and bpEvilImports and bpModules and bpPushStrings:
					bpAll = True
				if bPR or bFE or bCP or bSy or bPB or bHG or bST or bPS or bIM or bLM or bFD:
					print("Selections changed.\n")
					displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly, bpAll)
					break
				else:
					print("\nInput not recognized.\n")
		else:
			print("\nInput not recognized.\n")
		# print(yel + "\n ..........\n Print Menu\n ..........\n")

def uiPrintSyscallSubMenu(): #Printing/settings for syscalls
	global syscallSelection
	global shellbit
	global showDisassembly
	global syscallPrintBit

	print(yel + "\n ...................\n Syscall Settings\n ...................\n" + res)
	syscallPrintSubMenu(syscallSelection, showDisassembly, syscallPrintBit, True)
	x = ""
	while x != "e":
		print(cya + " Sharem>" + gre + "Print>" + yel + "Syscalls> " + res, end="")
		syscallIN = input()
		if(re.match("^x$", syscallIN, re.IGNORECASE)):
			# print("Returning to print menu.")
			break
		elif(re.match("^h$", syscallIN, re.IGNORECASE)):
			syscallPrintSubMenu(syscallSelection, showDisassembly, syscallPrintBit, True)
		elif(re.match("^g$", syscallIN, re.IGNORECASE)):
			syscallSelectionsSubMenu()
			print("\nChanges applied: ")
			syscallPrintSubMenu(syscallSelection, showDisassembly, syscallPrintBit, False)
		elif(re.match("^z$", syscallIN, re.IGNORECASE)):
			printSavedEgg(syscallPrintBit, showDisassembly)
		elif(re.match("^c$", syscallIN, re.IGNORECASE)):
			for osv in syscallSelection:
				osv.toggle = False
			print("\nChanges applied: ")
			syscallPrintSubMenu(syscallSelection, showDisassembly, syscallPrintBit, False)

		elif(re.match("^b$", syscallIN, re.IGNORECASE)):
			print("Warning: 64-bit is standard for all syscalls.\n\tDeviate with extreme care.\nSet bits:\n\n\t1 - 32-bit\n\t2 - 64-bit\n...")
			syscallBitIN = input("> ")
			if(syscallBitIN[0:1] == "1" ):
				syscallPrintBit = 32
			elif(syscallBitIN[0:1] == "2"): 
				syscallPrintBit = 64
			print("Print bits set to : ", syscallPrintBit,".")
			# print("Returning to syscall selection submenu.\n")

			

		elif(re.match("^d$", syscallIN, re.IGNORECASE)):
			showDisassembly = False if showDisassembly else True
			print("Show disassembly set to : ", showDisassembly)
		print("\n................\nSyscall Settings\n................\n")

def uiModulesSubMenu():		#Find and display loaded modules
	global bModulesFound
	global modulesMode		#1-3, whichever option we want
	print("\n............................\nFind InMemoryOrderModuleList\n............................\n")
	print("This feature will statically discover the order of the InMemoryOrderModuleList\n")
	if(rawHex):
		print("Warning: No PE file selected.\n")
	printModulesMenu(modulesMode)
	x = 'i'
	while x != 'e':
		print(".......\nModules\n.......\n")
		modIn = input("> ")
		if(re.match("^x$", modIn, re.IGNORECASE)):
			break
		elif(re.match("^[1-3]$", modIn, re.IGNORECASE)):
			modulesMode = int(modIn)
			if (modulesMode == 1):
				print("Selection changed to: Find only DLLs in IAT\n")
			if (modulesMode == 2):
				print("Selection changed to: Find DLLs in IAT and beyond\n")
			if (modulesMode == 3):
				print("Selection changed to: Find DLLs in IAT, beyond, and more\n")
		elif(re.match("^h$", modIn, re.IGNORECASE)):
			printModulesMenu(modulesMode)
		elif(re.match("^p$", modIn, re.IGNORECASE)):
			printInMemoryOrderModuleList()
		elif(re.match("^r$", modIn, re.IGNORECASE)):
			clearMods()
			print("InMemoryOrderModuleList cleared.\n")
		elif(re.match("^z$", modIn, re.IGNORECASE)):
			if(rawHex):
				print("\nNo PE file selected\n")
			else:
				runInMem()

		else:
			print("Input not recognized.\n")
		
	return



def runInMem():
	global modulesMode
	global bModulesFound

	clearMods()
	print("\nFinding DLLs in IAT\n")
	getDLLs()
	if(modulesMode > 1):
		print("Finding DLLs beyond the IAT\n")
		digDeeper(PE_DLLS)
	if(modulesMode > 2):
		print("Finding even more DLLs\n")
		dontPrint()
		digDeeper2()
	InMem2()
	allowPrint()
	colorama.init()

	if(len(IATs.foundDll) > 0):
		bModulesFound = True

def checkRegVal(regName, regVal):


	while checkHex(regVal) != True:
		try:
			regVal = input("Enter valid {} value> ".format(regName))
			return True

		except KeyboardInterrupt:
			print("\n")
			return False

	return True


def manualRegisters():
	global regsTemp
	
	eax = ebx = ecx = edx = edi = esi = ebp = esp = False
	print("Enter register values, Ctrl+C to exit")
	print("   *Note: recent strings found will be cleared\n")
	validatipon = True
	while True:
		try:

			eax = input("EAX> ")
			if not checkRegVal("EAX", eax):
				return
			ebx = input("EBX> ")
			if not checkRegVal("EBX", ebx):
				return
			ecx = input("ECX> ")
			if not checkRegVal("ECX", ecx):
				return
			edx = input("EDX> ")
			if not checkRegVal("EDX", edx):
				return
			edi = input("EDI> ")
			if not checkRegVal("EDI", edi):
				return
			esi = input("ESI> ")
			if not checkRegVal("ESI", esi):
				return
			ebp = input("EBP> ")
			if not checkRegVal("EBP", ebp):
				return
			esp = input("ESP> ")
			if not checkRegVal("ESP", esp):
				return
			break
		except KeyboardInterrupt:
			break
		except Exception as e:
			print(e)


	if eax:
		eax =hexDword(int(eax, 16))
		setReg(eax, False, "eax")

	if ebx:
		ebx =hexDword( int(ebx, 16))
		setReg(ebx, False, "ebx")

	if ecx:
		ecx =hexDword( int(ecx, 16))
		setReg(ecx, False, "ecx")

	if edx:
		edx =hexDword( int(edx, 16))
		setReg(edx, False, "edx")

	if edi:
		edi =hexDword( int(edi, 16))
		setReg(edi, False, "edi")

	if esi:
		esi =hexDword( int(esi, 16))
		setReg(esi, False, "esi")

	if ebp:
		ebp =hexDword( int(ebp, 16))
		setReg(ebp, False, "ebp")

	if esp:
		esp =hexDword( int(esp, 16))
		setReg(esp, False, "esp")

	clearStrings()

	# setReg(output, False, "eax")



	#print("Before -----> ",regsTemp)
	#print("Before -----> ",regsTemp)
	#print(regsTemp)


		
def changeRegsFile():
	global regFilePath
	regFilePath = ""
	while True:
		try:
			
			print("Enter registers file. Ctrl+C to exit\n")
			regFilePath = input("> ")
			tmpFile = open(regFilePath, "r")
			regsFile = regFilePath
			print("\nRegisters file changed to {}\n".format(regFilePath))
			tmpFile.close()
			break
		except Exception as e:
			print("File doesn't exit")
		except KeyboardInterrupt:
			break
	if regFilePath:
		tmpFile.close()
		assemblyx86.regsFile = regFilePath
		readRegs()
		

		# 		for line in regVals:
		# 			if " " not in line and "," not in line:
		# 				print("File format is not correct")
		# 			else:
		# 				if " " in line:
		# 					rval = int(line.split()[1])
		# 					pushStringRegisters.append(rval)
		# 				elif "," in line:
		# 					rval = int(line.split(",")[1])
		# 					pushStringRegisters.append(rval)
		# 		print(pushStringRegisters)
		# 		useStringsFile = True
		# 		break


		# 	except:
		# 		print("Unable to open file, please try again.\n")
		# except KeyboardInterrupt:
		# 	break
	


def uiFindStrings():
	global bStringsFound
	global bPushStringsFound
	global bAsciiStrings
	global bPushStrings
	global bWideCharStrings
	global bPushStackStrings
	global bAllStrings
	global minStrLen
	global pushStringRegisters
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp
	global FindStringsStatus
	global useStringsFile
	global chMode



	if(bAsciiStrings and bWideCharStrings and bPushStackStrings):
			bAllStrings = True
	else:
		bAllStrings = False

	print(yel + "\n ...............\n  Find Strings\n ...............\n"+res)
	stringMenu(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s, useStringsFile, chMode)
	x=""
	while True:
		# print("\n............\nFind Strings\n............\n")
		print(cya + " Sharem>" + gre + "Strings> " + res, end="")
		stringIN = input()
		if(re.match("^x$", stringIN, re.IGNORECASE)):
			break
		elif(re.match("^h$", stringIN, re.IGNORECASE)):
			stringMenu(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s, useStringsFile, chMode)
		elif(re.match("^r$", stringIN, re.IGNORECASE)):
			clearStrings()
			print("Found strings cleared.\n")
		
		elif(re.match("^m$", stringIN, re.IGNORECASE)):
			manualRegisters()

		elif(re.match("^e$", stringIN, re.IGNORECASE)):
			chMode = True
			print("\nEmulation enabled\n")
		elif (re.match("^s$", stringIN, re.IGNORECASE)):
			pushStringsOutput(5)	# Testing only
			# getPushStrings(5)
		elif(re.match("^n$", stringIN, re.IGNORECASE)):

			changeRegsFile()
			useStringsFile = True


			# print("Enter path to register file: (x to exit)\n")
			# while x != "e":
			# 	regFilePath = input("> ")
			# 	if (re.match("^x$", regFilePath, re.IGNORECASE)):
			# 		break
			# 	try:
			# 		regFile = open(regFilePath, "r")
			# 		regVals = regFile.readlines()
			# 	except:
			# 		print("Unable to open file, please try again.\n")
			# 	try:
			# 		t = 0
			# 		w = 0
			# 		j = 0
			# 		pushStringRegisters = [0, 0, 0, 0, 0, 0, 0, 0]
			# 		for char in regVals[0]:
			# 			# print(char)
			# 			if (regVals[0][w] == " ") or (regVals[0][w] == ","):
			# 				pushStringRegisters[t] = int(regVals[0][j:w])
			# 				j = w+2
			# 				w+=1
			# 				t+=1
			# 			if(t>6):
			# 				break
			# 			w+=1
			# 		regFile.close()
			# 		print(pushStringRegisters)
			# 		break
			# 	except Exception as e:
			# 		print(e)
			# 		print("Input file format not recognized.\n")

		elif(re.match("^g$", stringIN, re.IGNORECASE)):
			print("Enter input delimited by commas or spaces. (x to exit)\n\tE.g. as, wc\n")
			while x != 'e':
				sSelectIn = input("> ")
				if (re.match("^x$", sSelectIn, re.IGNORECASE)):
					break
				bAS = re.search("( |,|^)AS( |,|$)", sSelectIn, re.IGNORECASE)
				bWC = re.search("( |,|^)WC( |,|$)", sSelectIn, re.IGNORECASE)
				bPS = re.search("( |,|^)PS( |,|$)", sSelectIn, re.IGNORECASE)
				bAll = re.search("( |,|^)ALL( |,|$)", sSelectIn, re.IGNORECASE)
				if bAS:
					bAsciiStrings = False if bAsciiStrings else True
				if bWC:
					bWideCharStrings = False if bWideCharStrings else True
				if bPS:
					bPushStackStrings = False if bPushStackStrings else True
				if bAll:
					bAsciiStrings = False if bAsciiStrings else True
					bWideCharStrings = False if bWideCharStrings else True
					bPushStackStrings = False if bPushStackStrings else True
				if(bAsciiStrings and bWideCharStrings and bPushStackStrings):
					bAllStrings = True
				else:
					bAllStrings = False
				if (bAS or bWC or bPS or bAll):
					showStringSelections(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s)
					break
				else:
					print("Input not recognized.\n")
		elif(re.match("^c$", stringIN, re.IGNORECASE)):
			bAsciiStrings = False
			bWideCharStrings = False
			bPushStackStrings = False
			bAllStrings = False
			showStringSelections(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s)
		elif(re.match("^all$", stringIN, re.IGNORECASE)):
			bAsciiStrings = True
			bWideCharStrings = True
			bPushStackStrings = True
			bAllStrings = True
			showStringSelections(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s)

		elif(re.match("^z$", stringIN, re.IGNORECASE)):
			if not rawHex:
				t=0
				for sec in pe.sections:
					if bAsciiStrings:
						findStrings(s[t].data2,minStrLen)
					if bWideCharStrings:
						findStringsWide(s[t].data2,minStrLen)
					if bPushStackStrings:

						#if(pushStringRegisters == 'unset'):
							#findPushAscii(s[t].data2,minStrLen)
						findPushAsciiMixed(s[t].data2,5, t)
						#print(s[t].pushStrings)
					t+=1

				# if not (pushStringRegisters == 'unset'):
					# getPushStrings(minStrLen)
				t = 0

				maxLen = len("Searching for push stack strings")
				bTempWideString = False
				#print("{:>{x}}".format("[Found]    ", x=15+(maxLen-curLen)))
				for sec in pe.sections:
					if (len(s[t].Strings) > 0):
						bStringsFound = True
					
					if (len(s[t].wideStrings) > 0):
						bTempWideString = True
						
						bStringsFound = True
					if (len(s[t].pushStrings) > 0):
						bPushStringsFound = True

					t+=1

				if(bStringsFound):
					curLen = len("Searching for Strings")
					print(cya + " searchinG for strings."+ res, end="", flush=True)
					print("{:>{x}}[{}]".format("", gre + "Found" + res, x=20+(maxLen-curLen)))
				else:
					curLen = len("Searching for strings")
					print(cya + " searching for strings."+ res, end="", flush=True)
					print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=20+(maxLen-curLen)))

				if(bTempWideString):
					curLen = len("Searching for wide strings")
					print(cya + " searching for wide strings." + res, end="", flush=True)
					print("{:>{x}}[{}]".format("", gre + "Found" + res, x=20+(maxLen-curLen)))
				else:
					curLen = len("Searching for wide strings")
					print(cya + " searching for wide strings." + res, end="", flush=True)
					print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=20+(maxLen-curLen)))

				if(bPushStringsFound):
					curLen = len("Searching for push stack strings")
					print(cya + " Searching for push stack strings."+ res, end="", flush=True)
					print("{:>{x}}[{}]".format("", gre +"Found" + res, x=20+(maxLen-curLen)))
				else:
					curLen = len("Searching for Push stack strings")
					print(cya + " Searching for push stack strings."+ res, end="", flush=True)
					print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=20+(maxLen-curLen)))


			else:

				if bAsciiStrings and not bStringsFound:
					findStrings(rawData2,3)

				if bWideCharStrings and (stringsTempWide == []):
					findStringsWide(rawData2,3)
				if bPushStackStrings and not  bPushStringsFound:
					findPushAsciiMixed(rawData2,3)
				maxLen = len("Searching for Push stack strings")

				print("\n")
				if (len(stringsTemp) > 0):
					curLen = len("Searching for Strings")
					print(cya + " searching for strings."+ res, end="", flush=True)
					print("{:>{x}}[{}]".format("", gre + "Found" + res, x=20+(maxLen-curLen)))
					bStringsFound = True
				else:
					curLen = len("Searching for strings")
					print(cya + " searching for strings."+ res, end="", flush=True)
					print("{:>{x}}[{}]".format("", red + "Not found" + res, x=20+(maxLen-curLen)))
					bStringsFound = True
				if (len(stringsTempWide) > 0):
					curLen = len("Searching for wide strings")
					print(cya + " searching for wide strings." + res, end="", flush=True)
					print("{:>{x}}[{}]".format("", gre + "Found"+ res, x=20+(maxLen-curLen)))
					bStringsFound = True
				else:
					curLen = len("Searching for wide strings")
					print(cya + " searching for wide strings." + res, end="", flush=True)
					print("{:>{x}}[{}]".format("", red + "Not found"+ res, x=20+(maxLen-curLen)))
					bStringsFound = True
				if (len(pushStringsTemp) > 0):
					curLen = len("Searching for push stack strings")
					print(cya + " Searching for push stack strings."+ res, end="", flush=True)
					print("{:>{x}}[{}]".format("", gre + "Found" +res, x=20+(maxLen-curLen)))
					bPushStringsFound = True
				else:
					curLen = len("Searching for push stack strings")
					print(cya + " Searching for push stack strings."+ res, end="", flush=True)
					print("{:>{x}}[{}]".format("", red + "Not found" + res, x=20+(maxLen-curLen)))
					bStringsFound = True


			#printStrings()
		elif(re.match("^p$", stringIN, re.IGNORECASE)):
			printStrings()
		else:
			print("\nInput not recognized.\n")

def uiShellcodeStrings():
	global minStrLen
	global stringReadability
	global checkGoodStrings
	global shBy
	global bStringsFound
	global bPushStringsFound
	global bAsciiStrings
	global bWideCharStrings
	global bPushStackStrings
	global bAllStrings
	global minStrLen
	global pushStringRegisters
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp
	global shellcodeStrings 
	global shellcodeStringsWide
	global shellcodePushStrings

	if(bAsciiStrings and bWideCharStrings and bPushStackStrings):
			bAllStrings = True
	else:
		bAllStrings = False
	print("\n............\nFind Shellcode Strings\n............\n")
	shellcodeStringMenu(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s)
	x=""
	while x != "e":
		print("\n............\nFind Shellcode Strings\n............\n")
		stringIN = input("> ")
		if(re.match("^x$", stringIN, re.IGNORECASE)):
			break
		elif(re.match("^z$", stringIN, re.IGNORECASE)):
			shellcodeStrings = []
			shellcodeStringsWide = []
			shellcodePushStrings = []
			preSyscalDiscovery(0, 0x0, 20)
			for x,y,z in stringsTemp:
				if(goodString(rawData2, x, minStrLen)):
					shellcodeStrings.append(tuple((x,y,z)))
			for x,y,z  in shellcodeStrings:
				print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
		elif(re.match("^m$", stringIN, re.IGNORECASE)):
			print("\nEnter a minimum length for strings:\n")
			while x != 'e':
				minLenIn = input("> ")
				if(re.match("^[0-9]*$", minLenIn, re.IGNORECASE)):
					minStrLen = int(minLenIn)
					shellcodeStrings = []
					for x,y,z in stringsTemp:
						if(goodString(rawData2, x, minStrLen)):
							shellcodeStrings.append(tuple((x,y,z)))
					for x,y,z  in shellcodeStrings:
						print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
					break
				elif(re.match("^x$", minLenIn, re.IGNORECASE)):
					break
				else:
					print("\nInput not recognized.\n")
		elif(re.match("^h$", stringIN, re.IGNORECASE)):
			shellcodeStringMenu(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s)
		elif(re.match("^p$", stringIN, re.IGNORECASE)):
			for x,y,z  in shellcodeStrings:
				print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
		elif(re.match("^r$", stringIN, re.IGNORECASE)):
			clearStrings()

def uiFindImports():
	global bEvilImportsFound
	print("\n............\nFind Imports\n............\n")
	if(rawHex):
		print("Warning: No PE file selected.\n")
	importsMenu()
	x=""
	while x != "e":
		print("\n............\nFind Imports\n............\n")
		importsIN = input("> ")
		if(re.match("^x$", importsIN, re.IGNORECASE)):
			break
		elif(re.match("^h$", importsIN, re.IGNORECASE)):
			importsMenu()
		elif(re.match("^r$", importsIN, re.IGNORECASE)):
			clearImports()
		elif(re.match("^z$", importsIN, re.IGNORECASE)):
			if not rawHex:
				if not bEvilImportsFound:
					findEvilImports()
				if(len(FoundApisName) > 0):
					bEvilImportsFound = True
				print(showImports())
			else:
				print("No PE file selected.\n")
		elif(re.match("^p$", importsIN, re.IGNORECASE)):
			print(showImports())
		else:
			print("Input not recognized.\n")

def findAll():  #Find everything
	global peName
	global bEvilImportsFound
	global bPushRetFound
	global bDisassemblyFound
	global bDisassembly
	global bFstenvFound
	global bSyscallFound
	global bHeavenFound
	global bPEBFound
	global bCallPopFound
	global bModulesFound
	global bStringsFound
	global bPushStringsFound
	global modulesMode
	global minStrLen
	bTempWideString = False




	list_of_labels = ["Searching for push stack strings","Searching for wide strings", "Searching for strings", "Searching for disassembly", "Searching for fstenv instructions", "Searching for push ret instructions", "Searching for call pop instructions", "Searching for heaven's gate instructions", "Searching for windows syscall instructions", "Searching for PEB walking instructions"]
	maxLen = get_max_length(list_of_labels)

	if not rawHex:
		print("Finding imports.\n")
		if not bEvilImportsFound:
			findEvilImports()
		if(len(FoundApisName) > 0):
			bEvilImportsFound = True

	if(rawHex):
		pass
	else:
		runInMem()
		# clearMods()
		# print("\nFinding DLLs in IAT\n")
		# getDLLs()
		# if(modulesMode > 1):
		# 	print("Finding DLLs beyond the IAT\n")
		# 	digDeeper(PE_DLLS)
		# if(modulesMode > 2):
		# 	print("Finding even more DLLs\n")
		# 	digDeeper2()
		# InMem2()


	if not bStringsFound:
		print("Finding strings.\n")
		if not rawHex:
			t=0
			for sec in pe.sections:
				if bAsciiStrings:
					findStrings(s[t].data2,minStrLen)
				if bWideCharStrings:
					findStringsWide(s[t].data2,minStrLen)
				if bPushStackStrings:
					findPushAsciiMixed(s[t].data2,minStrLen, t)
				t+=1
			t = 0
			for sec in pe.sections:
				if (len(s[t].Strings) > 0):
					bStringsFound = True
				if (len(s[t].wideStrings) > 0):
					bTempWideString = True
				if (len(s[t].pushStrings) > 0):
					bPushStringsFound = True
				t+=1

			if(bStringsFound):
				curLen = len("Searching for Strings")
				print("searching for strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
			else:
				curLen = len("Searching for strings")
				print("Searching for strings: ", end="", flush=True)
				print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))

			if(bTempWideString):
				curLen = len("Searching for wide strings")
				print("searching for wide strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
			else:
				curLen = len("Searching for wide strings")
				print("searching for wide strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))

			if(bPushStringsFound):
				curLen = len("Searching for push stack strings")
				print("Searching for push stack strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
			else:
				curLen = len("Searching for push stack strings")
				print("Searching for push stack strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))



		else: 
			if bAsciiStrings:
				findStrings(rawData2,3)

			if bWideCharStrings:
				findStringsWide(rawData2,3)
			if bPushStackStrings:
				findPushAsciiMixed(rawData2,3)


			if (len(stringsTemp) > 0):
				curLen = len("Searching for strings")
				print("searching for strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
				bStringsFound = True
			else:
				curLen = len("Searching for strings")
				print("searching for strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))
				bStringsFound = True
			if (len(stringsTempWide) > 0):
				curLen = len("Searching for wide strings")
				print("Searching for  wide strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
				bStringsFound = True
			else:
				curLen = len("Searching for wide strings")
				print("searching for wide strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))
				bStringsFound = True
			if (len(pushStringsTemp) > 0):
				curLen = len("Searching for push stack strings")
				print("Searching for push stack strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
				bPushStringsFound = True
			else:
				curLen = len("Searching for push stack strings")
				print("Searching for push stack strings.", end="", flush=True)
				print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))
				bStringsFound = True

		#if (len(stringsTemp) > 0):
		#	bStringsFound = True


	

	if not bFstenvFound:
		curLen = len("Searching for fstenv instructions")
		print("Searching for fstenv instructions.", end="", flush=True)

		#print("Finding fstenv instructions.\n")
		if (rawHex):
			findAllFSTENV(rawData2, 'noSec')
		else:
			for secNum in range(len(s)):
				data2 = s[secNum].data2
				findAllFSTENV(data2, secNum)
		for i in s:
			if (len(i.save_FSTENV_info) > 0):
				bFstenvFound = True
		if len(m[o].save_FSTENV_info) > 0:
			print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))

			bFstenvFound = True
		else:
			print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))


	if not bPushRetFound:
		print("Searching for push ret instructions.", end="", flush=True)
		curLen = len("Searching for push ret instructions")
		#print("Finding push ret instructions.\n")
		if (rawHex):
			if bit32:
				findAllPushRet(rawData2, 'noSec')
			else:
				pass
				# findAllPushRet64(rawData2, 'noSec')

		else:
			for secNum in range(len(s)):
				data2 = s[secNum].data2
				if bit32:
					findAllPushRet(data2, secNum)
				else:
					pass
					# findAllPushRet64(data2, secNum)
		for i in s:
			if (len(i.save_PushRet_info) > 0):

				bPushRetFound = True
		if len(m[o].save_PushRet_info) > 0:

			bPushRetFound = True
		if(bPushRetFound):
			print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
		else:
			print("{:>{x}}{}".format("", "["+red+"Not Found"+res+"]", x=15+(maxLen-curLen)))

	if not bCallPopFound:
		curLen = len("Searching for call pop instructions")
		print("Searching for call pop instructions.", end="", flush=True)
		# print("Finding call pop instructions.\n")
		if (rawHex):
			if bit32:
				findAllCallpop(rawData2, 'noSec')
			else: 
				findAllCallpop64(rawData2, 'noSec')

		else:
			for secNum in range(len(s)):
				data2 = s[secNum].data2
				if bit32:
					findAllCallpop(data2, secNum)
				else:
					findAllCallpop64(data2, secNum)
		for i in s:
			if (len(i.save_Callpop_info) > 0):
				bCallPopFound = True
		if len(m[o].save_Callpop_info) > 0:
			bCallPopFound = True
		if(bCallPopFound):
			print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
		else:
			print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))


	if not bHeavenFound:
		curLen = len("Searching for heaven's gate instructions")
		print("Searching for heaven's gate instructions.", end="", flush=True)
		#print("Finding heaven's gate instructions.\n")
		if (rawHex):
			getHeavenRawHex(0, 8, 'noSec', rawData2)
		else:
			for secNum in range(len(s)):
					data2 = s[secNum].data2
					findAllHeaven(data2, secNum)
		for i in s:
			if (len(i.save_Heaven_info) > 0):
				bHeavenFound = True
		if len(m[o].save_Heaven_info) > 0:
			bHeavenFound = True

		if(bHeavenFound):
			print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
		else:
			print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))


	if not bSyscallFound:
		curLen = len("Searching for windows syscall instructions")
		print("Searching for windows syscall instructions.", end="", flush=True)
		#print("Finding windows syscall instructions.\n")
		if (rawHex):
			# getSyscallPE(20, 20, match, 'noSec', rawData2)
			getSyscallRawHex(0, 8, 'noSec', rawData2)
		else:
			for secNum in range(len(s)):
					data2 = s[secNum].data2
					for match in EGGHUNT.values():
						getSyscallPE(20, 20, match, secNum, data2)
		for i in s:
			if (len(i.save_Egg_info) > 0):
				bSyscallFound = True
		if len(m[o].save_Egg_info) > 0:
			bSyscallFound = True
		if(bSyscallFound):
			print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
		else:
			print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))

	if not bPEBFound:
		curLen = len("Searching for PEB walking instructions")
		print("Searching for PEB walking instructions.", end="", flush=True)
		#print("Finding PEB walking instructions.\n")
		if (rawHex):
			findAllPebSequences_old(rawData2, 'noSec')
		else:
			for secNum in range(len(s)):
					data2 = s[secNum].data2
					findAllPebSequences_old(data2, secNum)
		for i in s:
			if (len(i.save_PEB_info) > 0):
				bPEBFound = True
		if len(m[o].save_PEB_info) > 0:
			bPEBFound = True
		if(bPEBFound):
			print("{:>{x}}{}".format("", "["+gre+"Found"+res+"]", x=15+(maxLen-curLen)))
		else:
			print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))

		pass

	if not bDisassemblyFound:
		
		# print("Finding disassembly.\n")
		#dontPrint()
		if rawHex:
			curLen = len("Searching for disassembly")
			print("Searching for disassembly.", end="", flush=True)
			shellDisassemblyInit(rawData2)
			#allowPrint()
			if gDisassemblyText != "":
				print("{:>{x}}{}".format("", gre + "[Found]" + res, x=15+(maxLen-curLen)))
				bDisassemblyFound = True
			else:
				print("{:>{x}}{}".format("", "["+red+"not Found"+res+"]", x=15+(maxLen-curLen)))
	print("\n")
	print(".........................\n")
	print("Search completed.\n")

def syscallSelectionsSubMenu(): #Select osversions for syscalls
	global syscallSelection
	x = ''

	print("\nEnter input deliminted by commas or spaces.\n\tE.g. v3, xp2, r3\n")
	while x != 'e':
		sysSelectIN = input("> ")
		print("...")
		# print(type(syscallSelection[1]))
		v = "asdf"
		# print(type(v))
		#Recursively loop through to check each OS
		for osv in syscallSelection:
			#If we make changes, our multiselects no longer apply
			if (osv.category == "server Column multiselect variables"):
				osv.toggle = False

			#If we find a match between the selection codes and our input, toggle that os
			if re.search(fr"(^| |,){osv.code}($| |,)", sysSelectIN):
				osv.toggle = False if osv.toggle else True

				#If we toggle a category, toggle everything in that category
				if(osv.name == osv.category):
					for ver in syscallSelection:
						if(ver.category == osv.category):
							ver.toggle = osv.toggle

				#If we toggle a multiselect, do a multiselect
				if(osv.code == "all"): 	#Toggle all
					osv.toggle = True
					for ver in syscallSelection:
						if not (ver.category == "server Column multiselect variables"):
							ver.toggle = True
				if(osv.code == "l"): 	#Only latest releases
					osv.toggle = True
					for ver in syscallSelection:
						if not (ver.category == "server Column multiselect variables"):
							ver.toggle = False
					t = 0
					currentCategory = ""
					for ver in syscallSelection:
						if(t == 0):
							currentCategory = ver.category
						elif(currentCategory != ver.category):
							currentCategory = ver.category
							syscallSelection[t-1].toggle = True
						t+=1
				if(osv.code == "d"): 	#Only current win10
					osv.toggle = True
					for ver in syscallSelection:
						if not (ver.category == "server Column multiselect variables"):
							ver.toggle = False
					t=len(syscallSelection)-1
					for ver in syscallSelection:
						if(syscallSelection[t].category == "Windows 10"):
							syscallSelection[t].toggle = True
							break
						t-=1
				if(osv.code == "D"): 	#only current win10 and 7
					osv.toggle = True
					for ver in syscallSelection:
						if not (ver.category == "server Column multiselect variables"):
							ver.toggle = False
					t=len(syscallSelection)-1
					for ver in syscallSelection:
						if(syscallSelection[t].category == "Windows 10"):
							syscallSelection[t].toggle = True
							break
						t-=1
					t=len(syscallSelection)-1
					for ver in syscallSelection:
						if(syscallSelection[t].category == "Windows 7"):
							syscallSelection[t].toggle = True
							break
						t-=1
		break

def clearInstructions(): 	#Clears 
	#clear our lists of found instructions
	global rawHex
	for secNum in s:
		secNum.save_PEB_info.clear()
		secNum.save_FSTENV_info.clear()
		secNum.save_Egg_info.clear()
		secNum.save_Heaven_info.clear()
		secNum.save_Callpop_info.clear()
		secNum.save_PushRet_info.clear()


	# o = 0
	for oNum in m:
		oNum.save_PEB_info.clear()
		oNum.save_FSTENV_info.clear()
		oNum.save_Egg_info.clear()
		oNum.save_Heaven_info.clear()
		oNum.save_Callpop_info.clear()
		oNum.save_PushRet_info.clear()
		# o+= 1
	s.clear()
	m.clear()
	sections.clear()

	clearFoundBooleans()


def clearMods():			#Clears our module list
	global bModulesFound
	IATs.foundDll = []
	FoundApisName = []
	IATs.found = []
	IATs.path = []
	IATs.originate = []
	bModulesFound = False

def clearFoundBooleans(): 	#Clears bools saying we've found data
	global bPushRetFound
	global bDisassemblyFound
	global bFstenvFound
	global bSyscallFound
	global bHeavenFound
	global bPEBFound
	global bCallPopFound
	global bStringsFound
	global bEvilImportsFound
	global bModulesFound

	bPushRetFound = False
	bFstenvFound = False
	bSyscallFound = False
	bHeavenFound = False
	bPEBFound = False
	bCallPopFound = False
	bStringsFound = False
	bEvilImportsFound = False
	bModulesFound = False


def clearAll():		#Clears all found data and booleans
	clearInstructions()
	clearMods()
	clearFoundBooleans()
	clearStrings()
	clearImports()

def clearStrings():
	global bStringsFound
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp
	bStringsFound = False
	try:
		t = 0
		for sec in pe.sections:
			s[t].Strings.clear()
			s[t].wideStrings.clear()
			s[t].pushStrings.clear()
			t+=1

	except:
		pass
	stringsTempWide.clear()
	pushStringsTemp.clear()
	stringsTemp.clear()

def clearImports():
	global bEvilImportsFound
	FoundApisName.clear()
	bEvilImportsFound = False

def printToJson(bpAll, outputData):	#Output data to json
	#takes outputdata from generateoutputdata
	global bpPushRet
	global bpFstenv
	global bpSyscall
	global bpHeaven
	global bpPEB
	global bpCallPop
	global bpModules
	global bpEvilImports
	global bpStrings
	global bPushRetFound
	global bDisassemblyFound
	global bFstenvFound
	global bSyscallFound
	global bHeavenFound
	global bPEBFound
	global bCallPopFound
	global shellBit
	global rawHex


	time = datetime.datetime.now()
	filetime = time.strftime("%Y%m%d_%H%M%S")
	time = time.strftime("%Y-%m-%d %H:%M:%S")
	t = 0
	for char in peName:
		if(char == '.'):
			break
		t += 1
	noExtension = peName[0:t]
	if filename == "":
		outfile = peName.split(".")[0]
		outfileName = peName
	else:	
		outfile = filename.split(".")[0]
		outfileName = filename

	#jsonFileName =  os.getcwd() + "\\" + noExtension + "\\output_" + peName + "_" + filetime + ".json"
	jsonFileName =  os.getcwd() + "\\" + outfile + "\\" + outfileName + "_" + filetime + ".json"
	os.makedirs(os.path.dirname(jsonFileName), exist_ok=True)

	#Just clear the output data pushed here if it's not selected
	if not bpAll:
		if not bpPushRet:
			outputData['pushret'] = []
		if not bpCallPop:
			outputData['callpop'] = []
		if not bpFstenv:
			outputData['fstenv'] = []
		if not bpSyscall:
			outputData['syscall'] = []
		if not bpPEB:
			outputData['PEB'] = []
		if not bpHeaven:
			outputData['heavensGate'] = []
		if not bpStrings:
			outputData['strings'] = []
		if not bpEvilImports:
			outputData['imports'] = []
		if not bpModules:
			outputData['modules'] = []


	#create the json file, and write our data to it
	outfile = open(jsonFileName, "w")
	js_ob = json.dumps(outputData, indent = 3)

	outfile.write(js_ob)


def formatPrint(i, add4, addb, pe=False, syscall=False):


	#print('{1:>{0}}'.format(length, string))
	
	# print("---------> ", len(i.op_str))
	if print_style == "right":
		length = 35
		if not pe:
			val =('{0:<6s} {1:<{2}s} {3:<8s}'.format(i.mnemonic, i.op_str, length, add4))
			return val
		else:
			val =('{0:<6s} {1:<{2}s} {3:<12s} {4:<10}'.format(i.mnemonic, i.op_str, length, add4, "(offset " + addb + ")"))
			return val
	elif print_style == "left":
		length = 30
		if not pe:
			val =('{0:<10s} {1:<4s} {2} '.format(add4, i.mnemonic, i.op_str ))
			return val
		else:
			val =('{0:<10s} {1:<4s} {2:<{3}s} {4}'.format(add4, i.mnemonic, i.op_str , length, "(offset " + addb + ")"))

			# val =('{0:<6s} {1:<{2}s} {3:<12s} {4:<10}'.format(i.mnemonic, i.op_str, length, add4, "(offset " + addb + ")"))
			return val
	else:
		print("Error: format style is not correct, it should be either right, or left.")
		sys.exit()

def generateOutputData(): #Generate the dictionary for json out
	global bPushRetFound
	global bDisassemblyFound
	global bFstenvFound
	global bSyscallFound
	global bHeavenFound
	global bPEBFound
	global bCallPopFound
	global bStringsFound
	global bDisassemblyFound
	global shellBit
	global rawHex
	global brawHex
	global bstrLit
	global rawData2

	time = datetime.datetime.now()
	epoch = time.timestamp()
	filetime = time.strftime("%Y%m%d'T'%H%M%S%z")
	time = time.strftime("%Y-%m-%d %H:%M:%S")
	# jsonFileName = "output_" + peName + "_" + filetime + ".json"
	jsonFileName = peName + "_" + filetime + ".json"

	#jsonData is a dictionary, we add fields to it below
	jsonData = {}
	jsonData['dateAnalyzed'] = time
	jsonData['secondsSinceEpoch'] = epoch
	jsonData['fileType'] = ''
	jsonData['bits'] = shellBit
	if not rawHex:
		jsonData['modules']=[]
		jsonData['imports']=[]
	if rawHex:
		try:
			jsonData['entryPoint'] = str(hex(shellEntry))
		except:
			jsonData['entryPoint'] = str(shellEntry)

	else:
		jsonData['peInfo'] = []
	if rawHex:
		jsonData['fileType'] = 'rawHex'
	else:
		jsonData['fileType'] = 'PE'
	jsonData['pushret'] = []
	jsonData['callpop'] = []
	jsonData['PEB'] = []
	jsonData['fstenv'] = []
	jsonData['heavensGate'] = []
	jsonData['syscall'] = []
	if not rawHex:
		jsonData['strings'] = {}
	else:
		# print("---------------- RAWHEX-------------------")
		jsonData['strings'] = []

	jsonData['shellcode'] = {'rawhex':brawHex,
							 'strlit':bstrLit 
							}

	#We grab the saved info, and loop through it, adding an object to the respective category's list and add a new object for each. The method is the same as the printsaved____() functions
	if(bit32):
		callCS = cs
	else:
		callCS = cs64
	#Handle Sections
	if(rawHex):
		entryPoint = str(hex(m[o].entryPoint))
		jsonData['entryPoint'] = entryPoint
	else:
		t = 0
		# print("Sections --> ", s)
		for sec in sections:
			try:
				secName = s[t].sectionName.decode()
			except:
				secName = s[t].sectionName
			entryPoint = str(hex(s[t].entryPoint))
			virtualAddress =  str(hex(s[t].VirtualAdd))
			imageBase = str(hex(s[t].ImageBase))
			virtualSize =  str(hex(s[t].vSize))
			secSize = str(hex(s[t].SizeOfRawData))
			imageBasePlusVirtualAdd = str(hex(s[t].startLoc))
			DEP = str(s[t].depStatus)
			ASLR = str(s[t].aslrStatus)
			SEH = str(s[t].sehSTATUS)
			CFG = str(s[t].CFGstatus)
			Sha256 =s[t].Hash_sha256_section
			md5 = s[t].Hash_md5_section
			jsonData['peInfo'].append({"sectionName":secName, "entryPoint":{"offset":entryPoint, "imageBasePlusVirtualAdd":imageBasePlusVirtualAdd, "imageBase":imageBase}, "virtualAddress":virtualAddress, "virtualSize":virtualSize, "sectionSizeOfRawData":secSize, "mitigations":{"DEP":DEP, "ASLR":ASLR, "SEH":SEH, "CFG":CFG}, "hashes":{"Sha256":Sha256, "md5":md5}})
			t+=1


# "strings": {
#       ".text": [
#          {
#             "type": "string",
#             "section": ".text",
#             "offset": "0x263",
#             "address": "0x401263",
#             "length": "12",
#             "value": "SWharyAhLoad"
#          },
#          {
#             "type": "string",
#             "section": ".text",
#             "offset": "0x27d",
#             "address": "0x40127d",
#             "length": "17",
#             "value": "cthrotehualPhVirt"
#          },
	if (bStringsFound):
		if(rawHex):

			# jsonData['strings'] = {'shellcode':[]}
			for value,offset,wordLength in stringsTemp:
				jsonData['strings'].append({'type':'ascii', 
							'offset': hex(offset), 
							'length':str(wordLength), 
							'value':str(value),
							'source':'shellcode'})

			# 	jsonData['strings'][]
			# 	print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
			for value,offset,wordLength in stringsTempWide:
				jsonData['strings'].append({'type':'unicode', 
							'offset': hex(offset), 
							'length':str(wordLength), 
							'value':str(value),
							'source':'shellcode'})

			# 	print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z)))
			# #word4, offset, wordLength,instructionsLength
			for value,offset,wordLength, instLen in pushStringsTemp:
				jsonData['strings'].append({'type':'pushString', 
							'offset': hex(offset), 
							'length':str(wordLength), 
							'value':str(value),
							'source':'shellcode'})
			# 	print ("\t"+ str(word4) + "\t" + hex(offset) + "\t" + str(hex(wordLength)))
			
		#global stringsTemp ascii
		#global stringsTempWide
		#global pushStringsTemp
		else:

			t = 0
			for secNum in range(len(s)):
				jsonData['strings'][s[t].sectionName.decode()] = []
				for value,offset,length  in s[t].Strings:
					jsonData['strings'][s[t].sectionName.decode()].append({'type':'string', 
							'section':s[t].sectionName.decode(), 
							'offset': hex(offset + s[t].VirtualAdd), 
							"address":hex(s[t].ImageBase + s[t].VirtualAdd + offset), 
							'length':str(length), 
							'value':str(value)})
				for value,offset,length in s[t].wideStrings:
					#format widestring to string
					tempVal = ''
					j = 0
					for char in value:
						if not (j%2):
							tempVal += char
						j+=1
					jsonData['strings'][s[t].sectionName.decode()].append({'type':'wideString', 
						'section':s[t].sectionName.decode(), 
						'offset': hex(offset + s[t].VirtualAdd), 
						"address":hex(s[t].ImageBase + s[t].VirtualAdd + offset), 
						'length':str(length), 
						'value':tempVal})
				#for value, offset, length in s[t].pushStrings:
				#word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength
				for word4, offset, offsetVA, offsetpImage, wordLen, instLen in s[t].pushStrings:

					# jsonData['strings'][s[t].sectionName.decode()].append({'type':'pushString', 
					# 														'section':s[t].sectionName.decode(), 
					# 														"word4":word4, 'offset': hex(offset), 
					# 														"address":hex(s[t].ImageBase + s[t].VirtualAdd + offset), 
					# 														'length':str(length), 
					# 														'value':str(value)})

					jsonData['strings'][s[t].sectionName.decode()].append({'type':'pushString',
																			'section':s[t].sectionName.decode(),
																			"value":word4, 
																			'offset': hex(offset + s[t].VirtualAdd), 
																			'length':str(wordLen) 
																			})
				t+=1
			# for value,offset,length  in stringsTemp:
			# 	jsonData['strings'][s[t].sectionName.decode()].append({'type':'tempString', 'section':s[t].sectionName.decode(), 'offset': hex(offset), "address":hex(s[t].ImageBase + s[t].VirtualAdd + offset), 'length':sstr(length), 'value':str(value)})
	if (bPushRetFound):
		if(rawHex):
			# for i in m[o].save_PushRet_info:

			for item in m[o].save_PushRet_info:
				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				points = item[4]
				pushOffset = item[5]
				# print ("printoffset", pushOffset)
				pushAdd=int(pushOffset[0],16)
				retOffset = item[6]
				# print ("retOffset", retOffset)
				printEnd = int(retOffset, 16) + 15
				# print ("printEnd", printEnd)
				CODED2 = rawData2[address:(printEnd)]
				# print ("1",binaryToStr(CODED2))
				# print ("\n2",binaryToStr(rawData2[pushAdd:(printEnd)]))

			

				val =""
				val2 = []
				val3 = []
				val5 =[]
				stopRet=False
				for i in callCS.disasm(CODED2, address):
					if(rawHex):
						add4 = hex(int(i.address))
						addb = hex(int(i.address))
					else:
						add = hex(int(i.address))
						addb = hex(int(i.address +  section.VirtualAdd))
						add2 = str(add)
						add3 = hex (int(i.address + section.startLoc	))
						add4 = str(add3)

					val = formatPrint(i, add4, addb)
					# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
					checkRet= re.search( retOffset, val, re.M|re.I)
					# if str(retOffset) == addb:
					# 	val5.append(val)
					# 	break
					# else:
					# 	val5.append(val)
					if checkRet:
						if not stopRet:
							val5.append(val)
							stopRet = True
						else:
							pass
					if not stopRet:
						val5.append(val)

				# for i in callCS.disasm(CODED2, address):
				# 	if(rawHex):
				# 		add4 = hex(int(i.address))
				# 		addb = hex(int(i.address))
				# 	else:
				# 		add = hex(int(i.address))
				# 		addb = hex(int(i.address +  section.VirtualAdd))
				# 		add2 = str(add)
				# 		add3 = hex (int(i.address + section.startLoc	))
				# 		add4 = str(add3)
				# 	val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
				# 	val5.append(val)

				jsonData['pushret'].append({'address': hex(address), 'pushOffset':pushOffset, 'retOffset': retOffset, "modSecName": modSecName, "disassembly":val5, "internalData" : {'secNum': secNum, 'NumOpsDis': NumOpsDis,'points': points}})
		else:
			for section in s:
				for item in section.save_PushRet_info:
					address = item[0]
					NumOpsDis = item[1]
					modSecName = item[2].decode()
					secNum = item[3]
					points = item[4]
					pushOffset = item[5]
					retOffset = item[6]
					section = s[secNum]
					printEnd = int(retOffset, 16) + 3 - section.VirtualAdd
					val =""
					val2 = []
					val3 = []
					address2 = address + section.ImageBase + section.VirtualAdd
					val5 =[]
					CODED2 = section.data2[address:printEnd]
					CODED3 = CODED2
					stopRet = False
					# print("pushret generat function", CODED3.hex())
					for i in callCS.disasm(CODED3, address):
						add = hex(int(i.address))
						addb = hex(int(i.address +  section.VirtualAdd))
						add2 = str(add)
						add3 = hex (int(i.address + section.startLoc))
						add4 = str(add3)
						val = formatPrint(i, add4, addb, pe=True)

						# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
						val2.append(val)
						val3.append(add2)
						checkRet= re.search( retOffset, val, re.M|re.I)
						if checkRet:
							if not stopRet:
								val5.append(val)
								stopRet = True
							else:
								pass
						if not stopRet:
							val5.append(val)
						# val5.append(val)
					pOut=""
					pSize=len(pushOffset)-1
					# t=0
					
					
					# for p in pushOffset:
						

					# 	if t<pSize:
					# 		pOut+=p + ", "
					# 	else:
					# 		pOut+=p
					# 	t+=1
					# pushOffset=pOut
					jsonData['pushret'].append({'address': hex(address),'pushOffset':pushOffset, 'retOffset': retOffset, "modSecName": modSecName, "disassembly":val5, "internalData" : {'secNum': secNum, 'NumOpsDis': NumOpsDis,'points': points}})

	if (bCallPopFound):
		if(rawHex):
			for item in m[o].save_Callpop_info:
				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				distance = item[4]
				pop_offset = item[5]
				CODED2 = rawData2[(address):int(pop_offset, 16) + 1]
				CODED3 = CODED2
				val =""
				val2 = []
				val3 = []
				val5 =[]
				for i in callCS.disasm(CODED2, address):
					if(rawHex):
						add4 = hex(int(i.address))
						addb = hex(int(i.address))
					# else:
					# 	add = hex(int(i.address))
					# 	addb = hex(int(i.address +  section.VirtualAdd))
					# 	add2 = str(add)
					# 	add3 = hex (int(i.address + section.startLoc))
					# 	add4 = str(add3)
					val = formatPrint(i, add4, addb)
					# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
					val5.append(val)
				jsonData['callpop'].append({'address':hex(address), 'modSecName':modSecName, 'pop_offset':pop_offset, 'distance':distance,"disassembly":val5, "internalData" : {'secNum':secNum,'NumOpsDis':NumOpsDis}})
		else:
			for section in s:
				for item in section.save_Callpop_info:
					# address = item[0]
					origAddr = item[0]
					NumOpsDis = item[1]
					modSecName = item[2].decode()
					secNum = item[3]
					distance = item[4]
					pop_offset = item[5]
					# print("pop_offset in generateoutputdata", pop_offset)
					# input()
					address = origAddr + distance
					section = s[secNum]
					CODED2 = section.data2[(origAddr):(address+NumOpsDis)]
					# print(CODED2)
					# input()
					# CODED2 = section.data2[(address):(address+1+distance)]
					CODED3 = CODED2
					val =""
					val2 = []
					val3 = []
					val5 =[]
					# print("Disassm", CODED3.hex())
					# input()
					# print("origAddr: ", address, "CODED3", CODED3)
					# print("origAddr: ", origAddr, "CODED3", CODED3, "Address", address)
					# print("Generate output", CODED3.hex())
					for i in callCS.disasm(CODED3, origAddr):
						add = hex(int(i.address))
						addb = hex(int(i.address +  section.VirtualAdd))
						add2 = str(add)
						add3 = hex (int(i.address + section.startLoc	))
						add4 = str(add3)
						val = formatPrint(i, add4, addb, pe=True)

						# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
						val2.append(val)
						val3.append(add2)
						val5.append(val)
						if(addb == pop_offset):
							break
					address = origAddr + section.VirtualAdd
					jsonData['callpop'].append({'address':hex(address), 'modSecName':modSecName, 'pop_offset':pop_offset, 'distance':distance,"disassembly":val5, "internalData" : {'secNum':secNum,'NumOpsDis':NumOpsDis}})

	if (bFstenvFound):
		if(rawHex):
			for item in m[o].save_FSTENV_info:
				address = item[0]
				NumOpsDis = item[1]
				NumOpsBack = item[2]
				modSecName = item[3]
				secNum = item[4]
				FPU_offset  = item[5]
				FSTENV_offset = item[6]
				printEnd = item[7]
				CODED2 = rawData2[int(FPU_offset, 16):(int(printEnd, 16))]
				CODED3 = CODED2
				val =""
				val2 = []
				val3 = []
				val5 =[]
				for i in callCS.disasm(CODED2, (int(FPU_offset,16))):
					if(rawHex):
						add4 = hex(int(i.address))
						addb = hex(int(i.address))
					val = formatPrint(i, add4, addb)

					# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
					val5.append(val)
				jsonData['fstenv'].append({'address':hex(address), 'modSecName':modSecName, 'FPU_offset':FPU_offset, 'FSTENV_offset':FSTENV_offset,"disassembly":val5, "internalData" : {'secNum':secNum, 'NumOpsDis':NumOpsDis, 'NumOpsBack':NumOpsBack, 'printEnd':printEnd}})
		else:
			for section in s:
				for item in section.save_FSTENV_info:
					address = item[0]
					NumOpsDis = item[1]
					NumOpsBack = item[2]
					modSecName = item[3].decode()
					secNum = item[4]
					FPU_offset  = item[5]
					FSTENV_offset = item[6]
					printEnd = item[7]
					section = s[secNum]
					CODED2 = section.data2[(address - NumOpsBack):(address+NumOpsDis)]
					CODED3 = CODED2
					val =""
					val2 = []
					val3 = []
					val5 =[]
					for i in callCS.disasm(CODED3, address):
						add = hex(int(i.address))
						addb = hex(int(i.address +  section.VirtualAdd - NumOpsBack))
						add2 = str(add)
						add3 = hex (int(i.address + section.startLoc - NumOpsBack))
						add4 = str(add3)
						val = formatPrint(i, add4, addb, pe=True)

						# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
						val2.append(val)
						val3.append(add2)
						val5.append(val)
						if str(FSTENV_offset) == addb:
							break
						# if(addb == printEnd):
							# break
					jsonData['fstenv'].append({'address':hex(address), 'modSecName':modSecName, 'FPU_offset':FPU_offset, 'FSTENV_offset':FSTENV_offset,"disassembly":val5, "internalData" : {'secNum':secNum, 'NumOpsDis':NumOpsDis, 'NumOpsBack':NumOpsBack, 'printEnd':printEnd}})

	#jsonheav
	if (bHeavenFound):
		if(rawHex):
			for item in m[o].save_Heaven_info:
				address = hex(item[0])
				NumOpsDis = item[1]
				NumOpsBack = item[2]
				modSecName = item[3]
				secNum = item[4]
				offset = item[5]
				pushOffset = item[6]
				destLocation = item[7]
				converted = item[8]
				pivottype = item[9]
				if(pivottype == "ljmp/lcall"):
					converted = converted[-1:]
				elif(pivottype == "retf"):
					converted = converted[-5:]
				converted2 = []
				for line in converted:
					line = line.replace("\t", " ")
					converted2.append(line)
				converted = converted2

				jsonData['heavensGate'].append({'address':address, 'modSecName':modSecName, 'pushOffset':pushOffset, 'heaven_offset':offset, 'destLocation':destLocation, "disassembly":converted, "internalData" : {'secNum':secNum, 'NumOpsDis':NumOpsDis, 'NumOpsBack':NumOpsBack, 'pivottype':pivottype}})
				#Heaven Item: 0 | Section: -1 | Section name: rawHex | Heaven's Gate offset: 0x1ad
		else:
			for section in s:
				for item in section.save_Heaven_info:
					address = item[0]
					NumOpsDis = item[1]
					NumOpsBack = item[2]
					modSecName = item[3].decode()
					secNum = item[4]
					offset = item[5]
					pushOffset = item[6]
					destLocation = item[7]
					for char in range(len(destLocation)):
						if (destLocation[char] == '\t'):
							destLocation = destLocation[0:char-1]
							break
					pivottype = item[8]
					val =""
					val2 = []
					val3 = []
					val5 =[]
					bytesCompensation = 18
					if(pivottype == "ljmp/lcall"):
						start = int(offset, 16) - section.VirtualAdd
						#The 7 is for the ljmp assembly mnemonic
						CODED2 = section.data2[(start):(start+7)]
					elif(pivottype == "retf"):
						start = int(offset, 16) - section.VirtualAdd
						#The two bytes is for the retf
						CODED2 = section.data2[(start - bytesCompensation):start + 2]

					CODED3 = CODED2
					if(pivottype == "ljmp/lcall"):
						bytesCompensation = 0
					elif(pivottype == "retf"):
						bytesCompensation = 18
					for i in callCS.disasm(CODED3, start - bytesCompensation):
						add = hex(int(i.address))
						addb = hex(int(i.address +  section.VirtualAdd))
						add2 = str(add)
						add3 = hex (int(i.address + section.startLoc))
						add4 = str(add3)
						val = formatPrint(i, add4, addb, pe=True)

						# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
						val2.append(val)
						val3.append(add2)
						val5.append(val)
					# print("Push offset: ", pushOffset)
					# input()
					pushOffset = str(hex(pushOffset))
					# print("Offset", pushOffset)
					jsonData['heavensGate'].append({'address':hex(address), 'modSecName':modSecName, 'pushOffset':pushOffset, 'heaven_offset':offset, 'destLocation':destLocation, "disassembly":val5, "internalData" : {'secNum':secNum, 'NumOpsDis':NumOpsDis, 'NumOpsBack':NumOpsBack, 'pivottype':pivottype}})
	#jsonpeb
	if (bPEBFound):
		if(rawHex):
			if shellBit == 64:
				callCS = cs64
			else:
				callCS = cs
			for item in m[o].save_PEB_info:
				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				points = item[4]
				val =""
				val2 = []
				val3 = []
				#address2 = address + section.ImageBase + section.VirtualAdd
				val5 =[]
				CODED2 = rawData2[address:(address+NumOpsDis)]
				for i in callCS.disasm(CODED2, address):
					if(rawHex):
						add4 = hex(int(i.address))
						addb = hex(int(i.address))
					else:
						add = hex(int(i.address))
						addb = hex(int(i.address +  section.VirtualAdd))
						add2 = str(add)
						add3 = hex (int(i.address + section.startLoc	))
						add4 = str(add3)
					val = formatPrint(i, add4, addb)

					# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
					if "db" in val:
						break

					val5.append(val)
					if "ret" in val:
						break
				jsonData['PEB'].append({'address':hex(address), 'modSecName':modSecName,"disassembly":val5, "internalData":{'secNum':secNum, 'NumOpsDis':NumOpsDis, 'points':points}})
		else:
			for section in s:
				for item in section.save_PEB_info:
					if(shellBit == 64):
						address = item[0]
						NumOpsDis = item[1]
						modSecName = item[2].decode()
						secNum = item[3]
						points = item[4]
						val =""
						val2 = []
						val3 = []
						val5 =[]
						CODED2 = section.data2[address:(address+NumOpsDis)]
						CODED3 = CODED2
						for i in cs64.disasm(CODED3, address):
							add = hex(int(i.address))
							addb = hex(int(i.address +  section.VirtualAdd))
							add2 = str(add)
							add3 = hex (int(i.address + section.startLoc	))
							add4 = str(add3)
							val = formatPrint(i, add4, addb, pe=True)

							# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
							val2.append(val)
							val3.append(add2)
							val5.append(val)
						jsonData['PEB'].append({'address':hex(address), 'modSecName':modSecName,"disassembly":val5, "internalData":{'secNum':secNum, 'NumOpsDis':NumOpsDis, 'points':points}})
					else:
						address = item[0]
						NumOpsDis = item[1]
						modSecName = item[2].decode()
						secNum = item[3]
						points = item[4]
						tib = str(item[5])
						ldr = str(item[6])
						mods = item[7]
						# adv = item[8]
						adv = []
						adv2=""
						for ad in item[8]:
							# try:
							# 	adv2+=ad
							# 	if ad==-1:
							# 		adv2="N/A"
							# except:
							# 	pass
							try:
								adv.append(ad)
							except:
								adv.append(hex(ad))


						val =""
						val2 = []
						val3 = []
						val5 =[]
						CODED2 = section.data2[address:(address+NumOpsDis)]
						CODED3 = CODED2
						for i in callCS.disasm(CODED3, address):
							add = hex(int(i.address))
							addb = hex(int(i.address +  section.VirtualAdd))
							add2 = str(add)
							add3 = hex (int(i.address + section.startLoc	))
							add4 = str(add3)
							val = formatPrint(i, add4, addb, pe=True)

							# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
							val2.append(val)
							val3.append(add2)
							val5.append(val)

						# if -1 in adv:
						# 	adv = 'N/A'
						# else:
						# 	adv = ', '.join(adv)
						

						jsonData['PEB'].append({'address':hex(address), 'modSecName':modSecName, 'tib':tib, 'ldr':ldr, 'mods':mods, 'adv':adv,"disassembly":val5, "internalData":{'secNum':secNum, 'NumOpsDis':NumOpsDis, 'points':points}})
	#jsonsys
	if (bSyscallFound):
		if(rawHex):
			for item in m[o].save_Egg_info:
				address = item[0]
				NumOpsDis = item[1]
				NumOpsBack = item[2]
				modSecName = item[3]
				secNum = item[4]
				eax = item[5]
				c0_offset = item[6]
				converted = item[7]
				syscalls = "not found"
				# CODED2 = rawData2[address:(printEnd)]

				# print(NumOpsDis)
				CODED2 = rawData2[address:(address+20)]
				converted = [string.replace("\t", "") for string in converted]
				if(eax != "unknown"):
					# syscalls = returnSyscalls(int(eax, 0))
					# print(syscalls)
					# input()
					syscalls = getSyscallRecent(int(eax, 0), 64, "print2Json")

				CODED3 = CODED2
				val5 = []
				for i in callCS.disasm(CODED3, address):

					add4 = hex(int(i.address))
					addb = hex(int(i.address))
					val = formatPrint(i, add4, addb)
					val5.append(val)
					# print(i.mnemonic, i.op_str, add4, addb)
					# val = formatPrint(i, add4, addb, pe=True)

					# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
					# val2.append(val)
					# val3.append(add2)
					# val5.append(val)

					if c0_offset == addb:
						break

				# for idx, val in enumerate(converted):
				# 	if val.find("(offset") != -1:
						
				# 		converted[idx] = val[:val.find("offset")-18]
				# allInstr = conerted.split(" ")
				# mnemonic = allInstr[0]
				# add4 = allInstr[-3]
				# addb = allInstr[-2:]
				# op_str = allInstr[1:-4]
				# converted = formatPrint()

				# print(converted)
				# input()

				# print(val5)

				jsonData['syscall'].append({'address':hex(address), 'modSecName':modSecName, 'eax':eax, 'c0_offset':c0_offset, "disassembly":val5, "syscalls":syscalls,"internalData":{'NumOpsDis':NumOpsDis, 'NumOpsBack':NumOpsBack, 'secNum':secNum}})
		else:
			for section in s:
				for item in section.save_Egg_info:
					address = item[0]
					NumOpsDis = item[1]
					NumOpsBack = item[2]
					modSecName = item[3].decode()
					secNum = item[4]
					eax = item[5]
					c0_offset = item[6]
					val =""
					val2 = []
					val3 = []
					val5 =[]
					CODED2 = section.data2[(address-NumOpsBack):(address+NumOpsDis)]
					CODED3 = CODED2
					for i in callCS.disasm(CODED3, address):
						add = hex(int(i.address))
						addb = hex(int(i.address +  section.VirtualAdd - NumOpsBack))
						add2 = str(add)
						add3 = hex (int(i.address + section.startLoc	- NumOpsBack))
						add4 = str(add3)
						val = formatPrint(i, add4, addb, pe=True)

						# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
						val2.append(val)
						val3.append(add2)
						val5.append(val)
						if c0_offset == addb:
							break
					syscalls = "not found"
					if(eax != "unknown"):
						# syscalls = returnSyscalls(int(eax, 0))
						syscalls = getSyscallRecent(int(eax, 0), 64, "print2Json")
					if 'syscall' in val5[-1]:
						offsetLabel = 'syscall offset'
					elif 'int' in val5[-1]:
						offsetLabel = 'int offset'
					else:
						offsetLabel = 'c0_offset'
					jsonData['syscall'].append({'address':hex(address), 'modSecName':modSecName, 'eax':eax, offsetLabel:c0_offset,"disassembly":val5, "syscalls":syscalls, "internalData":{'NumOpsDis':NumOpsDis, 'NumOpsBack':NumOpsBack, 'secNum':secNum}})
	if(bModulesFound):
		t = 0
		for x in IATs.foundDll:
			try:
				x = x.decode()
			except:
				pass
			try:
				IATs.path[t] = IATs.path[t].decode()
			except:
				pass
			try:
				IATs.originate[t] = IATs.originate[t].decode()
			except:
				pass
			jsonData['modules'].append({'position':t, 'module':(x), 'path':IATs.path[t], 'caller':IATs.originate[t]})
			t+=1
	if(bEvilImportsFound):
		for dll, api, offset in FoundApisName:
			jsonData['imports'].append({'dll':dll.decode(), 'api':api.decode(), 'address':str(offset)})

	return jsonData


def dontPrint():
	sys.stdout = open(os.devnull, 'w')
	# sys.stdout = open('nul', 'w')

def allowPrint():
	sys.stdout = sys.__stdout__

def printToText(outputData):	#Output data to text doc
	#output data from generateoutputdata
	global bPushRetFound
	global bDisassemblyFound
	global bDisassembly
	global bFstenvFound
	global bSyscallFound
	global bHeavenFound
	global bPEBFound
	global bCallPopFound
	global bEvilImportsFound
	global bModulesFound
	global bpModules
	global bpEvilImports
	global shellBit
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp
	global syscallString
	global gDisassemblyText
	global save_bin_file



	data = outputData
	#Used for section info
	if (rawHex):
		info = showBasicInfo()
	else:
		info = showBasicInfoSections()

	time = datetime.datetime.now()
	epoch = time.timestamp()
	filetime = time.strftime("%Y%m%d_%H%M%S")
	time = time.strftime("%Y-%m-%d %H:%M:%S")
	t = 0
	for char in peName:
		if(char == '.'):
			break
		t += 1
	noExtension = peName[0:t]
	#print("********************************** ", peName, " **********************")
	if filename == "":
		outfile = peName.split(".")[0]
		outfileName = peName
	else:	
		outfile = filename.split(".")[0]
		outfileName = filename


	# txtFileName =  os.getcwd() + "\\" + outfile + "\\output_" + outfileName + "_" + filetime + ".txt"
	txtFileName =  os.getcwd() + "\\" + outfile + "\\" + outfileName + "_" + filetime + ".txt"

	# txtDis = open(directory+"disassembly\\"+filename[:-4]+"-disassembly.txt", "w")

	
	os.makedirs(os.path.dirname(txtFileName), exist_ok=True)
	text = open(txtFileName, "w")


	disFileName = os.getcwd() + "\\" + outfile + "\\" + outfileName + "-disassembly.txt"
	binFileName = os.getcwd() + "\\" + outfile + "\\" + outfileName + "-disassembly.bin"
	disasm = open(disFileName, "w")
	disasm.write(gDisassemblyText)
	disasm.close()

	if save_bin_file:
		binasm = open(binFileName, "w")
		binasm.write(gDisassemblyText)
		binasm.close()


	outString =  'Filename: ' + outfileName + "\n"
	outString += 'File Type: ' + outputData['fileType'] + "\n"
	outString += 'Bits: ' + str(shellBit) + "\n"
	outString += 'Date Analyzed: ' + time + "\n"
	outString += "Seconds since last epoch: " + str(epoch) + "\n"
	outString += '\nSection info\n\n'
	outString += info


	#If we've found and are printing a category, then do so
	if bpModules and bModulesFound:
		outString+="\n\n*******\nModules\n*******\n\n"
		t=0
		for x in IATs.foundDll:
			try:
				x = x.decode()
			except:
				pass
			try:
				IATs.path[t] = IATs.path[t].decode()
			except:
				pass
			try:
				IATs.originate[t] = IATs.originate[t].decode()
			except:
				pass
			outString += (('{:<15s} {:<40s} {:<5} {:<0}').format(x, IATs.path[t], " from ", IATs.originate[t])) + "\n"
			t+=1
	if bpEvilImports and bEvilImportsFound:
		outString+="\n\n*****************\nImports\n*****************\n"
		# outString+= showImports()
		for api, dll, offset in FoundApisName:
			try:
				outString += (' {:<14s} {:<32s} {:<0}'.format(api.decode(), dll.decode(), str(offset))) + "\n"
			except:
				pass

	if bpStrings:
		if bStringsFound:
			outString+="\n\n***********\nStrings\n***********\n\n"
			outString += "Note: The offset value is created by adding the offset plus the section virtual address."
			t=0
			try:
				if not rawHex:
					if (len(s[t].Strings)) or (len(s[t].wideStrings)) or (len(s[t].pushStrings)):
						outString += "Strings from PE file:\n"

						for secNum in range(len(s)):
							if (len(s[t].pushStrings)) or (len(s[t].Strings)) or (len(s[t].wideStrings)):
								outString += "Section: " + s[t].sectionName.decode()
								outString += ("\n")
								# for x,y,z  in s[t].Strings:
								# 	# outString += ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z))) 
								# 	outString += ('{:<5}{:<32s}{:<8s}{:<4s}'.format("",str(x), str(hex(y)),str(hex(z))))
								# 	outString += ("\n")
								# outString += ("**Wide Strings**\n")
								# for x,y,z in s[t].wideStrings:
								# 	# outString += str("\t"+ str(x) + "\t" + str(hex(y)))
								# 	outString += ('{:<5}{:<32s}{:<8s}{:<4s}'.format("",str(x), str(hex(y)),str(hex(z))))
								# 	outString += ("\n")
								#SWharyAhLoad                    0x401263   Offset: 0x263   size: 12   Ascii
								for x,y,z  in s[t].Strings:
									outString += ('{:<5} {:<32s} {:<10s} {:<16} {:<10} {:<10}'.format("",str(x), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)), "Offset: " + str(hex(y+s[t].VirtualAdd)),"size: "+ str(int(z)) , "Ascii"))
									outString += ("\n")
								for x,y,z in s[t].wideStrings:
									tempX = ''
									j = 0
									for char in x:
										if not (j%2):
											tempX+=char
										j+=1
									# outString += ('{:<5} {:<32s} {:<20s} {:<11s} {:<4}'.format("",str(tempX), "Offset: " + str(hex(y)),"Address: " + str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"Length: "+ str(int(z))))
									outString += ('{:<5} {:<32s} {:<10s} {:<16} {:<10} {:<10}'.format("",str(x), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)), "Offset: " + str(hex(y+s[t].VirtualAdd)),"size: "+ str(int(z)) , "Unicode"))
									outString += ("\n")

								outString += ("\n\n**Push Stack Strings**\n\n")
								if not len(s[t].pushStrings):
									outString+="none\n"
								for word4, offset, offsetVA,offsetPlusImagebase, wordLength,instLen in s[t].pushStrings:
								#for x, y in s[t].pushStrings:
									# outString += ("\t"+ str(x) + "\t" + str(hex(y)))
									# outString += ('{:<5} {:<32s} {:<20s} {:<11s} {:<4}'.format("",str(word4), "Offset: " + str(hex(offset)),"Address: " + str(hex(y + s[t].ImageBase + s[t].VirtualAdd)),"Length: "+ str(int(wordLength))))
									outString += ('{:<5} {:<32s} {:<10s} {:<16} {:<10} {:<10}'.format("",str(word4), str(hex(y + s[t].ImageBase + s[t].VirtualAdd)), "Offset: " + str(hex(offset+s[t].VirtualAdd)),"size: "+ str(int(wordLength)) , "Stack String"))
									outString += ("\n")
								outString += ("\n")
							t+=1
				else:
					outString += "Strings from shellcode:\n\n"
						#stringsTemp
						#stringsTempWide
						#pushStringsTemp
			
			# 	print ("\t"+ str(word4) + "\t" + hex(offset) + "\t" + str(hex(wordLength)))
					if(len(stringsTemp) > 0):
						for x, y, z in stringsTemp:
							outString += ('{:<5} {:<32s} {:<16s} {:<8s} {:<10}\n'.format("",str(x), "Offset: " + str(hex(y)),"size: "+ str(int(z)), "Ascii"))
					outString += "\n"
					if(len(stringsTempWide) >0):
						for x, y, z in stringsTempWide:
							outString += ('{:<5} {:<32s} {:<16s} {:<8s} {:<10}\n'.format("",str(x), "Offset: " + str(hex(y)),"size: "+ str(int(z)), "Unicode"))
					outString += "\n"	
					if(len(pushStringsTemp) > 0):
						outString += ("\n\n**Push Stack Strings**\n\n")
						for word4, offset, wordLength, instLen in pushStringsTemp:
							outString += ('{:<5} {:<32s} {:<16s} {:<8s} {:<10}\n'.format("",str(word4), "Offset: " + str(hex(offset)),"size: "+ str(int(wordLength)), "Stack String"))
					outString += "\n"



			except Exception as e:
				print(traceback.format_exc())
				outString += str(e)
				outString += "\n"
				pass
			
		else:
			outString+="\nNo strings found.\n"

	if bpPushRet:
		if bPushRetFound:
			outString+="\n\n***********\nPush ret\n***********\n\n"
			itemNum = 0
			#outString+="********************************************************************************************************\n"

			for item in data['pushret']:
				outString+="********************************************************************************************************\n"
				
				pOffset = item['pushOffset']
				pOffset = ', '.join(pOffset)
				pOffset = str(pOffset)
				
				# print(pOffset)
				# input()
				outString += "Push ret Item: " + str(itemNum)
				if(rawHex):
					outString += " | Section: " + str(item['internalData']['secNum']) + " | Section name: " + str(item['modSecName'])
				else:
					outString += " | Module: " + item['modSecName']

				outString += " | PUSH Offset: " + pOffset + " | RET Offset: " + str(item['retOffset']) + "\n"
				for line in item['disassembly']:
					outString+=line + "\n"
				itemNum += 1
		else:
			outString+="\nNo push ret instructions found.\n"
	if bpFstenv:
		if bFstenvFound:
			outString+="\n\n***********\nFstenv\n***********\n\n"
			itemNum = 0

			for item in data['fstenv']:
				outString+="********************************************************************************************************\n"

				outString += "Fstenv Item: " + str(itemNum)
				if(rawHex):
					outString += " | Section: " + str(item['internalData']['secNum']) + " | Section name: " + str(item['modSecName']) + " | FPU Offset: " + str(item['FPU_offset']) + " | FSTENV Offset: " + str(item['FSTENV_offset'])
				else:
					outString += " | Module: " + item['modSecName'] + " | FPU Offset: " + str(item['FPU_offset']) + " | FSTENV Offset: " + str(item['FSTENV_offset'])
				outString += '\n'
				for line in item['disassembly']:

					outString+=line + "\n"
				itemNum += 1
		else:
			outString+="\nNo fstenv instructions found.\n"

	if bpCallPop:
		if bCallPopFound:
			outString+="\n\n***********\nCall Pop\n***********\n\n"
			itemNum = 0

			for item in data['callpop']:
				outString+="********************************************************************************************************\n"

				outString += "Call pop Item: " + str(itemNum)
				if(rawHex):
					outString += " | Section: " + str(item['internalData']['secNum']) + " | Section name: " + str(item['modSecName'])
				else:
					outString += " | Call address: " + str(item['address']) + " | Pop offset: " + str(item['pop_offset']) + " | Distance from call: " + str(hex(item['distance']))
				outString += "\n"
				for line in item['disassembly']:
					outString+=line + "\n"
				itemNum += 1
		else:
			outString+="\nNo call pop instructions found.\n"

	if bpSyscall:
		if bSyscallFound:
			outString+="\n\n***************\nWindows syscall\n***************\n\n"
			itemNum = 0


			for item in data['syscall']:
				if 'c0_offset' in item:
					offsetLabel = 'c0_offset'
					offString = ' | 0xc0 offset: '
				elif 'syscall offset' in item:
					offsetLabel = 'syscall offset'
					offString = ' | syscall offset: '
				elif 'int offset' in item:
					offsetLabel = 'int offset'
					offString = ' | int offset: '
				else:
					offsetLabel = 'c0_offset'
					offString = ' | 0xc0 offset: '
				outString+="********************************************************************************************************\n"

				outString += "Syscall Item: " + str(itemNum)
				if(rawHex):
					outString += " | Section name: " + str(item['modSecName'])
				else:
					outString += " | Module: " + item['modSecName']
				outString += " | EAX: " + item['eax'] + offString + item[offsetLabel]
				outString += "\n"
				for line in item['disassembly']:
					outString += line + "\n"
				
				if item['syscalls'] == "not found":
					outString += "\nSyscall cannot be determined\n"

				else:
					outString += "\n"
					outString += getSyscallRecent(int(item['eax'], 0), 64, "print2Text")
					# for line in item['syscalls']:
						# outString += line + "\n"
				itemNum += 1
		else:
			outString+="\nNo syscall instructions found.\n"

	if bpPEB:
		if bPEBFound:
			outString+="\n\n***************\nWalking the PEB\n***************\n\n"
			itemNum = 0

			for item in data['PEB']:
				outString+="********************************************************************************************************\n"

				outString += "PEB Item: " + str(itemNum) + " | Points: " + str(item['internalData']['points'])
				if(rawHex):
					outString += " | Section: " + str(item['internalData']['secNum']) + " | Section name: " + str(item['modSecName'])
				else:
					outString += " | Module: " + item['modSecName']
				outString += "\n"
				try:
					# mods = ', '.join(map(str, item['mods']))
					mods = item['mods']
					mods = ', '.join(mods)
					# print(item['mods'].split(","))
					# print("DEBUG: 16483")
					offString = "Offsets:\n"
					offString += "TIB: " + item['tib'] + "\n"
					offString += "LDR: " + item['ldr'] + "\n"
					offString += "MODS: " + mods + "\n"
					outString += offString + "\n"
					
					
					adv = item['adv']
					for num, value in enumerate(adv):
						if value == -1:
							adv[num] = 'N/A'

					adv = ', '.join(adv)

					# print("DEBUG: 16498")


					offString = "Adv: " + str(adv) + "\n"
					outString += offString + "\n"

				except Exception as e:
					pass
					# print("Exception", e)
				for line in item['disassembly']:
					outString+=line + "\n"
				itemNum += 1
		else:
			outString+="\nNo peb walking instructions found.\n"
		
	if bpHeaven:
		#Heaven Item: 0 | Section: -1 | Section name: rawHex | PushOffset: 0x1211 | Heaven's Gate offset: 0x1ad
		#jsonData['heavensGate'].append({'address':address, 'modSecName':modSecName, 'pushOffset':pushOffset, 'heaven_offset':offset, 'destLocation':destLocation, "disassembly":converted, "internalData" : {'secNum':secNum, 'NumOpsDis':NumOpsDis, 'NumOpsBack':NumOpsBack, 'pivottype':pivottype}})
		if bHeavenFound:
			outString+="\n\n***************\nHeaven's Gate\n***************\n\n"
			itemNum = 0

			for item in data['heavensGate']:
				outString+="********************************************************************************************************\n"

				outString += "Heaven Item: " + str(itemNum) 
				if(rawHex):
					outString += " | Section: " + str(item['internalData']['secNum']) + " | Section name: " + item['modSecName'] + " | PushOffset: "+ hex(item['pushOffset']) + " | Heaven's Gate offset: " + str(item['heaven_offset']) 
				else:
					outString += " | Module: " + item['modSecName'] + " | Heaven's Gate offset: " + str(item['heaven_offset']) + " | Push dest. addr offset: " + item['pushOffset'] + " | Dest. Address: " + str(item['destLocation'])

				outString+= "\n"
				for line in item['disassembly']:
					outString+=line + "\n"
				itemNum += 1
		else:
			outString+="\nNo heaven's gate instructions found.\n"

	if bDisassembly:
		if bDisassemblyFound:
			outString += "\n\n****************\nDisassembly\n****************\n\n"
			outString += gDisassemblyText
	else:
		outString += "\nNo Disassembly found.\n"
	#disassembly = shellDisassemblyStart(filename, "txt")
	#dontPrint()
	#disassembly = takeBytes(rawData2, 0)
	#printAgain()
	
	#disassembly = disassembly.split("Raw Hex:")[0]
	#print(disassembly)
	#outString += "\n\n\n-------------------------- Disassembly --------------------------------\n\n"
	#outString += disassembly
	text.write (outString)
	text.close()

def returnSyscalls(callNum, bit = 64):
	#works the same as getsyscallrecent()
	#returns a list of syscalls to parse
	apiList = identifySyscall(callNum)
	if(bit == 64):
		apiList = apiList[1]
	else:
		apiList = apiList[0]
	if(bit == 64):
		with open('nt64.csv', 'r') as file:
				nt64Csv = csv.reader(file)
				versions = next(nt64Csv)
				versions = versions[1:]
	else:
		with open('nt32.csv', 'r') as file:
				nt32Csv = csv.reader(file)
				versions = next(nt32Csv)
				versions = versions[1:]
	categories = []
	for version in versions:
		version = version.rsplit('(',1)[0]
		if(version not in categories):
			categories.append(version)
	finalCat = [[] for _ in range(len(categories))]
	finalList = ["" for _ in range(len(versions))]

	for item in apiList:
		name = item[0]
		osList = item[1:]
		for osItem in osList:
			for i in range(len(versions)):
				if(osItem == versions[i]):
					addAPI = (name, osItem)
					finalList[i] = versions[i] + ": " + name

	#Return our list of syscalls
	return finalList

def testTarek():
	global bPushRet
	global bFstenv
	global bSyscall
	global bHeaven
	global bPEB
	global bCallPop
	global bDisassembly
	global bShellcodeAll
	global bWideCharStrings
	global bAsciiStrings
	global bPushStackStrings
	

	bPushRet = bFstenv = bSyscall = bHeaven = bPEB = bCallPop = bDisassembly = bShellcodeAll = bWideCharStrings = bAsciiStrings = bPushStackStrings = True


if __name__ == "__main__":

	# EXTRACTION - if dealing with PE files, uncomment this:
	try:
		Extraction()
	except Exception as e:
		print(e)
		pass

	bramwell=False
	austin=False
	andy=False
	tarek=False
	jacob=False
	BramwellID=0
	AustinID=1
	AndyID=2


	#user=BramwellID       #comment out, so only one user shows, or is the last one shown.
	# user=AndyID      #comment out, so only one user shows, or is the last one shown.

	# user = AustinID
	user=AndyID
	# user=BramwellID


	
	if user==AustinID:
		austin=True
		bramwell=False
		andy = False
	elif user==BramwellID:

		bramwell=True
		austin=False
		andy=False
	elif user==AndyID:
		bramwell=False
		austin=False
		andy=True
	elif user==JacobID:
		jacob=True
	elif user==TarekID:
		tarek=True
	
	# bramwell=True
	if bramwell:
		mode=""
		# findAllPebSequences(mode)
		# printSavedPEB()
		# findAllPushRet()
		# printSavedPushRet()

		# bramwellStart()   # PE file ?
		
		# yes = 1

		yes = 2


		if yes == 53:
			# init2(filename)
			# init2(filename)
			# # print (binaryToStr(rawData2))
			# if not os.path.exists(directory+'bins'):
			# 	os.makedirs(directory+'bins')
			# assembly=binaryToText(rawData2)
			# newBin = open(directory+"bins\\"+filename[:-4]+".bin", "wb")
			# newBin.write(rawData2)
			# newBin.close()
			# newDis = open(directory+"bins\\ascii-"+filename[:-4]+".txt", "w")
			# print (directory+"bins\\ascii-"+filename[:-4]+".txt")
			# print (directory+"bins\\"+filename[:-4]+".bin")
			# newDis.write(assembly)
			# newDis.close()



			# print ("checking")
			# if not rawBin:
			# 	print ("checking2")

			# 	rawBytes=readShellcodeTest(filename) 


			bramwellstart4()
			# saveBinAscii()


		if yes == 2:
			init2(filename)
			# bramwellDisassembly2()   # Takes as input .txt file of shellcode	- also takes .bin (py sharem.py shellcode.bin raw) - note the raw keyword at the end!!!

			shellDisassemblyInit(rawData2)
			bramwellStart2()


		if yes == 3:
			bramwellEncodeDecodeWork(filename)
			print ("final DIS")


		if yes == 4:
			#bz
			myTest="89 c3"
			shells=fromhexToBytes(myTest)
			address=0
			for i in cs.disasm(shells, address):
				val =  i.mnemonic + " " + i.op_str 
				print(val)
		# val2.append(val)
		# val3.append(add2)

		if yes ==5:
			bramwellStart3()
	## AUSTIN --> get list of disassmebly from from shellcode and list of of offsets


	####sample input -- if nothing found, it will return as false
	# targetAddress=0x0
	# linesGoBack=10
	# truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, targetAddress, linesGoBack)  # arg: starting offset/entry point - leave 0 generally
	# if truth:
	# 	####the FULL disassembly of the shellcode
	# 	print ("Full disassembly of shellcode")
	# 	for e in orgListDisassembly:
	# 		print (str(hex(orgListOffset[t])) + "\t" + e)
	# 		t+=1
	# 	print ("\n\n\n")
	# 	t=0

	# 	##### JUST the found list  = target address - linesGoBack
	# 	print ("Found Target Address")
	# 	for each in tl1:
	# 		print (hex(each), tl2[t]) 
	# 		t+=1	
	# else:
	# 	print ("Target address not found")


	# 	t = 0

	# clearTempDis()

	# listOffset,listDisassembly = preSyscalDiscovery(0)  # arg: starting offset
	# for e in listDisassembly:
	# 	print (str(hex(listOffset[t])) + "\t" + e)
	# 	t+=1

	# bramwellDisassembly2()   #.bin file? maybe? not sure
	# addComments()
 
	# bramwellEncodeDecodeWork(filename)
	# print ("final DIS")
	# printTempDis()

	# print (labels)

	###################################################################
	#Austin's work -- place here - may comment out as need be
	#test
	# starting()
	# Austin=False
	################################ AUSTIN'S WORK AREA
	if austin:
		# AustinTesting2()
		# AustinTesting3()
		AustinTesting4() # decrypt ui
		# AustinTestingStub()



	if tarek:
		testTarek()
	################################ ANDY'S WORK AREA
	if andy:

		if workDir:
			work_from_directory()
			# readConf()

			# for i in list_of_files:
			# 	print("******************************"  + yel + "\nProcessing: " + gre + i +res + "\n******************************")

			# 	if os.path.isfile(i):
			# 		if i[-3:] == "txt":
			# 			rawHex = True
			# 		elif i[-3:] == "bin":
			# 			rawHex = True
			# 			rawBin = True
			# 			f = open(i, "rb")
			# 			rawData2 = f.read()

			# 		filename = i
			# 		init2(filename)
			# 		startupPrint()
			# 		# print("peb: ", bPEBFound)

			# 		clearAll()

				# 	f = open(file2Check, "rb")
				# filename = file2Check
				# rawData2 = f.read()
				# f.close()
				# rawHex = True
				# rawBin = True



		init2(filename)
		if(bit32):
			shellBit = 32
		elif(bit32 == False):
			shellBit = 64

		if not readConf():
			ui()
		else:
			print(gre + "\n\n[Attention] Startup config has been used.\n")
			print(whi + "Change the startup value to disabled in the config file if you want to use the UI menu.\n" + res)
			startupPrint()
		# print(rawData2.hex())
		# global bit32

		# global linesForward
		# global regsVals
		# linesForward = 40
		# bUI = False
		# # bit32 = True
		# bPushRet = False
		# bFstenv = False
		# bSyscall = False
		# bHeaven = False
		# bEm = False
		# bCallPop = True
		# # bFstenv = True
		# bPushRet = False
		# bHeaven = False
		# # bSyscall = True
		# # bCallPop = True
		# # bEm = True
		# # bit32=False
		# # ignoreDisDiscovery = True

		# bUI= True
		# # bCheck = False
		# bCheck = True
		# bUI= False
		# bit32=True



		

		
		# print("CONVERTED HERE")
		# print(binaryToStr(rawData2))

		# initSysCallSelect()
		# if (rawHex):
		# 	# for match in EGGHUNT.values():
		# 	# 	getSyscallPE(20, 20, match, 'noSec', rawData2)
		# 	print("doing the jive")
		# 	getSyscallRawHex(0, 8, 'noSec', rawData2)
		# 	printSavedEgg(shellBit, True)

		#Run the UI
		# if bUI:
			
		#Run command line instead
		# elif bCheck: 
		# 	if bSyscall:

		# 		if (rawHex):
		# 			# for match in EGGHUNT.values():
		# 			# 	getSyscallPE(20, 20, match, 'noSec', rawData2)
		# 			getSyscallRawHex(0, 8, 'noSec', rawData2)
		# 		else:
		# 			for secNum in range(len(s)):
		# 					data2 = s[secNum].data2
		# 					for match in EGGHUNT.values():
		# 						getSyscallPE(20, 20, match, secNum, data2)
		# 		printSavedEgg(shellBit, True)
			
		# 	if bFstenv:
		# 		if (rawHex):#(rawBin == False) and not isPe: 
		# 			findAllFSTENV(rawData2, 'noSec')


		# 		else:
		# 			for secNum in range(len(s)):
		# 				data2 = s[secNum].data2
		# 				findAllFSTENV(data2, secNum)
		# 		printSavedFSTENV(shellBit)

		# 	if bPushRet:
		# 		if (rawHex):#(rawBin == False) and not isPe:
		# 			if bit32:
		# 				findAllPushRet(rawData2, 'noSec')
		# 			else: 

		# 				findAllPushRet64(rawData2, 'noSec')

		# 		else:
		# 			for secNum in range(len(s)):
		# 				data2 = s[secNum].data2
		# 				if bit32:
		# 					print("running 32 bit")
		# 					findAllPushRet(data2, secNum)
		# 				else:
		# 					print("Running 64 bit")
		# 					findAllPushRet64(data2, secNum)
		# 					# print("")
		# 					# findAllPushRet64(data2, 'noSec')
		# 					# disHerePushRet64rawhex(0, 10, 'noSec', data2)
		# 		printSavedPushRet(shellBit)

		# 	if bCallPop:

		# 		print ("caall pop")
		# 		if (rawHex):#(rawBin == False) and not isPe:
		# 			if bit32:
		# 				findAllCallpop(rawData2, 'noSec')
		# 			else: 
		# 				print ("test")
		# 				findAllCallpop64(rawData2, 'noSec')

		# 		else:
		# 			for secNum in range(len(s)):
		# 				data2 = s[secNum].data2
		# 				if bit32:
		# 					findAllCallpop(data2, secNum)
		# 				else:
		# 					findAllCallpop64(data2, secNum)
		# 					# print("")
		# 					# findAllPushRet64(data2, 'noSec')
		# 					# disHerePushRet64rawhex(0, 10, 'noSec', data2)

		# 		printSavedCallPop(shellBit)
		# 	if bHeaven:
		# 		if (rawHex):
		# 			getHeavenRawHex(0, 8, 'noSec', rawData2)
		# 		else:
		# 			for secNum in range(len(s)):
		# 					data2 = s[secNum].data2
		# 					findAllHeaven(data2, secNum)
		# 		printSavedHeaven(shellBit)


			
			

		# 		print("\n")
		# # print ("neo subarashiki kono sekai")

		# bSyscall = True
		# bCallPop = True
		# bEm = True
		# bit32=False
		# ignoreDisDiscovery = True
