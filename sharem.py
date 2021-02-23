from capstone import *
import re
import pefile
import sys
import binascii
import copy
import os
from collections import OrderedDict
from lists import *
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

tempDisassembly=[]
tempAddresses=[]
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
skipExtraction=False
rawHex = False
rawData2 = b''
numArgs = len(sys.argv)
rawBin=False  # only if .bin, not .txt



FindStringsStatus=True

# FindStringsStatus=False


GoodStrings=["cmd",  "net","add", "win", "http", "dll", "sub", "calc"]


#####SAME AS FROM SHAREM
filename=""
if numArgs > 1:			# to get full functionality, need to put file location for binary that is installed (may need to find some DLLs in that directory)
	txtDoc= re.search( r'\.txt', sys.argv[1], re.M|re.I)
	if txtDoc:
		filename= sys.argv[1]
		skipExtraction=True
		rawHex=True
		print("set rawHEx")

if len(filename) > 1:
	testing=filename

if numArgs==1:
	skipExtraction=True
	rawHex=True
	filename= sys.argv[1]
	print("numargs")
if not skipExtraction:
	if numArgs > 1:			# to get full functionality, need to put file location for binary that is installed (may need to find some DLLs in that directory)
		peName= sys.argv[1] 
		matchObj = re.match( r'^[a-z]+:[\\|/]+', peName, re.M|re.I)
		if matchObj:
			head, tail = os.path.split(peName)
			peName = tail
			PE_path = head
			skipPath = True
		if not matchObj:
			skipPath = False
		matchObj = re.match( r'^[a-z0-9]+.txt', peName, re.M|re.I)
		if matchObj:
			rawBin=False  # only if .bin, not .txt
			head, tail = os.path.split(peName)
			with open(tail, "r") as ins:
				for line in ins:
					line2 = line.rstrip('\n')
					PEsList.append(line2)
			peName = PEsList[0]
			# print "name"
			print (peName)
			head, tail = os.path.split(peName)
			peName = tail
			PE_path = head
			numPE = len(PEsList)
			skipPath = True
			# print PEsList
	PEtemp = PE_path + "/"+ peName



	############### AUSTIN ####################
	print ("entering Austin")
	rawHex = False
	# global rawData2
	print ("0", sys.argv[0])
	print ("1", sys.argv[1])
	print ("2", sys.argv[2])
	if(numArgs > 1):
		if(sys.argv[2] == "raw"):
			rawHex = True
			rawBin=True  # only if .bin, not .txt
			print("set raw", (sys.argv[2]), (sys.argv[1]), peName)
			try:
				f = open(peName, "rb")
				# global rawData2
				rawData2 = f.read()
				f.close()
				# print ("rawData2", len(rawData2))
			except Exception as e:
				print("Invalid path to hex file.")
				print(e)
				quit()
	############### AUSTIN ####################

	if skipPath == False:
		PEtemp = peName
	if skipPath == True:
		PEtemp = PE_path + "/"+ peName

	if(rawHex):
		bit32 = True #### ADD UI SELECTION LATER #####
		pe = peName

	else:
		try:
			if win32file.GetBinaryType(PEtemp) == 6:
				bit32 = False
			else:
				bit32 = True
		except:
			pass
		try:
			if skipPath == True:
				pe = pefile.PE(PEtemp)
			if skipPath == False:
				pe = pefile.PE(peName)
		except:
			pass
if(bit32):
	cs = Cs(CS_ARCH_X86, CS_MODE_32)
else:
	cs = Cs(CS_ARCH_X86, CS_MODE_64)

cs64 = Cs(CS_ARCH_X86, CS_MODE_64)
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
		self.Strings = []    # tuple - strings, starting offset
		self.pushStrings=[]
		self.wideStrings = []    # tuple - strings, starting offset
		self.save_PEB_info = []
		self.save_PushRet_info = []
		# self.sectionStart =0 ### image base + virtual address
		self.save_FSTENV_info = [] #tuple - addr, NumOps, modSecName, secNum
		self.save_Egg_info = [] #tuple - addr, NumOps, modSecName, secNum
		self.save_Callpop_info = [] #tuple - addr, NumOps, modSecName, secNum
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
	for api, dll, offset in FoundApisName:
		
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
			addDeeper(iatList[t].name)
			# print("\n\nFROM INMEM2")
			addIAT(dll, iatList[t].name)
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
		# print "      s_old--@? " + x.name.lower()  +  " old " + old
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

			newpath = extractDLLNew(dll)
			# print(newpath)
			# input("newpath")
			doneAlready0.append(dll)
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
	test = ""
	i = 0
	print ("pename " + peName)
	pe = pefile.PE(peName)
	print (pe.OPTIONAL_HEADER.AddressOfEntryPoint)


	for sec in pe.sections:
		sections.append(sec.Name)
	print (sections)

	# print pe.sections[0].get_data()[0:]

	# print "t " + str(t)
	# print "m " + str(len(m))
	# print "s " + str(len(s))
	t=0
	for x in pe.sections:
		newSection()

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
		s[t].data2  = pe.sections[t].get_data()[0:]
		s[t].protect = str(peName) + "\t"
		s[t].depStatus =  str(dep())
		s[t].aslrStatus =  str(aslr())
		s[t].sehSTATUS =  str(seh())
		s[t].CFGstatus =  str(CFG())
		s[t].protect = s[t].protect + s[t].depStatus + s[t].aslrStatus + s[t].sehSTATUS + s[t].CFGstatus
		DLL_Protect.append(s[t].protect)
		t+=1
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
	print ("Sections: " + display)
	# print len(PE_DLLS)
	o = 0
	t=0
	# modName = peName
def extractDLLNew(dllName):
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
	print ("NEW: extracting enter")
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
	print ("# m: " + str(len(m)))
	for each in m:	
		cat +=str(m[o].modName)+"\n"
		# cat +="Section: " + str(m[0].sectionName) +"\n"
		cat+="Entry point: " + str(hex(m[o].entryPoint)) +"\n"
		cat+="Virtual Address: " + str(hex(m[o].VirtualAdd))+"\n"
		cat+="ImageBase: " + str(hex(m[o].ImageBase))+"\n"
		cat+="VirtualSize: " + str(hex(m[o].vSize))+"\n"
		cat+="Size of section: " + str(hex(len(m[o].data2)))+"\n"
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
	print("showBasicInfoSections")
	cat=""
	t=0
	print ("# s: " + str(len(s)))

	for each in s:	
		cat +=str(s[t].sectionName)+"\n"
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


def binaryToText(binary):
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

		rawH="\nRaw Hex:\n\""+rawH+"\"\n"
		strLit = "\nString Literal:\n\""+strLit+"\"\n"
		arrayLit=arrayLit[:-2]
		arrayLit ="\nArray Literal:\n{ "+arrayLit+" }\n"
		print (strLit)
		print (rawH)
		print (arrayLit)
		returnVal=rawH+strLit+arrayLit
	except Exception as e:
		print ("*Not valid format")
		print(e)
	return returnVal

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

def get_PEB_walk_start_64(NumOpsDis ,bytesToMatch, secNum, data2): ############### AUSTIN ######################
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
				#print(data2[t+i])
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				# input(e)
				pass
			i += 1

		if(found):
			# input("enter..")
			disHerePEB_64(t, numOps, secNum, data2)

			

		t=t+1


#CHANGED: works based off of all sections in pefile now (rather than just .text). unused 'Reg' param changed to secNum to indicate where data came from.

total1 = 0
total2 = 0
def disHerePEB(mode, address, NumOpsDis, secNum, data): ############ AUSTIN ##############
	print ("disHerePEB", mode)
	global o
	global total1
	global total2
	w=0


	foundAdv = False
	foundPEB = False
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
		val5.append(val)
		# print (val)
	#return val5
	# stop = timeit.default_timer()
	# total2 += (stop - start)
	# print("Time 2 PEB: " + str(stop - start))


	points = 0
	disString = val5

	loadTIB_offset = -1
	loadLDR_offset = -1
	loadModList_offset = -1
	advanceDLL_Offset = [-1]

	for line in disString:
		#print (line)

		##############################################

		movLoadPEB = re.match("^(mov) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr fs:\[((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?)?0x30)\]", line, re.IGNORECASE)
		addLoadPEB = re.match("^(add) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr fs:\[((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?)?0x30)\]", line, re.IGNORECASE)
		adcLoadPEB = re.match("^(adc) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr fs:\[((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?)?0x30)\]", line, re.IGNORECASE)
		xorLoadPEB = re.match("^(xor) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr fs:\[((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?)?0x30)\]", line, re.IGNORECASE)
		orLoadPEB = re.match("^(or) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr fs:\[((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?)?0x30)\]", line, re.IGNORECASE)
		xchgLoadPEB = re.match("^(xchg) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr fs:\[((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?)?0x30)\]", line, re.IGNORECASE)
		pushLoadPEB = re.match("^(push) (d?word ptr fs:\[((e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))))) ?(\+ ?0x30)?\]", line, re.IGNORECASE)


		if(movLoadPEB or addLoadPEB or adcLoadPEB or xorLoadPEB or orLoadPEB or xchgLoadPEB or pushLoadPEB and foundPEB):
			loadTIB_offset = line.split()[-1]
			loadTIB_offset = loadTIB_offset[:-1]
			points += 1
			foundPEB = True
		elif(not foundPEB):
			return


		##############################################

		movLoadLDR = re.match("^(mov) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0xc)\])", line, re.IGNORECASE)
		addLoadLDR = re.match("^(add) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0xc)\])", line, re.IGNORECASE)
		adcLoadLDR = re.match("^(adc) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0xc)\])", line, re.IGNORECASE)
		xorLoadLDR = re.match("^(xor) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0xc)\])", line, re.IGNORECASE)
		orLoadLDR = re.match("^(or) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0xc)\])", line, re.IGNORECASE)
		xchgLoadLDR = re.match("^(xchg) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0xc)\])", line, re.IGNORECASE)
		
		if(movLoadLDR or addLoadLDR or adcLoadLDR or xorLoadLDR or orLoadLDR or xchgLoadLDR):
			loadLDR_offset = line.split()[-1]
			loadLDR_offset = loadLDR_offset[:-1]
			points += 1


		###############################################

		movLoadInMemOrder = re.match("^(mov) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x14))\])", line, re.IGNORECASE)
		addLoadInMemOrder = re.match("^(add) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x14))\])", line, re.IGNORECASE)
		adcLoadInMemOrder = re.match("^(adc) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x14))\])", line, re.IGNORECASE)
		xorLoadInMemOrder = re.match("^(xor) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x14))\])", line, re.IGNORECASE)
		orLoadInMemOrder = re.match("^(or) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x14))\])", line, re.IGNORECASE)
		xchgLoadInMemOrder = re.match("^(xchg) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x14))\])", line, re.IGNORECASE)

		if(movLoadInMemOrder or addLoadInMemOrder or adcLoadInMemOrder or xorLoadInMemOrder or orLoadInMemOrder or xchgLoadInMemOrder):
			loadModList_offset = line.split()[-1]
			loadModList_offset = loadModList_offset[:-1]
			points += 1


		###############################################

		movLoadInInitOrder = re.match("^(mov) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x1c))\])", line, re.IGNORECASE)
		addLoadInInitOrder = re.match("^(add) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x1c))\])", line, re.IGNORECASE)
		adcLoadInInitOrder = re.match("^(adc) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x1c))\])", line, re.IGNORECASE)
		xorLoadInInitOrder = re.match("^(xor) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x1c))\])", line, re.IGNORECASE)
		orLoadInInitOrder = re.match("^(or) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x1c))\])", line, re.IGNORECASE)
		xchgLoadInInitOrder = re.match("^(xchg) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x1c))\])", line, re.IGNORECASE)

		if(movLoadInInitOrder or addLoadInInitOrder or adcLoadInInitOrder or xorLoadInInitOrder or orLoadInInitOrder or xchgLoadInInitOrder):
			loadModList_offset = line.split()[-1]
			loadModList_offset = loadModList_offset[:-1]
			points += 1

		###############################################

		movDereference = re.match("^(mov) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))\])", line, re.IGNORECASE)
		addDereference = re.match("^(add) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))\])", line, re.IGNORECASE)
		adcDereference = re.match("^(adc) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))\])", line, re.IGNORECASE)
		orDereference = re.match("^(or) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))\])", line, re.IGNORECASE)
		xorDereference = re.match("^(xor) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))\])", line, re.IGNORECASE)
		xchgDereference = re.match("^(xchg) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l)))\])", line, re.IGNORECASE)

		if(movDereference or addDereference or adcDereference or orDereference or xorDereference or xchgDereference):
			advanceDLL_Offset_temp = line.split()[-1]
			advanceDLL_Offset_temp = advanceDLL_Offset_temp[:-1]
			if(not foundAdv):
				advanceDLL_Offset[0] = advanceDLL_Offset_temp
				foundAdv = True
				points += 1
			else:
				advanceDLL_Offset.append(advanceDLL_Offset_temp)



		############## AUSTIN ####################
		lodsd = re.match("^(lodsd)", line, re.IGNORECASE) 

		if(lodsd):
			points += 1
	############## AUSTIN ####################


	if(points >= 2):
		if(rawHex):
			modSecName = peName
		else:
			modSecName = section.sectionName

		if mode=="decrypt":
			print ("decrypt returning")
			print (address, NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, loadModList_offset, advanceDLL_Offset)
			return address , NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, loadModList_offset, advanceDLL_Offset
		#print("Adding item #" + str(len(m[o].save_PEB_info)))
		# print("saving at sec num = " + str(secNum))
		saveBasePEBWalk(address, NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, loadModList_offset, advanceDLL_Offset)

def disHerePEB_64(address, NumOpsDis, secNum, data): ############## AUSTIN ####################

	global o
	global total1
	global total2
	w=0
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
	for i in cs.disasm(CODED3, address):

		if(secNum == "noSec"):

			print("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
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


	points = 0
	disString = val5

	for line in disString:

		##############################################

		movLoadPEB = re.match("^(mov) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		addLoadPEB = re.match("^(add) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		adcLoadPEB = re.match("^(adc) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		xorLoadPEB = re.match("^(xor) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		orLoadPEB = re.match("^(or) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		xchgLoadPEB = re.match("^(xchg) ((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))), ?((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))) ?\+ ?)?0x60)\]", line, re.IGNORECASE)
		pushLoadPEB = re.match("^(push) ((q|d)?word ptr gs:\[(((e|r)((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|(r((9)|(10)|(11)|(12)|(13)|(14)|(15)))))) ?(\+ ?0x60)?\]", line, re.IGNORECASE)


		if(movLoadPEB or addLoadPEB or adcLoadPEB or xorLoadPEB or orLoadPEB or xchgLoadPEB or pushLoadPEB):
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



	if(points >= 3):
		modSecName = section.sectionName
		saveBasePEBWalk_64(address, NumOpsDis, modSecName, secNum, points)



def saveBasePEBWalk(address, NumOpsDis,modSecName,secNum, points): 
	# print("saving")
	#save virtaul address as well
	if(secNum != "noSec"):
		s[secNum].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))
	else:
		secNum = -1
		modSecName = "rawHex"
		m[o].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))

def saveBasePEBWalk_64(address, NumOpsDis,modSecName,secNum, points): ############## AUSTIN ####################
	#print "saving"
	#save virtaul address as well
	if(secNum != "noSec"):
		s[secNum].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))
	else:
		secNum = -1
		modSecNmae = "rawHex"
		m[o].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))
print ("#############################################################################")


def printSavedPEB(): ######################## AUSTIN ###############################3
	#formatting

	print ("printSavedPEB", len(rawData2))
	print ("m[o].save_PEB_info", len(m[o].save_PEB_info))
	print ("rawhex", rawHex)
	j = 0

	if(rawHex):
		for item in m[o].save_PEB_info:


			print("OFFSETS: ")
			print("TIB = " + str(item[5]))
			print("LDR = " + str(item[6]))
			print("MODS = " + str(item[7]))
			print("Adv = " + str(item[8]))

			CODED2 = b""

			address = item[0]
			NumOpsDis = item[1]
			modSecName = item[2]
			secNum = item[3]
			points = item[4]

			CODED2 = rawData2[address:(address+NumOpsDis)]

			outString = "\n\nItem : " + str(j) + " | Points: " + str(points)
			if(secNum != -1):

				outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName

			print ("\n********************************************************")
			print (outString)
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
				val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
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
				CODED2 = ""


				print("OFFSETS: ")
				print("TIB = " + str(item[5]))
				print("LDR = " + str(item[6]))
				print("MODS = " + str(item[7]))
				for adv in item[8]:
					print("Adv = " + str(adv))

				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				points = item[4]

				section = s[secNum]

				outString = "\n\nItem : " + str(j) + " | Points: " + str(points)
				if(secNum != -1):

					outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				print ("\n********************************************************")
				print (outString)
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
					val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					val5.append(val)
					print (val)
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

			outString = "\n\nItem : " + str(j) + " | Points: " + str(points)
			if(secNum != -1):

				outString += " | Section number: " + str(secNum) + " | Section name: " + modSecName
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName

			print ("\n********************************************************")
			print (outString)
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
				val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
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
			for item in section.save_PEB_info:
				CODED2 = ""

				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				points = item[4]

				section = s[secNum]

				outString = "\n\nItem : " + str(j) + " | Points: " + str(points)
				if(secNum != -1):

					outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				print ("\n********************************************************")
				print (outString)
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
					val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					val5.append(val)
					print (val)
				print ("\n")
				j += 1
				# print str(type(m[o].data2))
				# trash = raw_input("enter...")


def get_PushRet_start(NumOpsDis ,bytesToMatch, secNum, data2): ######################### AUSTIN #############################

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
				pass
			i += 1

		if(found):
			# input("enter..")
			disHerePushRet(t, numOps, secNum, data2)

			

		t=t+1


	


def disHerePushRet(address, NumOpsDis, secNum, data): ############################# AUSTIN ############################

	# print("inDisherePush")
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
		# print(val)
	# stop = timeit.default_timer()
	# print("Time 2: " + str(stop - start))

	#input("enter..")


	points = 0
	disString = val5



	for line in disString:

		##############################################

		push = re.match("^push (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
		ret = re.match("^ret", line, re.IGNORECASE)

		if(push):
			points += 1

		if(ret):
			points += 1

	if(points >= 2):
		if(rawHex):
			modSecName = peName
		else:
			modSecName = section.sectionName
		saveBasePushRet(address, NumOpsDis, modSecName, secNum, points)



def saveBasePushRet(address, NumOpsDis,modSecName,secNum, points): ################## AUSTIN ##############################
	#print "saving"
	#save virtaul address as well
	if(secNum != "noSec"):
		s[secNum].save_PushRet_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))
	else:
		secNum = -1
		modSecName = "rawHex"
		m[o].save_PushRet_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))

def printSavedPushRet(): ############################## AUSTIN #############################
		#formatting
	j = 0
	if(rawHex):
		for item in m[o].save_PushRet_info:
			CODED2 = b""

			address = item[0]
			NumOpsDis = item[1]
			modSecName = item[2]
			secNum = item[3]
			points = item[4]

			CODED2 = rawData2[address:(address+NumOpsDis)]

			outString = "\n\nItem : " + str(j) + " | Points: " + str(points)
			if(secNum != -1):

				outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName

			print ("\n********************************************************")
			print (outString)
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
				val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
				print (val)
	#return val5
			print ("\n")
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

				section = s[secNum]

				outString = "\n\nItem : " + str(j) + " | Points: " + str(points)
				if(secNum != -1):

					outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				print ("\n********************************************************")
				print (outString)
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
					val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					val5.append(val)
					print (val)
				print ("\n")
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
				#print(data2[t+i])
				#input("enter..")
				if ((data2[t+i]) != (bytesToMatch[i])):
					found = False #no match
			except Exception as e:
				# input(e)
				pass
			i += 1

		if(found):
			# input("enter..")
			disHereFSTENV(t, numOps, NumOpsBack, secNum, data2)

			

		t=t+1


fcount = 0

#NumOpsBack: how many opcodes to search back when looking for fpu instruction
def disHereFSTENV(address, NumOpsDis, NumOpsBack, secNum, data): ############ AUSTIN ##############

	global o
	global total1
	global total2
	global fcount
	w=0

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


	# print("------------------------------------")
	for back in range(NumOpsBack):
		# print("back = " + str(back))
		CODED2 = data[(address-(NumOpsBack-back)):(address+x)]
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
		# print("BINARY2STR")
		# print(binaryToStr(CODED3))
		# print("******************************************")
		for i in cs.disasm(CODED3, address):
			#print('address in for = ' + str(address))
			if(secNum == "noSec"):

			#	print("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
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
			# print(val)

			disString = val5

			#we save when the fpu instr is the first one 
			# match instructions beginning with "f" but is not fstenv or fnstenv
			FPU_instr = re.match("^f((?!n?stenv).)*$", disString[0], re.IGNORECASE)
			fstenv = False
			if(FPU_instr):
				FPU_offset = disString[0].split()[-1]
				# print("FPU OFF1 = " + str(FPU_offset))
				FPU_offset = FPU_offset[:-1]
				# print("FPU OFF2 = " + str(FPU_offset))
				# input("fpu2")

				for line in disString:
					FSTENV_instr = re.match("^fn?stenv", line, re.IGNORECASE)

					if(FSTENV_instr):
						FSTENV_offset = line.split()[-1]
						FSTENV_offset = FSTENV_offset[:-1]
						fcount += 1
						# print("CONFIRMED FSTENV -- NUMBER " + str(fcount))
						# print("SAVING THIS ONE")
						if(rawHex):
							modSecName = peName
						else:
							modSecName = section.sectionName

						saveBaseFSTENV(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, FPU_offset, FSTENV_offset)
						return




def saveBaseFSTENV(address, NumOpsDis, NumOpsBack, modSecName, secNum, FPU_offset, FSTENV_offset):
	if(secNum != "noSec"):
		print("FPU OFF1 = " + str(FPU_offset))
		print("FPU OFF2 = " + str(FPU_offset))
		print("Fstenv OFF1 = " + str(FSTENV_offset))
		print("Fstenv OFF2 = " + str(FSTENV_offset))
		input("fpu2")
		s[secNum].save_FSTENV_info.append(tuple((address,NumOpsDis,NumOpsBack,modSecName,secNum,FPU_offset,FSTENV_offset)))
	else:
		print("Saving one raw")
		secNum = -1
		modSecName = "rawHex"
		m[o].save_FSTENV_info.append(tuple((address,NumOpsDis,NumOpsBack,modSecName,secNum,FPU_offset,FSTENV_offset)))

def printSavedFSTENV(): ######################## AUSTIN ###############################3
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
			print("OFFSETS: ")
			print("FPU = " + str(FPU_offset))
			print("FSTENV = " + str(FSTENV_offset))
			CODED2 = rawData2[(address-NumOpsBack):(address+NumOpsDis)]

			outString = "\n\nItem : " + str(j)
			if(secNum != -1):

				outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName

			print ("\n********************************************************")
			print (outString)
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
				val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
				print (val)
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
				print("OFFSETS: ")
				print("FPU = " + FPU_offset)
				print("FSTENV = " + FSTENV_offset)
				# print("NUMBACK = " + str(NumOpsBack))

				section = s[secNum]

				outString = "\n\nItem : " + str(j)
				if(secNum != -1):

					outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				print ("\n********************************************************")
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


def get_Callpop(NumOpsDis, bytesToMatch, secNum, data2, distance): 
	#change to work off of data2 - add param - get rid of secNum

	# print('in get')

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
				pass
			i += 1

		if(found):
			# input("enter..")
			disHereCallpop(t, numOps, secNum, data2, distance)

		t=t+1

def disHereCallpop(address, NumOpsDis, secNum, data, distance):
	# print("in dishere")
	pop = False
	CODED2 = ""
	x = NumOpsDis

	origAddr = address
	address = address + distance
	if(secNum != "noSec"):
		section = s[secNum]
	CODED2 = data[(address):(address+NumOpsDis)]

	# I create the individual lines of code that will appear>
	val =""
	val2 = []
	val3 = []
	#address2 = address + section.ImageBase + section.VirtualAdd
	val5 =[]
	

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
		# print(val)


	disString = val5



	for line in disString:

		##############################################

		pop = re.match("^pop (e((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp)|(sp)))", line, re.IGNORECASE)
		if(pop):
			pop_offset = line.split()[-1]
			pop_offset = pop_offset[:-1]
		# print("POP OFFSET")
		print(pop_offset)
		if(pop):

			if(rawHex):
				modSecName = peName
			else:
				modSecName = section.sectionName
			# print("saving one")
			saveBaseCallpop(address, NumOpsDis, modSecName, secNum, distance)
			return


def saveBaseCallpop(address, NumOpsDis,modSecName,secNum,distance): 
	# print("saving")
	#save virtaul address as well
	if(secNum != "noSec"):
		s[secNum].save_Callpop_info.append(tuple((address,NumOpsDis,modSecName,secNum,distance)))
	else:
		secNum = -1
		modSecName = "rawHex"
		m[o].save_Callpop_info.append(tuple((address,NumOpsDis,modSecName,secNum,distance)))

def printSavedCallPop(): ######################## AUSTIN ###############################3
	# print("in print")
	#formatting
	j = 0
	if(rawHex):
		for item in m[o].save_Callpop_info:
			CODED2 = b""

			address = item[0]
			NumOpsDis = item[1]
			modSecName = item[2]
			secNum = item[3]
			distance = item[4]

			CODED2 = rawData2[(address):(address+NumOpsDis)]

			outString = "\n\nItem : " + str(j)
			if(secNum != -1):

				outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName

			print ("\n********************************************************")
			print (outString)
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
				val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
				print (val)
	#return val5
			print ("\n")
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


				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				distance = item[4]

				# print("NUMBACK = " + str(NumOpsBack))

				section = s[secNum]

				outString = "\n\nItem : " + str(j)
				if(secNum != -1):

					outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				print ("\n********************************************************")
				print (outString)
				print ("\n")
				val =""
				val2 = []
				val3 = []
				address2 = address + section.ImageBase + section.VirtualAdd
				val5 =[]

				CODED2 = section.data2[(address):(address+NumOpsDis)]

				CODED3 = CODED2
				for i in cs.disasm(CODED3, address):
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc))
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
				found = int(numeric.group(), 0)
				# print("here is what i found:")
				# print(found)

				found = hex(found)

			else:
				found = "unknown"

			stack.append(found)

			if(esp != "unknown"):
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



def get_Egghunters(NumOpsDis, NumOpsBack, bytesToMatch, secNum, data2): 
	#change to work off of data2 - add param - get rid of secNum

	# print('in get')

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
				pass
			i += 1

		if(found):
			# input("enter..")
			disHereEgg(t, numOps, NumOpsBack, secNum, data2)

			

		t=t+1

def disHereEgg(address, NumOpsDis, NumOpsBack, secNum, data): ############ AUSTIN ##############

	global o
	global total1
	global total2
	global fcount
	w=0

	op_const = 16
	line_const = 8
	NumOpsBack = NumOpsBack + op_const

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


	# print("------------------------------------")
	for back in range(NumOpsBack):
		unlikely = 0
		# print("back = " + str(back))
		CODED2 = data[(address-(NumOpsBack-back)):(address+x)]
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
		# print("BINARY2STR")
		# print(binaryToStr(CODED3))
		# print("******************************************")
		for i in cs.disasm(CODED3, address):
			#print('address in for = ' + str(address))
			if(secNum == "noSec"):

			#	print("i = " + str(i) + " i.mnemonic = " + str(i.mnemonic))
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
			# print(val)

			disString = val5
			# print("before")
			# print(disString)
			# disString = disString[2:]
			# print("after")
			# print(disString)
			c0_match = False
			#check for dword ptr fs:[reg] and verify value of register


		for line in disString:
			if(re.match("^((jmp)|(call)) ?dword ptr fs: ?\[0xc0\]", line, re.IGNORECASE)):
				c0_match = True

			byte = re.search("byte ptr", line, re.IGNORECASE)
			insd = re.search("insd", line, re.IGNORECASE)
			longNum = re.search("(0x)([0-9a-f]){6,}", line, re.IGNORECASE)

			if(byte or insd or longNum):
				unlikely = unlikely + 1


			if(c0_match and (unlikely < 3)):
				# print("c0 match")
				# print("SAVING THIS ONE")
				# input()
				if(rawHex):
					modSecName = peName
				else:
					modSecName = section.sectionName

				startStates = ("unknown","unknown","unknown","unknown","unknown","unknown","unknown","unknown")
				eax = trackRegs(disString, startStates, [])[0][0]
				if(eax == "0x26"):
					# print("TrackRegs found eax = " + str(eax))
					saveBaseEgg(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, eax)
				return


def saveBaseEgg(address, NumOpsDis, NumOpsBack, modSecName, secNum, eax):
	if(secNum != "noSec"):
		s[secNum].save_Egg_info.append(tuple((address,NumOpsDis,NumOpsBack,modSecName,secNum,eax)))
	else:
		print("Saving one raw")
		secNum = -1
		modSecName = "rawHex"
		m[o].save_Egg_info.append(tuple((address,NumOpsDis,NumOpsBack,modSecName,secNum, eax)))


def printSavedEgg(): ######################## AUSTIN ###############################3
	#formatting
	j = 0
	if(rawHex):
		for item in m[o].save_Egg_info:
			CODED2 = b""

			address = item[0]
			NumOpsDis = item[1]
			NumOpsBack = item[2]
			modSecName = item[3]
			secNum = item[4]
			eax = item[5]

			CODED2 = rawData2[(address-NumOpsBack):(address+NumOpsDis)]

			outString = "\n\nEGG Item : " + str(j)
			if(secNum != -1):

				outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
				# if(secNum != 0):
				# 	trash = raw_input("enter...")
				
			else:
				outString += " | Module: " + modSecName

			outString += " | EAX: " + eax

			print ("\n********************************************************")
			print (outString)
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
				val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")\n"
				print (val)
	#return val5
			print ("\n")
			j += 1
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

				# print("NUMBACK = " + str(NumOpsBack))

				section = s[secNum]

				outString = "\n\nItem : " + str(j)
				if(secNum != -1):

					outString += " | Section number: " + str(secNum) + " | Section name: " + str(modSecName)
					# if(secNum != 0):
					# 	trash = raw_input("enter...")
					
				else:
					outString += " | Module: " + modSecName

				outString += " | EAX: " + eax

				print ("\n********************************************************")
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



def saveBasePEBWalk(address, NumOpsDis,modSecName,secNum, points, loadTIB_offset, loadLDR_offset, loadModList_offset, advanceDLL_Offset): 
	# print("saving")
	#save virtaul address as well
	if(secNum != "noSec"):
		s[secNum].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points,loadTIB_offset,loadLDR_offset,loadModList_offset,advanceDLL_Offset)))
	else:
		secNum = -1
		modSecName = "rawHex"
		m[o].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points,loadTIB_offset,loadLDR_offset,loadModList_offset,advanceDLL_Offset)))


def findAllFSTENV(data2, secNum): ################## AUSTIN ######################

	for match in FSTENV_GET_BASE.values(): #iterate through all opcodes representing combinations of registers
		get_FSTENV(10, 15, match, secNum, data2) 


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

def findAllCallpop(data2, secNum): ################## AUSTIN ######################

	for match in CALLPOP_START.values(): #iterate through all opcodes representing combinations of registers
		get_Callpop(10, match[0], secNum, data2, match[1]) 


def findAllPebSequences(data2, secNum): ################## AUSTIN ######################
	# global rawHex

	for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
		get_PEB_walk_start(19, match, secNum, data2) 





def findAllPebSequences(mode): ################## AUSTIN ######################
	# global rawHex
	print ("findAllPebSequences", mode, binaryToStr(rawData2),)
	if(rawHex):


		for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
			ans=get_PEB_walk_start(mode, 19, match, "noSec", rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
			# print ("ans", ans)
			if mode=="decrypt" and ans is not None:
				print ("good, get pet walk")
				print (ans)
				return (ans)
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

	elif(bit32):
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

	else:
		for secNum in range(len(s)):
			data2 = s[secNum].data2
			for match in PEB_WALK_MOV_64.values(): #iterate through all opcodes representing combinations of registers
				get_PEB_walk_start_64(28, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence


def findAllPushRet(data2, secNum): ################## AUSTIN #########################
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
	print ("findingStrings sharem")
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
 					# print ("saving string", word.encode("utf-8"))
 					stringsTemp.append(tuple((word, offset, wordSize)))
	except Exception as e:
		print ("*String finding error1!!!")
		print (e)

	# print (stringsTemp)

def findStringsWide(binary,Num):#,t):
	print ("findStringsWide")
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
						if ((word[1]==".") and (word[3]==".") and (word[5]==".") and (word[7]==".") and (word[9]==".") and (word[2]!=".") and (word[4]!=".") and (word[6]!=".") and (word[8]!=".") and (word[10]!=".")):
							wordSize=len(word)
							# print ("ws - got one1\n")
							try:
								s[t].wideStrings.append(tuple((word, offset,wordSize)))
							except:
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
									if ((word[1]==".") and (word[3]==".") and (word[5]==".") and (word[7]==".") and (word[9]==".") and (word[2]!=".") and (word[4]!=".") and (word[6]!=".") and (word[8]!=".") and (word[10]!=".")):
										if ((ord(word[0])>0x40 ) and (ord(word[0])<0x5b ) or (ord(word[0])>0x60 ) and (ord(word[0])<0x7b )):
											wordSize=len(word)
											# print ("ws - got one2", "t", hex(t), word, hex(offset), wordSize)

											try:
												s[t].wideStrings.append(tuple((word, offset,wordSize)))
												# print ("success")
											except:
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
					if (len(word) >= (Num*2)):
						if ((word[1]==".") and (word[3]==".") and (word[5]==".") and (word[7]==".") and (word[9]==".") and (word[2]!=".") and (word[4]!=".") and (word[6]!=".") and (word[8]!=".") and (word[10]!=".")):
							if (((ord(word[0]))>0x40 ) and (ord(word[0])<0x5b ) or (ord(word[0])>0x60 ) and (ord(word[0])<0x7b )):
								wordSize=len(word)
								try:
									s[t].wideStrings.append(tuple((word, offset,wordSize)))
								except:
									stringsTempWide.append(tuple((word, offset,wordSize)))
					inProgress=False
					word=""
					offset=0
					WideCnt=0
			x+=1
			y+=1
	except Exception as e:
		print ("*String finding error2!!!")
		print(e)
	print("Strings Wide")
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
								pushStringsTemp.append(tuple((word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength)))  
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
								if t2>2:    #### this part here may be redundant, or could cause weird problems, but I like the idea of a done for thte single push byte. if push byte, word, dword, then no go.
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
def findPushAsciiMixed(binary,Num):
	print ("findPushAsciiMixed")
	global t
	global o
	global pushStringsTemp

	chMode=True
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
								print ("word", word2)
							except:
								print ("word2 error")
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
							# print "enter checkedString: " + word2
							valid, word4temp, checkedString = checkedString1(word2, chMode)
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
							valid, word4temp,checkedString = checkedString1(altWord, chMode)
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
										print ("throw out " + finalWord)
										finalWord=""
						# print "finalWord " + finalWord
						try:
							if len(finalWord) > 0:
								# print "offy " + str(offset)
								offset=offset-8
								instructionsLength=instructionsLength+8
						except:
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
									print("saving pushMixed", word4)
								except:
									pass
								pushStringsTemp.append(tuple((word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength)))  # 
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
	section = s[0]
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
	# print ("hexStrtoAscii")
	word2=""
	for i in range(0, len(word), 2):
		word2+=chr(int(word[i:i+2],16))
	word2=word2[ :  :-1]
	if word2.isascii():
		print("isAscii")
		print (word2)
		return word2
	else:
		print("isNotAscii", len(word2))
		return "^^^^"

def checkedString1(altWord, mode):
	print ("checkedString1", altWord)
	# print altWord
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

	for letter in word2:
		# print letter  + " t2: " + str(t2) + " old "  + old
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
			# print "push EAX"
			tem="^^^^"
			if (mode):
				tem=retR32("eax","n")
				tem = hexStrtoAscii(tem)
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==1) and (letter =="S") and  (done==False)):
			print ("push EBX2")
			tem="^^^^"
			if (mode):
				tem=retR32("ebx","n")
				tem = hexStrtoAscii(tem)
			spec.append((tem))
			t2=0
			tem=""
		elif ((t2==1) and (letter =="Q") and  (done==False)):
			# print "push ECX"
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
		findPushAsciiMixed(s[t].data2,Num)
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


		ans= disCheckStrings(y, instructionsLength, 0, "basic")

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
	for x in s:
		print (s[t].sectionName)
		print ("\t"+str(len(s[t].Strings)))
		print ("\t"+str(len(s[t].wideStrings)))
		t+=1
	t=0

def printStrings():
	t=0
	try:
		for sec in pe.sections:
			print (s[t].sectionName)
			for x,y,z  in s[t].Strings:
				print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z))) 
			print ("wideStrings res")
			for x,y in s[t].wideStrings:
				print ("\t"+ str(x) + "\t" + str(hex(y)))
			for x,y, z in s[1].wideStrings:
				print ("\t"+ str(x) + "\t" + str(hex(y)))
				
			for x, y in s[t].pushStrings:
				print ("\t"+ str(x) + "\t" + str(hex(y)))
			print ("\n")
			t+=1
	except:
		pass
	for x,y,z  in stringsTemp:
		print ("\t"+ str(x) + "\t" + str(hex(y)) + "\t" + str(hex(z))) 


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

	# elif(bit32):
	# 	for secNum in range(len(s)):
	# 		# print("Trying section: " + str(secNum))
	# 		data2 = s[secNum].data2
	# 		# print("before mov"
	# 		for match in FSTENV_GET_BASE.values(): #iterate through all opcodes representing combinations of registers
	# 			get_FSTENV(10, 15, match, secNum, data2) #19 hardcoded for now, seems like good value for peb walking sequence

	for secNum in range(len(s)):
			# print("Trying section: " + str(secNum))
			data2 = s[secNum].data2
			# findAllPebSequences(data2, secNum)
			for match in EGGHUNT.values(): #iterate through all opcodes representing combinations of registers
				get_Egghunters(20, 20, match, secNum, data2)

	printSavedEgg()
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


def AustinTesting2():
	data2 = s[0].data2
	disHereTiny(data2)
	filename=data2
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
	print("goodstring ", word, size)
	numbers = sum(c.isdigit() for c in word)
	letters = sum(c.isalpha() for c in word)
	spaces  = sum(c.isspace() for c in word)
	others  = len(word) - numbers - letters - spaces
	print (numbers,letters,spaces,others)
	
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
	print (letters, (letters+numbers+spaces)/wordSize, len(word), size)
	if (letters >= 2) and ((letters+numbers+spaces)/wordSize > .65) and (len(word) >=size):
		print ("yes, goodString")
		return True

	if word.lower() in GoodStrings:
		return True
 
	for each in GoodStrings:    ### maybe too computationally expensive if long list??
		if each.lower() in word.lower():
			return True
	return False


def goodStringWide(data,word, size):
	print("goodStringWide ", word, size)
	numbers = sum(c.isdigit() for c in word)
	letters = sum(c.isalpha() for c in word)
	spaces  = sum(c.isspace() for c in word)
	others  = len(word) - numbers - letters - spaces
	print (numbers,letters,spaces,others)
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
	print (letters, len(word), size)
	if (letters >= 5)  and (len(word) >=size):
		print ("yes, goodStringWide")
		return True

	if word.lower() in GoodStrings:
		return True
 
	for each in GoodStrings:    ### maybe too computationally expensive if long list??
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


def readShellcode(shellcode):
	file1 = open(shellcode, 'r') 
	shells = file1.read() 
	# print("\nshells\n")
	shells = re.sub(rf"[{string.punctuation}]", "", shells)
	print (shells)
	shells=splitBackslashx(shells)
	shells=splitArrLit(shells)
	shells=split0x(shells)
	# print("\nshells2\n")
	print(shells)
	shells=fromhexToBytes(shells)
	# printBytes(shells)
	print ("\n\n\nend\n")
	return shells

def reduceShellToStrHex(shellcode):
	shells=splitBackslashx(shellcode)
	shells=splitArrLit(shells)
	shells=split0x(shells)
	# print("\nshells2\n")
	dprint(shells)
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
	dprint (type(b))
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
			val="     label_"+addb+":\n"
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
				return val_b+ " (??)"    ## ?? because goes to offset that doesn't exit! Probably db or something else
	except:
		pass
	return val_b

def checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, possibleBadLabelOffsets,data, num_bytes):
	# val_b=checkForValidAddress(val_a,val_b1, val_b2, sizeShell, possibleBadLabelOffsets)
	val_b=val_b1+ " " +  val_b2 
	try:
		if str(val_b2) in possibleBadLabelOffsets:
			dprint ("oh noes "  + val_b2)
			print(val_a, val_b1, val_b2)
			# res=specialDisDB(data, int(val_a,16))
			# val_b=res
			addy=int(val_a,16)
			modifyShByRange(data, addy,addy+num_bytes,"d")
			# val_b =  val_b+ " (??)"
			
			print ("check2: valb: "  + val_b + " " + str(num_bytes) )
			
			num_bytes=num_bytes-1
			
			
			return val_b, num_bytes
	except:
		pass
	return val_b,0



def testcb(buffer, size, offset, userdata):
    # always skip 2 bytes of data
    return 8

def specialDisDB2(data):
	dprint("special2")
	out=binaryToStr(data[:1])
	out=out[1:]
	val="db 0"
	return val+out+" (?)"
def specialDisDB(data,addy):  #//takes bytes
	cs.skipdata = True
	cs.skipdata_setup = ("db", None, None)
	dprint (binaryToStr(data[addy:addy+1]))
	address=0
	val_b=""
	for i in cs.disasm(data[addy:addy+1], address):
		val_b=i.mnemonic + " " + i.op_str 
		dprint ("hi2")
		try:
			dprint (val_b)
			return val_b
		except:
			pass
	return val_b

def makeDBforUnknownBytes(num_bytes, val_c,addb):
	# dprint ("makeDBforUnknownBytes(num_bytes, val_c)")
	dprint (num_bytes)
	dprint (val_c)
	bVal_c = reduceShellToStrHex(val_c)
	# dprint("ans:")
	reducedVal_c=(binaryToStr(bVal_c))
	dprint (reducedVal_c)
	# dprint(type(bVal_c))
	new=specialDisDB2(bVal_c)
	newVal_c=val_c[:4]
	dprint ("new")
	dprint (newVal_c)
	res=makeAsciiforDB(newVal_c)
	num_bytes=int(len(val_c)/4)
	address=0x0
	val =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(addb, new, newVal_c, res))
	dprint (val)
	dprint (num_bytes)
	dprint ("bval")
	dprint (type(bVal_c))
	reducedVal_c=reducedVal_c[4:]
	num_bytes=int(len(reducedVal_c)/4)

	return val, num_bytes, reducedVal_c

def disHereMakeDB(data,offset, end, mode, CheckingForDB):
	global labels

	dprint ("dishereMakeDB "  + str(offset) + " end: " + str(end))

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
		dprint ("truth check " + addb)
		truth,res=checkForLabel(addb,labels)
		if truth:
			val=res+val
		valCheck=i.mnemonic + " " + i.op_str 
		addb=str(hex(int(addb,16)+1))
		dprint("final val_c")
		dprint(type(val_c))
		val2.append(val)
		val3.append(add2)
		val5.append(val+"(!)")
		t+=1
	returnString=""
	dprint ("dishereMakeDB2 "  + str(offset) + " end: " + str(end))
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
	dprint(type(data))
	CODED3=reduceShellToStrHex(data)

	dprint(type(CODED3))
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
	dprint (res)
	return res


def addDis(address, line,):
	global tempDisassembly
	global tempAddresses
	tempDisassembly.append(line[:-2])

	try:
		tempAddresses.append(str(hex(address)))
	except:
		tempAddresses.append(address)


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

def printTempDisAustin():
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
		offset=int(offset,16)
		each1 = array[1]
		each2 = array[2]
		each3 = array[3]
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
	tempDisassembly.clear()
	tempAddresses.clear()

def checkForBad00(data, offset, end):
	print("checkForBad00")
	global tempAddresses
	global tempDisassembly
	print (len(tempAddresses), len(tempDisassembly))
	sample="add byte ptr \[eax], al"
	ans=[]
	for x in range(4):
		if str(hex(offset)) in tempAddresses:
			print("FOUND candidate", str(hex(offset)))
			index=tempAddresses.index(str(hex(offset)))


			print (index, tempDisassembly[index], tempAddresses[index])
			findBad00= re.search(sample, tempDisassembly[index], re.M|re.I)
			if findBad00:
				print ("    ", tempAddresses[index], "gots it")
				ans.append(int(tempAddresses[index],16))
				ans.append(int(tempAddresses[index],16) +1)
		offset+=1
	print (ans)
	if len(ans)>0:
		size=len(ans)-1
		distance = ans[size]-ans[0]
		print(distance)
		print (ans[0], ans[distance])
		modifyShBySpecial(data, ans[0], end, "al")
		modifyShByRange(data, ans[0], end,  "d")



def disHereMakeDB2(data,offset, end, mode, CheckingForDB):
	print("dis: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	num_bytes=end-offset
	print (num_bytes)
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
		print ("checkingDis", hex(offset), hex(length))
	

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
			print("FoundSTRING", hex(stringStart), hex(offset),"off")
			if stringStart==offset:
				dbOut=""
				before=""
				beforeS=sVal 
				# beforeS=removeLastLine(sVal)
				print (sVal, "\n", beforeS)
				# print ("beforeS", sVal, beforeS)
				sVal=""
				startAddString=str(hex(offset))
				stringVala=shBy.stringsValue[offset]+" ; string"
				dbOut+=(binaryToStr(data[t:t+1]))
				print (stringVala)
				
			if offset>stringStart:
				print (stringVala)
				print ("dbout ", hex(t))
				dbOut+=(binaryToStr(data[t:t+1]))
		if (shBy.strings[offset]==False):#  and shBy.boolspecial[offset]==False:
			print("FoundNOTSTRING", hex(stringStart), hex(offset),"off")

			stringInProgress=False
			if dbFlag==False  and shBy.boolspecial[offset]==False:
				# print ("dbflag=False")
				truth,res=checkForLabel(str(hex(offset)),labels)
				if truth:
					val=val+res
					stringVal=stringVal+res
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				stringVal+=curDisassembly

				addDis(offset,"A."+curDisassembly)
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
				addDis(int(startAddString, 16),"B."+curDisassembly)
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				if  shBy.boolspecial[offset]==False:
					stringVal+="*C"+curDisassembly
					addDis(offset,""+curDisassembly)
				if len(beforeS) > 0:
					stringVal= beforeS +"\n"+ "C."+curDisassembly
				print ("stringVal", stringVal)
				dbOut=""
				print (stringVal)
				dbFlag=False
				skip=True
			if not skip:
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				stringVal+="*B"+curDisassembly
				addDis(offset,"D."+stringVal)
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
			stringVal+="*A"+curDisassembly
			addDis(shBy.specialStart[offset],"D."+curDisassembly)
			# print ("got it align", hex(offset))
			print (hex(len(shBy.boolspecial)))

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
				addDis(startAddString,"E."+curDisassembly)
				# stringVal= beforeS + stringVal
				dbOut=""
				dbFlag=False
				if len(dbOut)>0:
					curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
					stringVal+=curDisassembly
					addDis(offset,"F."+curDisassembly)
			w=0
	# print("ending: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	print("returnDB2\n", val)
	print("stringval\n")
	print(stringVal)
	print ("")
	val=stringVal
	return val

debuging=True
# debuging=False
def dprint(info):
	global debuging
	# print("Debug")
	if debuging==True:
		print(info)

def dprint2(*args):
	global debuging
	# print("Debug")
	out=""
	if debuging==True:
		for each in args:
			try:
				each=str(each)
			except:
				pass
			out+=(each) +"\t"
	print (out)

def removeBadOffsets(notBad):
	print("remove offset ", notBad)
	global possibleBadLabelOffsets
	for x in possibleBadLabelOffsets:
		# print (x, type(x))
		if x == notBad:
			print ("it gone")
			possibleBadLabelOffsets.remove (x)
	print (possibleBadLabelOffsets)


def removeLabels(notLabel, val):
	print("remove labels ", notLabel)
	# labels.append(str(hex(destination)))
	# labelOffsets.append(int(i.op_str, 16))
	global labels
	t=0
	for x in labels:
		# print (x, type(x))
		if x == val:
			print ("labels it gone")
			labels.remove (x)
			del labelOffsets[t]
			print ("labels it gone2")
		t+=1


def analysisFindHiddenCalls(data, startingAddress):
	dprint("analysisFindHiddenCalls " + str(startingAddress))
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
		print ("1ana",  "start", hex(start), "current", hex(current),  hex(distance))
		if max==current:
			current+=1
		print(binaryToStr(data[start:current]))
		if not typeBytes:
			dprint ("AN: above is data")
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
	print("anaFindF2")
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
		print ("checking", hex(offset))


		while (test == OP_FF) and (shBy.bytesType[offset]==False):
			print ("enter", hex(offset))
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
			print (total, "newAlignTotal")
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
	print("analysisConvertBytes", startingAddress)
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
		print(binaryToStr(data[start:current]))
		finalPrint+=finalPrint0
		if not typeBytes:
			dataRangeStart.append(start)
			dataRangeEnd.append(current)
		start, current, distance, typeBytes = findRange2(current)
	t=0
	print ("final ranges")
	for x in dataRangeStart:
		try:
			distance=dataRangeStart[t]-dataRangeEnd[t-1]
		except:
			distance=0
		try:
			print (hex(dataRangeEnd[t-1]), hex(dataRangeStart[t]) )
			if str(hex(dataRangeEnd[t-1])) not in labels:
				# print (str(hex(dataRangeEnd[t-1])),"not in label0")
				# s2=dataRangeEnd[ t-1]
				# s1=dataRangeStart[t-1]
				# print (s1, s2)
				# ans, valb_1, valb_2, num_bytes=disHereTiny(data[s1:s2])
				# print(ans, "ans convertbyes")
				if distance <=5:
					print ("make data?")
					modifyShByRange(data, dataRangeEnd[t-1],dataRangeEnd[t-1]+distance, "d")
			else: 
				print (str(hex(dataRangeEnd[t-1])),"****in labels")
		except:
			pass
		print (hex(distance))
		print ("*************************\n")
		t+=1

def anaFindCalls(data, start, current):
	global offsets
	print ("anna: " + " "  + str(hex(start)) + " " + str(hex(current)) )
	OP_CALL =  b"\xe8"
	OP_ff =  b"\xff"
	print (binaryToStr(data[start:current]))
	t=0
	destination=99999999
	searchFor=[]
	for opcode in data[start:current]:
		test=int(data[start+t])
		# print (hex(test), hex(ord(OP_CALL)))
		if test==ord(OP_CALL):
			dprint("FOUND 0xe8!")
			ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
			dprint2 (ans, valb_1, valb_2)
			if valb_1=="call":
				modifyShByRange(data, start+t,start+t+5,"i")
				###check to see if = FF FF FF  - negative - otherwise, positive!
				dprint ("checking ff")
				dprint2 (int(data[start+t+4]), ord(OP_ff))
				if (int(data[start+t+4]))==ord(OP_ff):
					if (int(data[start+t+3]))==ord(OP_ff):
						signedNeg=signedNegHexTo(int(valb_2,16))
						destination=(start+t) +signedNeg
						ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
						dprint (valb_2)
						dprint("ff destination: " + str(hex(destination)))
						if str(hex(destination)) not in labels:
							print  ("1 appending label " + str(hex(destination)))
							labels.append(str(hex(destination)))
				#ok, it is positive
				elif (int(data[start+t+4]))==0:
					# if (int(data[start+t+3]))==0:
					ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
					destination = (start+t) + int(valb_2,16)
					# print ((hex(start+t)))
					# print(hex(signedNeg))
					dprint("00 destination: " + str(hex(destination)))
					if str(hex(destination)) not in labels:
						print  ("2 appending label " + str(hex(destination)))
						labels.append(str(hex(destination)))
				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))
		t+=1
	for addy in searchFor:
		if addy in offsets:
			dprint("In offsets")
		else:
			if int(addy,16) not in offsets:
				offsets.append(int(addy,16))
			dprint("Not in offsets")
			# removeBadOffsets(addy)
			modifyShByRange(data, int(addy,16)-2, int(addy,16),"d")

def anaFindShortJumps(data, start, current):
	global offsets
	global labels
	dprint ("anna2: " + " "  + str(hex(start)) + " " + str(hex(current)) )
	OP_SHORT_JUMP =  b"\xeb"
	OP_SHORT_JUMP_NEG =  b"\xe9"
	OP_ff =  b"\xff"
	dprint (binaryToStr(data[start:current]))
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
				dprint ("checking short jump")
				modifyShByRange(data, start+t,start+t+num_bytes,"i")
				destination = (start+t) + int(valb_2,16)
				dprint("eb destination: " + str(hex(destination)))
				if str(hex(destination)) not in labels:
					labels.append(str(hex(destination)))
					print  ("3 appending label " + str(hex(destination)))

				
				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))
		# FINE, IT IS NEGATIVE
		if test==ord(OP_SHORT_JUMP_NEG):
			dprint("FOUND 0xe9!")
			ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
			dprint2 (ans, valb_1, valb_2)
			dprint2 ("ans:",ans)
			if valb_1=="jmp":
				modifyShByRange(data, start+t,start+t+num_bytes,"i")
				dprint ("checking short jump negative")
				destination = (start+t) + int(valb_2,16)
				dprint("neg e9 destination: " + str(hex(destination)))
				if str(hex(destination)) not in labels:
					labels.append(str(hex(destination)))
					print  ("4 appending label " + str(hex(destination)))

				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))




		t+=1
	for addy in searchFor:
		if int(addy,16) in offsets:
			dprint("In offsets")
		else:
			dprint("Not in offsets")
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
	dprint ("disHereAnalysis - range  "  + str(offset) + " " + str(end))
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
				print("addlabel:  " + val)
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
	dprint (possibleBadLabelOffsets)
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
				dprint ("truth check " + addb)
				truth,res=checkForLabel(addb,labels)
				if truth:
					val=res+val
				valCheck=i.mnemonic + " " + i.op_str 
				addb=str(hex(int(addb,16)+1))
				dprint("final val_c")
				dprint(type(val_c))
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


def disHereShell(data,offset, end, mode, CheckingForDB): #
	global labels
	global offsets
	global labelOffsets
	global possibleBadLabelOffsets
	printAllShByRange(offset,end)
	dprint ("dis: dishereshell - range  "  + str(hex(offset)) + " " + str(hex(end)))
	dprint(binaryToStr(data[offset:end]))
	dprint(binaryToStr(data))
	nada=""
	
	global o
	w=0

	try:
		address=offset
	except:
		address=0
	i=0
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
	for i in cs.disasm(CODED3, address):
		cntLines+=1
		val=i.mnemonic + " " + i.op_str 
		offsets.append((int(i.address)))
		controlFlow= re.match( r'\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bja\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', val, re.M|re.I)
		if controlFlow:
			val=i.op_str
			isHex= re.match( "^[0-9][x]*[A-Fa-f0-9 -]*",val, re.M|re.I)
			if isHex:
				print("addlabel: shell call " + val)
				is0x=re.match("0x*",val, re.M|re.I)
				if not is0x:
					val="0x"+val
				print  ("6 appending label " + val)

				labels.append(val)
				labelOffsets.append(int(i.op_str, 16))
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
	dprint (possibleBadLabelOffsets)
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
		print ("weird error - investigate")
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
		# CheckingForDB=False
		if CheckingForDB:
			try:
				num_bytes=int(len(val_c)/4)
			except:
				num_bytes=1
			val_b, num_bytes =checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, possibleBadLabelOffsets,data,num_bytes)

		if mode=="ascii":
			val =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(val_a, val_b, val_c, val_d))
			addDis(int(val_a, 16), "*"+val)
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
				print ("push match", shBy.pushStringValue[cur])
				nada=""
				msg="; "+shBy.pushStringValue[cur] + " - Stack string"
				newVal =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(nada, msg, nada, nada))
				val= newVal+val
				print (val)
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


	print ("possibleBadLabelOffsets")
	print (possibleBadLabelOffsets)
	return returnString

def disHereTiny(data): #
	address=0
	i=0
	CODED2=data
	val =""
	val2 = []
	val3 = []
	val5 =[]
	print ("disheretiny")
	binStr=(binaryToStr(data))
	print(binStr)
	first_val_b=""
	first_val_b1=""
	first_val_b2=""
	first=True
	second=0
	num_bytesLine1=0
	nop="90"
	nop1=fromhexToBytes(nop)
	print (binaryToStr(nop1))
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
			print ("num_bytes", num_bytesLine1)
	if num_bytesLine1==0:
		pass
	returnString=""
	for y in val5:
		returnString+=y+"\n"
	print ("\n")
	print (returnString + "rs\n")
	return first_val_b, first_val_b1, first_val_b2, num_bytesLine1


def disHereCheck(data): #
	address=0
	i=0
	CODED2=data
	val =""
	val2 = []
	val3 = []
	val5 =[]
	dprint ("disHereCheck")
	binStr=(binaryToStr(data))
	dprint(binStr)
	first_val_b=""
	first_val_b1=""
	first_val_b2=""
	first=True
	second=0
	num_bytesLine1=0
	nop="90"
	nop1=fromhexToBytes(nop)
	dprint (binaryToStr(nop1))
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
				print("removLab:  " + val)
				
				removeLabels(val_b, val)
				print("done")

		val_b1=i.mnemonic
		val_b2=i.op_str
		num_bytes=0
		val2.append(val)
		val3.append(add2)
		val5.append(val_b)

	returnString=""
	for y in val5:
		returnString+=y+"\n"
	print ("\n")
	print (returnString + "rs\n")
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
					# print("changing value @ " + str(t))
				t+=1

		print (shBy.bytesType)


def modifyShByRange(data, start,end, dataType):
	print ("modRange ", hex(start),hex(end),dataType)
	global shBy
	BytesBool=False
	t=0
	if dataType=="d":
		BytesBool=False
	if dataType=="i":
		BytesBool=True

	if dataType=="d":
		print ("magic")
		out=disHereCheck(data[start:end])
		print(out)
	for x in shBy.bytesType:
		if (t>=start) and (t < end):
			print ("before", shBy.bytesType[t])
			shBy.bytesType[t]=BytesBool
			
			print("changing value @ " + str(hex(t)))
			print (shBy.bytesType[t], " value: ", hex(shBy.values[t]))
			if BytesBool:
				shBy.boolspecial[t]=False
		t+=1



def modifyShBySpecial(data, start,end, dataType):
	print ("modRangeSpecial ", hex(start),hex(end),dataType)
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
			print ("before", shBy.specialVal[t])
			shBy.specialVal[t]=spec
			shBy.specialStart[t]=start
			shBy.specialEnd[t]=end
			shBy.boolspecial[t]=True
			print("changing value align @ " + str(hex(t)))
			print (shBy.specialVal[t], " value: ", hex(shBy.values[t]))
			print(shBy.boolspecial[t], hex(shBy.specialStart[t]), hex(shBy.specialEnd[t]) )
		t+=1

	# print (shBy.bytesType)
def modifyStringsRange(start,end, dataType, word):
	print ("modStrings " )
	print (hex(start),hex(end),dataType)
	global shBy
	BytesBool=False
	t=0
	if dataType=="ns":
		BytesBool=False
	if dataType=="s":
		BytesBool=True
	for x in shBy.bytesType:
		if (t>=start) and (t < end):
			# print (shBy.strings[t])
			shBy.strings[t]=BytesBool
			shBy.stringsStart[t]=(tuple((start, end-start)))
			shBy.stringsValue[t]=word
			print("changing Strings value @ " + str(hex(t)))
			print (shBy.strings[t], " value: ", hex(shBy.values[t]))
			print (hex(t))
			# print (shBy.stringsValue[t])

			# print (hex(shBy.stringsStart[t]), " value: ", hex(shBy.values[t]))
			x,y=shBy.stringsStart[t]
			print (x,y)
		t+=1
	# print (shBy.bytesType)

def modifyPushStringsRange(start,end, dataType, word):
	print ("modStringPush " )
	print (hex(start),hex(end),dataType)
	global shBy
	BytesBool=False
	t=0
	if dataType=="ns":
		BytesBool=False
	if dataType=="s":
		BytesBool=True
	for x in shBy.bytesType:
		if (t>=start) and (t < end):
			# print (shBy.strings[t])
			shBy.strings[t]=False
			shBy.stringsStart[t]=(tuple((0, 0)))
			shBy.stringsValue[t]=""
			shBy.pushStringEnd[t]= end
			shBy.pushStringValue[t]=word
			shBy.boolPushString[t]=BytesBool
			print("changing StringsPush value @ " + str(hex(t)))

			print (shBy.boolPushString[t], " value: ", hex(shBy.values[t]))
			print ("end", shBy.pushStringEnd[t])
			print (hex(t))
			# print (shBy.stringsValue[t])

			# print (hex(shBy.stringsStart[t]), " value: ", hex(shBy.values[t]))
			x,y=shBy.stringsStart[t]
			print (x,y)
		t+=1
	# print (shBy.bytesType)
def printAllShBy():
	print("printAllShBy")
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
	print (out)


def printAllShByStrings():
	print("printAllShByStrings")
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
	print (out)

def printAllShByRange(start,end):
	print("printAllShBy " + str(hex(start)) + " "  + str(hex(end) ))
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
	print (out)

def findTargetAddressReturnPrior(targetAddress, linesGoBack, l1, l2):
	tl1=[]
	tl2=[]
	linesGoBack=linesGoBack-1
	# targetAddress=0x0
	try:
		index = l1.index(targetAddress)
	except ValueError:
		dprint ("Target Index not found")
		return False, tl1, tl2
	print ("my own index", index)
	print (index - linesGoBack)
	if (index - linesGoBack) < 0:
		print ("ok")
		linesGoBack= index-0
		print ("linesGoBack", linesGoBack)

	tl1=l1[index-linesGoBack:index+1]
	tl2=l2[index-linesGoBack:index+1]
	t=0
	print ("size", len(tl1))
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

	if rawBin:
		shellBytes=rawData2
	if not rawBin:
		rawBytes=readShellcode(filename) 
		rawData2=rawBytes
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
	if FindStringsStatus:
		findStrings(shellBytes,3)
		findStringsWide(shellBytes,3)
		findPushAsciiMixed(shellBytes,3)
	anaFindFF(shellBytes)
	out=findRange(shellBytes, startingAddress)  #1st time helps do corrections
	anaFindFF(shellBytes)
	l1, l2=printTempDisAustin()
	# saveDB()
	clearDisassBytClass()
	truth, tl1, tl2= findTargetAddressReturnPrior(targetAddress, linesGoBack, l1, l2)

	print ("sizetl1", len(tl1))
	return truth, tl1, tl2, l1,l2

def takeBytes(shellBytes,startingAddress):
	global shBy
	global FindStringsStatus
	print ("take bytes")

	# FindStringsStatus=False
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

	# modifyShByRange(data, 0x14, 0x19, "d")
	print ("FindStringsStatus", FindStringsStatus)
	if FindStringsStatus:
		# import sharem
		findStrings(shellBytes,3)
		findStringsWide(shellBytes,3)
		findPushAsciiMixed(shellBytes,3)
	anaFindFF(shellBytes)
	addComments()

	out=findRange(shellBytes, startingAddress)  #1st time helps do corrections
	
	anaFindFF(shellBytes)
	clearTempDis()
	out=findRange(shellBytes, startingAddress) # makes sure all corrections fully implemented
	# printAllShBy()
	print ("printing final\n")
	printTempDisAustin()
	assembly=binaryToText(shellBytes)
	return out+assembly

def addComments():
	for item in m[o].save_PEB_info:
		tib=item[5]
		shBy.comments[int(tib,16)] = "; load TIB"
		ldr=item[6]
		shBy.comments[int(ldr,16)] = "; load PEB_LDR_DATA LoaderData"
		mods=item[7]
		shBy.comments[int(mods,16)] = "; LIST_ENTRY InMemoryOrderModuleList"
		# print ("index of tib is", tib)
		# print ("index of ldr is", ldr)
		# print ("index of mods is", mods)
# ; PEB_LDR_DATA LoaderData
      # mov ebp,[eax+1ch]          ; LIST_ENTRY InMemoryOrderModuleList
def findInList(listPeb, address):
	t=0
	for x in listPeb:
		if listPeb[t]==address:
			# print ("found", t)
			return t, True
		t+=1
	return 0, False

def findRange(data, startingAddress):
	global FindStringsStatus
	current=0
	start=startingAddress
	max=len(shBy.bytesType)-1
	finalPrint=""
	analysis= disHereAnalysis(data, False, False, "ascii", True)
	analysisFindHiddenCalls(data, startingAddress)
	analysisConvertBytes(data, startingAddress)
	analysisFindHiddenCalls(data, startingAddress)
	# anaFindAlign2(data)#, startingAddress)
	if FindStringsStatus:
		anaFindStrings(data,startingAddress)
	while current < max:
		start, current, distance, typeBytes = findRange2(current)
		finalPrint0=""
		print ("max: " + str(hex(max)) + " "+str(hex(current)))
		if max==current:
			current+=1
		print(binaryToStr(data[start:current]))
		if typeBytes:
			print ("above is instructions")
			finalPrint0+= (disHereShell(data, start, current, "ascii", True))
		if not typeBytes:
			print ("above is data")
			finalPrint0+= (disHereMakeDB2(data, start, current, "ascii", True))
		print (finalPrint0)
		finalPrint+=finalPrint0
		# analysisFindHiddenCalls(data, startingAddress)
	print ("\n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n"+finalPrint)
	print ("\n\n")
	print (binaryToStr(data))
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
	print ("size", len(shBy.bytesType))
	if shBy.bytesType[begin]==False:
		typeData="data"
		# print ("*********making data" )
	else:
		typeData="inst"
		# print ("********making inst")
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
					dprint ("FIN: data done!")
					distance=current-start
					print ("r d-:",hex(start), hex(current), hex(distance), typeBytes)
					return start, current, distance, typeBytes
			t+=1
	t=0
	if typeData=="inst":
		# dprint ("ins")
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
					dprint ("FIN: instructions done!")
					distance=current-start
					print ("r: i-",hex(start), hex(current), hex(distance), typeBytes)
					return start, current, distance, typeBytes
			t+=1
	distance=current-start
	print ("r: -end", hex(start), hex(current), hex(distance), (typeBytes))
	return start, current, distance, typeBytes

FindStrings=True

def anaFindStrings(data, startingAddress):
	# global FFInstructions
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp
	print("anaFindStrings")
	# print (sharem.stringsTemp)
	OP_FF=b"\xff"

	for word,offset,distance  in stringsTemp:# and stringsTemp:
		print ("\t"+ str(word) + "\t" + str(hex(offset)) + "\t" + str(hex(distance))) 
		if goodString(data,word,6):
			modifyShByRange(data, offset, offset+distance, "d")
			modifyStringsRange(offset, offset+distance, "s", word)
			total=0			
			v=1
			w=0
			test=b"\xff"
			while (test == OP_FF):
				print(word, "2binaryToStrCheck", binaryToStr(data[offset+distance:offset+distance+v]))
				test=(data[offset+distance+w:offset+distance+v])
				test2=(data[offset+distance+w:offset+distance+v+1])
				print ("test2", len(test2), hex(offset+distance+w), hex(offset+distance+v+1))
				if test==(OP_FF) and (test2 not in FFInstructions):
					print("gots one") # this just counts how many FF's there are that are not part of a more import instruciton'
					total+=1
				v+=1
				w+=1
			print ("fftotal",total)
			if total > 1:
				modifyShByRange(data, offset, offset+distance+total, "d")
				# modifyStringsRange(offset, offset+distance+total, "s", word)

	##WIDE			
	print ("wideStringsStart")	
	try:
		for word,offset,distance  in stringsTempWide:# and stringsTemp:
			print ("ok")
			print ("\t"+ str(word) + "\t" + str(hex(offset)) + "\t" + str(hex(distance))) 
			# print (word, offset, distance, "before modify range")
			# modifyStringsRange(offset, offset+distance, "s", word)
			# print (goodString(data,word,6),"goodstring", word)
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
					print(word, "2binaryToStrCheck", binaryToStr(data[offset+distance:offset+distance+v]))
					test=(data[offset+distance+w:offset+distance+v])
					test2=(data[offset+distance+w:offset+distance+v+1])
					# if test==(OP_FF) and (test2 != inc_esi):
					print ("test2", len(test2), hex(offset+distance+w), hex(offset+distance+v+1))
					if test==(OP_FF) and (test2 not in FFInstructions):
						print("gots one") # this just counts how many FF's there are that are not part of a more import instruciton'
						total+=1
					v+=1
					w+=1
				print ("fftotal",total)
				if total > 1:
					modifyShByRange(data, offset, offset+distance+total, "d")
					# modifyStringsRange(offset, offset+distance+total, "s", word)
	except:
		print ("Exception")
		print (e)
		pass
	###   end
	print ("end wideStrings")
	# pushStringsTemp.append(tuple((word4, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength)))
	print("pushmixed")
	for word, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength in pushStringsTemp:
		try:
			print ("word", word, "starting offset:", hex(offset), "; ending offset:", hex(offset+instructionsLength))
		except:
			word="error"
			print ("word", word, "starting offset:", hex(offset), "; ending offset:", hex(offset+instructionsLength))
			print ("pushmixed error")
	distance=0
	for word, offset, offsetVA,offsetPlusImagebase, wordLength,instructionsLength in pushStringsTemp:
		# offset=ofset-2
		try:
			print ("word", word, "starting offset", hex(offset), "ending offset", hex(offset+instructionsLength))
		except:
			word="error"
			print ("pushmixed error2")
		distance=instructionsLength
		print ("instructionsLength", instructionsLength, type(instructionsLength))
		if goodString(data,word,4):
			print ("push mixed change", word, hex(offset), hex(offset+distance), hex(len(data)))
			modifyShByRange(data, offset-2, offset+distance, "i") # -2 is a correction
			modifyPushStringsRange(offset, offset+distance, "s", word)
			total=0			
			v=1
			w=0
			test=b"\xff"
			while (test == OP_FF):
				print(word, "pushstrings", binaryToStr(data[offset+distance:offset+distance+v]))
				test=(data[offset+distance+w:offset+distance+v])
				test2=(data[offset+distance+w:offset+distance+v+1])
				print ("test2", len(test2), hex(offset+distance+w), hex(offset+distance+v+1))
				if test==(OP_FF) and (test2 not in FFInstructions):
					print("gots one PS") # this just counts how many FF's there are that are not part of a more import instruciton'
					total+=1
				v+=1
				w+=1
			print ("PS fftotal",total)
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
		print(binaryToStr(data[start:current]))
		if not typeBytes:
			print ("AFS: above is data", hex(start))
			if shBy.strings[start]==True:
				xStart, ydis=shBy.stringsStart[start]
				print (hex(start))
				print ("AFS: strings ", hex(xStart), hex(ydis), shBy.stringsValue[start])
		start, current, distance, typeBytes = findRange2(current)
		##reset once done - do analysis again to catch any changes 
		if (current) == max and reset != True:
			reset=True
			print ("reset")
			current=0
	print (shBy.stringsValue)




def anaFindFF(data):
	# global FFInstructions
	print("anaFindFF")
	OP_FF=b"\xff"
	OP_00=b"\x00"

	offset=0
	maxV=len(data)
	escape=False
	while offset < maxV:
	# for datum in data:
		# print ("ff:\t"+ str(binaryToStr(data[offset:offset+1])) + "\t" + str(hex(offset)))
		escape=False
		total=0			
		total2=0
		v=1
		w=0
		vv=1
		ww=0
		distance=0
		# print ("total", total)
		# test=b"\xff"
		test=(data[offset+distance+w:offset+distance+v])
		while (test == OP_FF):
			# print ("w", hex(w), "v", hex(v), "offset", hex(offset))
			# print( "2binaryToStrCheck", binaryToStr(data[offset+distance:offset+distance+v]))
			test=(data[offset+distance+w:offset+distance+v])
			test2=(data[offset+distance+w:offset+distance+v+1])
			# if test==(OP_FF) and (test2 != inc_esi):
			if test==(OP_FF) and (test2 not in FFInstructions):
				total+=1
				print(" OP_FF, total, gots one", total, hex(offset)) # this just counts how many FF's there are that are not part of a more import instruciton'
				
			v+=1
			w+=1
			escape=True

		test=(data[offset+distance+ww:offset+distance+vv])
		while (test == OP_00):

			print ("op_00", "ww", hex(w), "vv", hex(v), "offset", hex(offset+distance+ww))
			print( "2binaryToStrCheck", binaryToStr(data[offset+distance+ww:offset+distance+vv]))
			test=(data[offset+distance+ww:offset+distance+vv])
			# if test==(OP_FF) and (test2 != inc_esi):
			if test==(OP_00): #and (test2 not in FFInstructions):
				# print("gots one") # this just counts how many FF's there are that are not part of a more import instruciton'
				total2+=1
				print ("total2", total2)
				print (hex(offset), hex(offset+distance+ww))
			vv+=1
			ww+=1
			escape=True
		# print ("ffcount",total)
		if total > 3:
			print (total, "ffTotal2")
			modifyShByRange(data, offset, offset+distance+total, "d")
			modifyShBySpecial(data, offset, offset+distance+total, "ff")
			# modifyStringsRange(offset, offset+distance+total, "s", word)
		if total2 > 4:
			print (total2, "00Total2")
			modifyShByRange(data, offset+4, offset+distance+total2, "d")
			modifyShBySpecial(data, offset+4, offset+distance+total2, "al")

			checkForBad00(data, offset, offset+distance+total2)
			# modifyStringsRange(offset, offset+distance+total, "s", word)
		if escape:
			# print ("inc offset", escape, hex(offset))
			if total >1 or total2> 1:
				offset+=total
				offset +=total2
			else:
				offset+=1

		if not escape:
			# print ("inc offset, not", escape, hex(offset))
			offset+=1




# >>> bin(0b1111 ^ 0b1111)
# '0b0'
# >>> bin(0b1111 ^ 0b0000)
# '0b1111'
# >>> bin(0b0000 ^ 0b1111)
# '0b1111'
# >>> bin(0b1010 ^ 0b1111)
# '0b101'

def encodeShellcode(data):
	print ("encodeShellcode")
	global rawData2
	print (binaryToStr(rawData2))
	shells=""
	for each in rawData2:
		new=each^0x55
		new+=1
		new= new ^ 0x11
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
	except:
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
##### START


# Extraction()

# starting()
# AustinStart()
# AustinTesting()


# bramwellStart()
# testing8Start()


# testing8Start()
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
			print ("\nDID IT", hex(x), ans)
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
	yes="yes"
	if yes=="yes":
		disassembly=takeBytes(old,0)
		print ("old disassembly")
		print (disassembly)
		final=old[:0x23] +new[0x23:]
		clearDisassBytClass()
		disassembly=takeBytes(final,0)

		print ("combined")
		print (disassembly)


	##### end example


	yes="yes1"
	if yes=="yes1 ":

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

def shellDisassemblyStart(shellArg):
	global filename
	global rawData2
	filename=shellArg
	rawBytes=readShellcode(shellArg) 
	mode=""
	rawData2=rawBytes
	# printBytes(rawBytes)
	# print (disHereShell(rawBytes, False, False, "ascii", True))
	# print ("SizeRawdata2", len(rawData2)) 
	rawBytes=rawData2
	findAllPebSequences(mode)
	print ("rawbytes class", type(rawBytes))
	disassembly=takeBytes(rawBytes,0)
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



def shellDisassemblyStart2(shellArg):
	global filename
	global rawData2
	filename=shellArg
	# rawBytes=readShellcode(shellArg) 

	# rawData2=rawBytes
	# # # printBytes(rawBytes)
	# print (disHereShell(rawBytes, False, False, "ascii", True))
	# print ("SizeRawdata2", len(rawData2))
	# rawBytes=rawData2
	# print ("rawbytes class", type(rawBytes))
	print ("size shellArg", len(shellArg) )
	print ("find peb")

	mode=""
	findAllPebSequences(mode)

	print ("find peb res")
	printSavedPEB()
	disassembly=takeBytes(shellArg,0)
	
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
	# newBin = open(directory+"outputs\\"+filename[:-4]+".bin", "wb")
	# newBin.write(rawBytes)
	# newBin.close()
	newDis = open(directory+"outputs\\"+filename[:-4]+"-disassembly.txt", "w")
	newDis.write(disassembly)
	newDis.close()
	# binaryToText(rawBytes)

# fromShellTxt= readShellcode()
# print(fromShellTxt)
# printFromStringLiteralToBytes(fromShellTxt)
# rawBytes=fromStringLiteralToBytes(fromShellTxt)
# printBytes(fromShellTxt)


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


def bramwellDisassembly2():
	global shellcode4
	global filename
	global rawData2
	# testing="shellcodes\\testing.txt"
	# print ("numargs" , numArgs)
	# if numArgs==1:
	# 	shellcode4='shellcode4.txt'
	# 	filename=shellcode4
	# shellDisassemblyStart(filename)
	print ("rawData2 a", len(rawData2))
	shellDisassemblyStart2(rawData2)
	# shellDisassemblyStart2(filename)

if __name__ == "__main__":


	# EXTRACTION - if dealing with PE files, uncomment this:
	try:
		Extraction()
	except:
		pass
	###################################################################
	##Bramwell's work - may comment out if need be
	mode=""
	# bramwellDisassembly()
	# findAllPebSequences(mode)
	# printSavedPEB()
	# findAllPushRet()
	# printSavedPushRet()

	# bramwellStart()

	# bramwellDisassembly()   # .txt file
	# bramwellStart2()



	## AUSTIN --> get list of disassmebly from from shellcode and list of of offsets

	#sample input -- if nothing found, it will return as false
	targetAddress=0x2
	linesGoBack=10
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, targetAddress, linesGoBack)  # arg: starting offset/entry point - leave 0 generally
	if truth:
		####the FULL disassembly of the shellcode
		print ("Full disassembly of shellcode")
		for e in orgListDisassembly:
			print (str(hex(orgListOffset[t])) + "\t" + e)
			t+=1
		print ("\n\n\n")
		t=0

		##### JUST the found list  = target address - linesGoBack
		print ("Found Target Address")
		for each in tl1:
			print (hex(each), tl2[t]) 
			t+=1	
	else:
		print ("Target address not found")


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
	# AustinStart()
	# AustinTesting()
