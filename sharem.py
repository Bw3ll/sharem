from capstone import *
from sharemu import *
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

try:
	import win32api
	import win32con
	import win32file
	import _win32sysloader

except:
	print ("Pywin32 needs to be installed.\nhttps://pypi.org/project/pywin32/\n\t")
	
import ctypes
from ctypes import windll
from ctypes import wintypes
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
import hashlib
try:
	import ssdeep
except:
	print ("Ssdeep needs to be installed. A Windows Python wrapper is available:\nhttps://github.com/DinoTools/python-ssdeep")

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
res2 = '\u001b[0m'



oldsysOut=sys.stdout
my_stdout = open( 1, "w", buffering = 400000 )

sys.stdout = my_stdout
sys.stdout=oldsysOut
print (res2+"")
			
iatList=[]
m = {} #[]   # start modules CHANGED to dicitonary
mBool = {} #[]   # start modules CHANGED to dicitonary

mL=[]
s = []  # start sections
list_of_files = []
list_of_files32 = []
list_of_files64 = []
list_of_pe32 = []
list_of_pe64 = []

list_of_unk_files = []
current_arch = 0
sharem_out_dir = "current_dir"
emulation_verbose = True

labels=set()
offsets=set()
off_Label=set()
off_PossibleBad=set()

elapsed_time = 0
pebPresent = False
doneAlready1 = []
syscallString = ''
chMode = False
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

shellEntry=0x00
decodedBytes=b''

shellEntry=0x0
useDirectory = False

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
# o=0
gName=""
o="shellcode"
shOrg="shellcode"
shBody="decoded body"
shStub="decoder stub"
shDec="decoded shellcode (full)"
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
filename2=""
filenameRaw=""
skipExtraction=False
rawHex = False
rawData2 = b''
useHash=False
known_arch = False
numArgs = len(sys.argv)
rawBin=False  # only if .bin, not .txt
isPe=False
pointsLimit = 3
maxDistance = 15
useStringsFile = False
minStrLen = 6
mEAX = ''
mEBX = ''
mEDX = ''
mECX = ''
mEBP = ''
mESP = ''


gDisassemblyText=""
emulation_multiline = False
# Moved from viewBool's work area
linesForward = 40
bPushRet = True
bFstenv = True
bSyscall = True
bHeaven = True
bCallPop = True
bPrintEmulation = True
bDisassembly = True
bAnaHiddenCallsDone=False
bAnaConvertBytesDone=False
bAnaFindStrDone=False
deobfShell = True
fastMode=False
pebPoints = 3
p2screen = True
configOptions = {}
print_style = "left"
stubFile = "stub.txt"
sameFile = True
stubEntry = 0
stubEnd = 0
# mBool[o].ignoreDisDiscovery=False
shellSizeLimit=120
conFile = "config.cfg" 
workDir = False
bit32_argparse = False
save_bin_file = True
linesForward = 7
linesBack = 10
bytesForward = 15
bytesBack = 15
unencryptedShell=0x0
decoderShell=0x1
unencryptedBodyShell=0x3
sample=0x4
allObject=0x5
gDirectory="" # #used to hold original directory --immutable 
# debugging=True
debugging=False


GoodStrings={"cmd",  "net","add", "win", "http", "dll", "sub", "calc", "https"}
toggList = {'findString':True, 
			'deobfCode':False,
			'findShell':False,
			'comments':True,
			'hidden_calls':True,
			'show_ascii':True,
			'ignore_dis_discovery':False,
			'opcodes':True,
			'labels':True,
			'offsets':True,
			'max_opcodes':8,
			'binary_to_string':3}

brawHex = ''
bstrLit = ''
bfindString = True
bdeobfCode = False
bdeobfCodeFound = False

bfindShell = True
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

# 	# 		# #global m[o].rawData2

# 	# 		m[o].rawData2 = f.read()
# 	# 		f.close()
# 	# 		# print ("m[o].rawData2", len(m[o].rawData2))
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


def parsePE():
	pass

def parseShell():
	pass

def isDir(file_path):
	if os.path.isdir(file_path):
		return True
	else:
		return False


def isPE(file_path):


	hnd = open(file_path, "rb")
	# print("First 2 bytes: ", repr(hnd.read(2)))
	# print("First 2 bytes: ", repr(hnd.read(2)))

	mz = b'\x4d\x5a'

	mzFile = hnd.read(2)
	# print("Two bytes ", mzFile)
	hnd.close()
	if mzFile == mz:	# PE file
		# print(yel + "Found EXE file" + res, file_path)
		return True
	else:
		return False

def CliParser():
	global gName
	global peName
	global rawData2
	global filename
	global bit32
	global shellBit
	global rawBin
	global rawHex
	global conFile
	global workDir
	global useDirectory
	global bit32_argparse
	global known_arch

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
			gName=shellFile
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

			# print("Shellcode file: ", shellFile)
		else:
			print(args.r, "file doesn't exist")
			sys.exit()
			# print("32 bit")
			bit32 = True

		
		# print (gDirectory, tail)
	# 


	if args.pe:
		if os.path.isfile(args.pe):

			gName = os.path.basename(args.pe)
			peName = args.pe
			# print("PE path is: ", args.pe)
			if win32file.GetBinaryType(args.pe) == 6:
				# print("64 bit file", args.pe)
				bit32 = False
			else:
				# print("32 bit")
				bit32 = True
			gDirectory, tail = os.path.split(peName)  # keave this here
			PE_path=gDirectory
		else:
			print(args.pe, "file doesn't exist3")
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
		useDirectory = True
		if os.path.isdir(args.d):

			workingDir = args.d
			workDir = True
			for path in os.listdir(workingDir):
				full_path = os.path.join(workingDir, path)

				if os.path.isfile(full_path):
					# print("Found file", full_path, isPE(full_path))
					if isPE(full_path):
						print("is pe file", full_path)
						# print("isPE returned", isPE(full_path), full_path)
						if win32file.GetBinaryType(full_path) == 6:
							bit32 = False
							peName = full_path
							list_of_pe64.append(full_path)
							# print("Found 64", full_path)
							# print("-----------------> ", list_of_pe64)

						else:
							bit32 = True
							list_of_pe32.append(full_path)
					else:
						if not known_arch:
							# ext = f[-3:]
							# if ext == "txt":
							# 	rawHex = True
							# 	rawBin = False
							# 	filename = f
							# 	bit32 = True
							# full_file_path = os.path.join(full_path, f)
							list_of_unk_files.append(full_path)
							# else:
							# 	rawHex = True
							# 	rawBin = True
							# 	filename = f
							# 	bit32 = True
							# 	fp = open(f, "rb")
							# 	rawData2 = fp.read()
							# 	fp.close()
							# 	full_file_path = os.path.join(full_path, f)
							# 	list_of_unk_files.append(full_file_path)



				elif isDir(full_path) and known_arch:
					print("here <------------")
					dirName = os.path.basename(full_path)
					# print("isDir Directory: ", dirName)
					if "32" in dirName:
						for f in os.listdir(full_path):
							ext = f[-3:]
							if ext == "txt":
								rawHex = True
								rawBin = False
								filename = f
								bit32 = True
								full_file_path = os.path.join(full_path, f)
								# print("full_file_path", full_file_path)
								list_of_files32.append(full_file_path)
							else:
								rawHex = True
								rawBin = True
								filename = f
								bit32 = True
								fp = open(f, "rb")
								rawData2 = fp.read()
								fp.close()
								full_file_path = os.path.join(full_path, f)
								# print("full_file_path BIN", full_file_path)

								list_of_files32.append(full_file_path)

					elif "64" in dirName:
						for f in os.listdir(full_path):
							ext = f[-3:]
							if ext == "txt":
								rawHex = True
								rawBin = False
								filename = f
								bit32 = False
								full_file_path = os.path.join(full_path, f)
								# print("full_file_path 64 txt", full_file_path)
								list_of_files64.append(full_file_path)
							else:
								rawHex = True
								rawBin = True
								filename = f
								bit32 = False
								fp = open(f, "rb")
								rawData2 = fp.read()
								fp.close()
								full_file_path = os.path.join(full_path, f)
								# print("full_file_path 64 BIN", full_file_path)
								list_of_files64.append(full_file_path)


					else:
						print("Directory ", full_path, "isn't 32 or 64 bit")
						continue

					

						

			# work_from_directory()
				# 		peName = full_path
				# 	list_of_files.append(full_path)

				# elif os.path.isdir(full_path):
				# 	print("Found Directory", full_path)
				# 	input()
			# list_of_files = os.listdir(workingDir)

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

# 	# 		m[o].rawData2 = f.read()
# 	# 		f.close()
# 	# 		# print ("m[o].rawData2", len(m[o].rawData2))
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

# 				m[o].rawData2 = f.read()
# 				f.close()
# 				# print ("m[o].rawData2", len(m[o].rawData2))
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
def clearConsole():
    command = 'clear'
    if os.name in ('nt', 'dos'):  # If Machine is running on Windows, use cls
        command = 'cls'
    os.system(command)



class foundBooleans():
	def __init__(self, name):
		self.bAnaHiddenCallsDone=False
		self.bAnaHiddenCnt=0
		self.bAnaConvertBytesDone=False
		self.bDoFindHiddenCalls=True
		self.bDoEnableComments=True
		self.bDoShowAscii=True
		self.bDoShowOffsets=True
		self.bDoshowOpcodes=True
		self.bDoFindStrings=True
		self.bShowLabels=True
		self.ignoreDisDiscovery=False
		self.bAnaFindStrDone=False
		self.bPreSysDisDone=False
		self.disAnalysisDone=False
		self.maxOpDisplay=8
		self.btsV=3     # value/option for binary to string function. #3 is default - this is just to be used so users can change how disassembly is printed.

		self.name=name
		self.bPushRetFound = False
		self.bDisassemblyFound = False
		self.bFstenvFound = False
		self.bSyscallFound = False
		self.bHeavenFound = False
		self.bPEBFound = False
		self.bCallPopFound = False
		self.bEvilImportsFound = False
		self.bModulesFound = False
		self.bWideStringFound = False
		self.bPushStringsFound = False
		self.bAsciiStrings=False
		self.bStringsFound=False
		self.bEmulationFound=False


class OSVersion:
	#Used for list of OSVersions to print for syscall
	def _init_(self, name, category, toggle, code):
		self.name = name 			#Version, e.g. SP1
		self.category = category 	#OS, e.g. Windows 10
		self.toggle = toggle 		#To print or not
		self.code = code 			#The opcode, e.g. xp1
									#^Used for selection

class MyBytes:

	def __init__(self, nameOfType, rawD, name): #, name):
		"""Initializes the data."""
		self.peName = 'peName'
		self.shellName=nameOfType
		self.name =name
		self.modName ='modName'
		self.pe = pe #pefile.PE(self.peName)
		self.data2 = 0
		self.rawData2=rawD
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
		self.md5=0
		self.sha256 = 0
		self.ssdeep = 0
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
	def setShellName(self,n):
		self.shellName=n
	def setName(self,n):
		self.name=n
	def setHashes(self):
		ssdeepHash = ssdeep.hash(self.rawData2)
		md5sum=(hashlib.md5(self.rawData2).hexdigest())
		sha256=(hashlib.sha256(self.rawData2).hexdigest())
		self.md5 = md5sum
		self.sha256=sha256
		self.ssdeep=ssdeepHash
	def setHashesPE(self):
		global peName
		print (peName)
		ssdeepHash = ssdeep.hash(open(peName,'rb').read())
		md5sum=hashlib.md5(open(peName,'rb').read()).hexdigest()
		sha256=hashlib.sha256(open(peName,'rb').read()).hexdigest()
		self.md5 = md5sum
		self.sha256=sha256
		self.ssdeep=ssdeepHash
	def getHashes(self):
		# out=mag+"Shellcode hashes\n"+res
		out+=yel+ "\tmd5: " +res +self.md5 + "\n"
		out+=yel+ "\tsha256: " +res+ self.sha256+ "\n"
		out+=yel+ "\tssdeep: "+res + self.ssdeep+ "\n"
		return (out)
	def getMd5(self):
		return self.md5 
	def getSsdeep(self):
		return self.ssdeep
	def getSha256(self):
		return self.sha256

# end classs 

class IATS:
	def __init__(self): #, name):
		"""Initializes the data."""
		self.name=""
		self.entries=[]
		self.SearchedFully = False
		self.path = []

class FoundIATs:
	def __init__(self): #, name):
		"""Initializes the data."""
		self.found=[]
		self.foundDll=[]
		self.path = []
		self.originate=[]

class shellcode:
# 	o="shellcode"
# shBody="decoded body"
# shStub="decoder stub"
# shDec="decoded shellcode (full)"
	def __init__(self, rawData=None, decodedBody=None, decoderStub=None, decodedFull=None):
		# print ("init")
		self.rawData2 = rawData  # This is current - it is variable
		self.decodedFullBody=decodedBody     #  3   the body has been decoded
		self.decoderStub=decoderStub 	 # 2    just the decoder stub
		self.decodedFull=decodedFull     # 1   fully decrypted, whole thing
		self.original=rawData # original rawdata2    #0
		# self.id = 0    # tells which one rawData2 is 
		self.decryptSuccess=False
		self.hasDecoderStub=False
		self.isEncoded = False

	def setRawData2(self, rawData):
		self.rawData2 = rawData
	def setDecodedBody(self, decodedBody):
		self.decodedFullBody=decodedBody
	def setDecoderStub(self, decoderStub):
		self.decoderStub=decoderStub
	def setDecoded(self, decodedFull):
		self.decodedFull=decodedFull
	def useDecBody(self):
		o=shBody
	def useDecStub(self):
		o=shStub
		# self.rawData2=self.useDecoderStub
	def useDecoded(self):
		o=shDec
		# self.rawData2=self.decodedFull
	def isDecrypted(self):
		return self.decryptSuccess
	def hasDecStub(self):
		return self.hasDecoderStub
	def isEncoded(self):
		return self.isEncoded
	# def id():
		# return self.id
	# def giveTypeText():
	# 	if self.id == 0:
	# 		text="Type: Original shellcode"
	# 	elif self.id == 1:
	# 		text="Type: Fully decrypted shellcode"
	# 	elif self.id == 2:
	# 		text="Type: Decoder stub"
	# 	elif self.id == 3:
	# 		text="Type: Body of Decoded shellcode"

def cBytesChange(name):
	global o 
	# o="shellcode"
	# shOrg="shellcode"
	# shBody="decoded body"
	# shStub="decoder stub"
	# shDec="decoded shellcode (full)"
	o=name
def cBytesShow():
	print("Current class:", o)
	print("Total classes:", len(o))


class shellHash:
	def __init__(self, md5=None, sha256=None, ssdeep=None):
		# print ("init")
		self.md5 = md5
		self.sha256 = sha256
		self.ssdeep = ssdeep
		self.unecryptedMd5 = None
		self.unecryptedSha256 = None
		self.unecryptedSsdeep = None
		self.decoderStubSha256 = None
		self.decoderStubMd5 = None
		self.decoderStubSsdeep = None
		self.unecryptedBodyMd5 = None
		self.unecryptedBodySha256 = None
		self.unecryptedBodySsdeep = None

	def setMd5(self, md5, mode=None):
		# print ("setMd5")
		if mode==None:
			self.md5 = md5
			# print ("self.md5", self.md5)
		elif mode==unencryptedShell:
			self.unecryptedMd5=md5
			# print ("self.unecryptedMd5", self.unecryptedMd5)
		elif mode==decoderShell:
			self.decoderStubMd5=md5
			# print ("self.decoderStubMd5", self.decoderStubMd5)
		elif mode==unencryptedBodyShell:
			self.unecryptedBodyMd5=md5
			# print ("self.unecryptedBodyMd5", self.unecryptedBodyMd5)

	def setSha256(self,sha256, mode=None):
		# print("setSha256")
		if mode==None:
			self.sha256 = sha256
			# print ("self.sha256", self.sha256)
		elif mode==unencryptedShell:
			self.unecryptedSha256=sha256
			# print ("self.unecryptedSha256", self.unecryptedSha256)
		elif mode==decoderShell:
			self.decoderStubSha256=sha256
			# print ("self.decoderStubSha256", self.decoderStubSha256)
		elif mode==unencryptedBodyShell:
			self.unecryptedBodySha256=sha256
			# print ("self.unecryptedBodySha256", self.unecryptedBodySha256)
			
	def setSsdeep(self,ssdeepHash, mode=None):
		if mode==None:
			# print("setSsdeep")
			self.ssdeep = ssdeepHash
			# print ("self.ssdeep", self.ssdeep)
		elif mode==unencryptedShell:
			self.unecryptedSsdeep=ssdeepHash
			# print ("self.unecryptedSsdeep", self.unecryptedSsdeep)
		elif mode==decoderShell:
			self.decoderStubSsdeep=ssdeepHash
			# print ("self.decoderStubSsdeep", self.decoderStubSsdeep)
		elif mode==unencryptedBodyShell:
			self.unecryptedBodySsdeep=ssdeepHash
			# print ("self.unecryptedBodySsdeep", self.unecryptedBodySsdeep)

	def show(self, mode=None):
		
		if mode==None:
			out=mag+"Shellcode hashes\n"+res
			out+=yel+ "\tmd5: " +res +self.md5 + "\n"
			out+=yel+ "\tsha256: " +res+ self.sha256+ "\n"
			out+=yel+ "\tssdeep: "+res + self.ssdeep+ "\n"
		elif mode==unencryptedBodyShell:
			out="Decoded shellcode body hashes\n"
			out+=yel+ "\tmd5: " +res+ self.unecryptedBodyMd5 + "\n"
			out+=yel+ "\tsha256: " +res+ self.unecryptedBodySha256+ "\n"
			out+=yel+ "\tssdeep: " +res+ self.unecryptedBodySsdeep+ "\n"
		elif mode==decoderShell:
			out="Shellcode decoder stub hashes\n"	
			out+=yel+ "\tmd5: " +res+ self.decoderStubMd5 + "\n"
			out+=yel+ "\tsha256: " +res +self.decoderStubSha256+ "\n"
			out+=yel+ "\tssdeep: " +res+ self.decoderStubSsdeep+ "\n"
		elif mode==unencryptedShell:
			out="Decoded shellcode (all) hashes\n"
			out+=yel+ "\tmd5: " +res+ self.unecryptedMd5 + "\n"
			out+=yel+ "\tsha256: " +res +self.unecryptedSha256+ "\n"
			out+=yel+ "\tssdeep: "+res + self.unecryptedSsdeep+ "\n"

		return out
# class DisassemblyBytes:
# 	def __init__(self): #, name):
class DisassemblyBytes:
	def __init__(self):#
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
		self.shDisassemblyLine = []
		self.shAddresses = []
		self.shMnemonic = []
		self.shOp_str = []
		self.shCodes = []
			



		# self.PreSysOffsets = []   # starting offsets of bytes - may not always be 0 or 1
		# self.PreSysValues = [] # the hex value
		# # selPreSysf.instructions =[]  # t/f - is it instructions--intinialized as instructions first
		# # selPreSysf.data =[] # t/f is data bytes
		# self.PreSysRanges=[] # does it identify ranges?
		# self.PreSysBytesType=[]
		# self.PreSysStrings=[] # TRUE if strings, false if not
		# self.PreSysStringsStart=[] #offset the strings starts @
		# self.PreSysStringsValue=[]
		# self.PreSysPushStringEnd=[]
		# self.PreSysPushStringValue=[]
		# self.PreSysBoolPushString=[]
		# self.PreSysSpecialVal=[] # align, FF
		# self.PreSysBoolspecial=[]
		# # selPreSysf.specialType=[]
		# self.PreSysSpecialStart=[]
		# self.PreSysSpecialEnd=[]
		# self.PreSysComments=[]
		self.PreSysShDisassemblyLine = []
		self.PreSysShAddresses = []
		self.PreSysShMnemonic = []
		self.PreSysShOp_str = []
		self.PreSysShCodes = []
def clearDisassemblyBytesClass():
	sBy.offsets.clear()
	sBy.values.clear()
	# sBy.instructions.clear()
	# sBy.data.clear()
	sBy.ranges.clear()
	sBy.bytesType.clear()
	sBy.strings.clear()
	sBy.stringsStart.clear()
	sBy.stringsValue.clear()
	sBy.pushStringEnd.clear()
	sBy.pushStringValue.clear()
	sBy.boolPushString.clear()
	sBy.specialVal.clear()
	sBy.boolspecial.clear()
	# sBy.specialType.clear()
	sBy.specialStart.clear()
	sBy.specialEnd.clear()
	sBy.comments.clear()


def newModule(nameOfType,rawD, name="Name"):
	global m
	global peName
	global rawHex
	global o
	global gName
	global rawHex

	show=False
	if show:
		out= (mag+"new module " + name+res )
		if rawHex:
			out+=" - shellcode -  len rawdata2: " + (str(len(rawD)))
		else:
			out+=" -pe file"


	obj = MyBytes(nameOfType,rawD,name)
	obj.setShellName(nameOfType)
	obj.setName(name)

	if rawHex:
		o=nameOfType   # shellcode - >  "shellcode", "decoded"  -- only two, not name of shellcode
		m[nameOfType]=obj
		obj.setHashes()
	else:  #pe file
		o=name    # name of the pe   #gName   -- e.g. example.dll, example.exe   -- not the full path
		m[name]=obj   #name of pe file is the key
		obj.setHashesPE()
	
	if not rawHex:
		obj.setShellName("pe")
	mL.append(obj)

	if show:
		print (out)
		print (gre+"# mods"+res, len(m))

	objBool=foundBooleans(name)
	if rawHex:
		o=nameOfType   # shellcode - >  "shellcode", "decoded"  -- only two, not name of shellcode
		mBool[nameOfType]=objBool
	else:  #pe file
		o=name    # name of the pe   #gName   -- e.g. example.dll, example.exe   -- not the full path
		mBool[name]=objBool   #name of pe file is the key

	
def newSection():
	global s
	global gName
	obj = MyBytes("pe",0,gName)
	s.append(obj)

def newIAT():
	global iatList
	obj = IATS()
	iatList.append(obj)



# if __name__ == "__main__":
# 	newModule()
# 	shellHash=shellHash()
# 	sh=shellcode()
	# IATs = FoundIATs()
	# IATs._init_()
	# sBy=DisassemblyBytes()
	# sBy._init_()








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
	global pe
	return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040)
def seh():
	global pe
	return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x0400)
def CFG():
	global pe
	return bool(pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000)

def Extraction():

	# print("Extraction")
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
	global pe
	# print("Extracting ", peName)

	modName = peName
	try:
		head, tail = os.path.split(peName)
		modName = tail
	except Exception as e:
		print(e)
		pass
	PEtemp = PE_path + "/"+ peName
	if skipPath == False:
		pe = pefile.PE(peName)
	if skipPath == True:
		pe = pefile.PE(PEtemp)
	# print("peName : ", peName, m)
	old=o
	m[o].modName=peName
	m[o].entryPoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
	m[o].VirtualAdd = pe.sections[0].VirtualAddress
	m[o].ImageBase = pe.OPTIONAL_HEADER.ImageBase
	m[o].vSize = pe.sections[0].Misc_VirtualSize
	m[o].startLoc = m[o].VirtualAdd + m[o].ImageBase
	m[o].endAddy = m[o].startLoc + m[o].vSize
	m[o].endAddy2 = m[o].startLoc + m[o].vSize
	m[o].sectionName = pe.sections[0].Name
	m[o].SizeOfRawData  =pe.sections[0].SizeOfRawData
	m[o].Hash_sha256_section=	 pe.sections[0].get_hash_md5()
	m[o].Hash_md5_section =   pe.sections[0].get_hash_sha256()
	o=old
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

	# print ("extraction end")
def findEvilImports():
	global FoundApisAddress
	for item in pe.DIRECTORY_ENTRY_IMPORT:
		# print item.dll
		for i in item.imports:
			FoundApisName.append(tuple((item.dll, i.name, hex(i.address))))
	mBool[o].bEvilImportsFound=True

def showImports(out2File=None):


	apis= []
	for dll, api, offset in FoundApisName:
		apis.append(api.decode())
	maxLen = get_max_length(apis)
	# print(maxLen)

	cat=""
	cat += "\n***************\n"
	cat += "   Imports\n"
	cat += "***************\n\n"

	catNoClr = cat
	# print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
	for dll, api, offset in FoundApisName:
		
		try:
			curLen = len(api.decode())
			# cat += yel +api.decode()  + "\t" + cya + dll.decode() + "\t"+ red + str(offset)+res + "\n"
			cat += '{}{:>{x}} {}  {}\n'.format(yel + api.decode(), "", cya + dll.decode(), red + str(offset)+res, x=5+(maxLen-curLen))
			catNoClr += '{}{:>{x}} {}  {}\n'.format(api.decode(), "", dll.decode(), str(offset), x=5+(maxLen-curLen))

		except:
			pass
	if out2File:
		return catNoClr
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
  

def cleanColors(out):
	global red 
	global gre 
	global yel 
	global blu 
	global mag 
	global cya 
	global whi 
	global res
	res = '\u001b[0m'
	out = out.replace(red, "")	
	out = out.replace(gre, "")	
	out = out.replace(yel, "")	
	out = out.replace(blu, "")	
	out = out.replace(mag, "")	
	out = out.replace(cya, "")	
	out = out.replace(whi, "")	
	out = out.replace(res, "")	
	return out

def giveLoadedModules(mode=None):
	global filename
	t=0
	out=yel+"\nLoaded Modules\n\n"+res
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
		fromStr=""
		
		if IATs.originate[t] !="":
			fromStr=yel+" from " +cya +IATs.originate[t]
		out+= (gre + x + res+ "\t" + IATs.path[t] + fromStr)+"\n"
		t+=1
	out+= (red + "\nTotal: " + res + str(len(IATs.originate)))+"\n"


	if filename == "":
		outfile = peName.split(".")[0]
		outfileName = peName
	else:	
		outfile = filename.split(".")[0]
		outfileName = filename

	if mode =="text" or mode =="save":
		# out = cleanColors(out)
		if mode =="save":
			out2 = cleanColors(out)
			txtFileName =  os.getcwd() + "\\" + outfile + "\\" + outfileName + "_" + "loaded_Modules" + ".txt"
			os.makedirs(os.path.dirname(txtFileName), exist_ok=True)
			text = open(txtFileName, "w")
			text.write(out2)
	return (out)

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
				# print ("Invalid path found for " + dll + "\nResults, thus, will be inaccurate.")
				peFound=False
				name = "Invalid path for " + dll + " " 
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
							iatList[c].entries.append(name)
					apiMSWIN = re.match( r'\bAPI-MS-WIN\b', name, re.M|re.I)
					if not apiMSWIN:			
						if name not in PE_DLLS:
							PE_DLLS.append(name)# + " " + dll)
		except Exception as e:
			# # pass
			# print(e)
			# print(traceback.format_exc())
			# input("EXCPETED")
			pass

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
	# o = 0
	
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
	# o = 0
	t=0
	# modName = peName
def extractDLLNew(dllName):
	# print ("extractDLLNew", dllName)
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

	# print ("try1")
	newpath = _win32sysloader.GetModuleFilename(dllName) or _win32sysloader.LoadModule(dllName)
	ans=newpath
	# print ("Success", ans)

	if ans==None:
		try:
			# print ("1")
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
			# print ("2")

			if h_module_base is None:
				directory = PE_path
				# print ("directory", directory)
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
							print ("\t\tNote: " + dllName + " will be excluded. Please scan this manually if needed.")
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
				# print ("4")

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
			# print (e)
			# print(traceback.format_exc())


			# print ("a1")
			
			directory = PE_path
			# print ("directory", directory)
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
	try:
		# print ("[*] Found ", dllName, " at ",  newpath)
		# print ("ans", ans,"\n")
		return ans
	except:
		print ("Error:", dllName, "was not found. ")
		return ""

def extractDLL_MinNew(dll):
	print ("NEW: extracting enter ", dll)
	global pe
	global modName
	global o
	global index
	dllName = dll
	modName = dll
	
	newModule(dll,rawData2,dll)

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
	global shellEntry
	cat=""
	# o=0
	dprint2 ("# m: " + str(len(m)))
	for o in m:
		if rawHex:
			try:
				cat+=gre+"Shellcode Entry point: " + res+str(hex(shellEntry)) +"\n"
			except:
				cat+=gre+"Shellcode Entry point: " + res+str(shellEntry) +"\n"


		else:
			cat +=m[o].modName.decode()+"\n"
			cat +gre+"Section: "+ res + str(m[0].sectionName) +"\n"
			cat+=gre+"Entry point: "+ res + str(hex(m[o].entryPoint)) +"\n"
			cat+=gre+"Virtual Address: " + res+ str(hex(m[o].VirtualAdd))+"\n"
			cat+=gre+"ImageBase: "+ res + str(hex(m[o].ImageBase))+"\n"
			cat+=gre+"VirtualSize: " + res+ str(hex(m[o].vSize))+"\n"
			cat+=gre+"Size of section: " + res+ str(hex(m[o].data2))+"\n"
			cat+=gre+ "DEP: " + res+ str(m[o].depStatus)+"\n"
			cat+=gre+"ASLR: " + res+ str(m[o].aslrStatus)+"\n"
			cat+=gre+"SEH: "+ res + str(m[o].sehSTATUS)+"\n"
			cat+=gre+"CFG: "+ res + str(m[o].CFGstatus)+"\n"
			cat+="\n"
			cat+=""
	# 	o+=1
	# o=0
	return cat

def showBasicInfoSections():
	global gName
	dprint2("showBasicInfoSections")
	cat=""
	t=0
	# dprint2 ("# s: " + str(len(s)))
	cat += mag+(gName)+"\n"
	cat += gre+"Md5: "+res+str(m[o].getMd5())+"\n"
	cat += gre+"Sha256: "+res+str(m[o].getSha256())+"\n"
	cat += gre+"Ssdeep: "+res+str(m[o].getSsdeep())+"\n\n"

	cat += '\nSection info\n\n'
	for each in s:	
		cat +="Section:"+yel+s[t].sectionName.decode()+res+"\n"
		# cat +="Section: " + str(m[0].sectionName) +"\n"
		cat+=gre+"Entry point: "+res + str(hex(s[t].entryPoint)) +"\n"
		cat+=gre+"Virtual Address: "+res + str(hex(s[t].VirtualAdd))+"\n"
		cat+=gre+"ImageBase: " +res+ str(hex(s[t].ImageBase))+"\n"
		cat+=gre+"VirtualSize: "+res + str(hex(s[t].vSize))+"\n"
		cat +=gre+"SizeOfRawData: " +res+ str(hex(s[t].SizeOfRawData)) +"\n"
		cat +=gre+"VirtualAddress: " +res+ str(hex(s[t].VirtualAdd)) +"\n"
		cat +=gre+"ImageBase + sec. virtual address: " +res+ str(hex(s[t].startLoc)) +"\n"
		cat+=gre+"Actual size of section: " +res+ str(hex(len(s[t].data2)))+"\n"
		cat+=gre+ "DEP: " +res+ str(s[t].depStatus)+"\n"
		cat+=gre+"ASLR: " +res+ str(s[t].aslrStatus)+"\n"
		cat+=gre+"SEH: " +res+ str(s[t].sehSTATUS)+"\n"
		cat+=gre+"CFG: " +res+ str(s[t].CFGstatus)+"\n"

		cat+=gre+"Sha256: "+res+s[t].Hash_sha256_section+"\n"
		cat+=gre+"md5: "+res+s[t].Hash_md5_section+"\n"
		cat+="\n"
		cat+=""
		t+=1
	t=0
	return cat
	
def show1(int):
		show = "{0:02x}".format(int) #
		return show

def me(mode=None):
	print (sys._getframe().f_lineno)
	if mode==1:
		input()

def toString(input1):

	result=""
	zz=""
	for y in input1:
		zz= "{0:02x}".format(y) #
		if ((y > 31) & (y < 127)):
			try: 
				zz=int(zz,16)
				zz = chr(zz)
			except:
				zz="."
		else:
			zz="."
		result+=zz
	return result


def binaryToStr(binary, mode = None):
	newop=""
	

	try:
		if mode ==None or mode ==1:
			for v in binary:
				newop += "\\x"+"{0:02x}".format(v) #   e.g \\xab\\xac\\xad\\xae
			return newop
		elif mode==2:
			for v in binary:
				newop += "{0:02x}".format(v)		#   e.g abacadae
				# print ("newop",newop)
			return newop
		elif mode==3:
			for v in binary:
				newop += "{0:02x} ".format(v)    #   e.g ab ac ad ae
				# print ("newop",newop)
				


			return newop
	except Exception as e:
		print ("*Not valid format")
		print(e)


def Text2Json(shell, jsonOut=None):
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

	# print(shellcode_dict)
	if jsonOut != None:
		return shellcode_dict
	fileName = "rawhex" + "_" + inputFile + "_" + filetime + ".json"
	outDir = os.getcwd() + "\\outputs\\" 
	fullPath = outDir + fileName
	os.makedirs(os.path.dirname(outDir), exist_ok=True)

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
			# print (strLitwColor)
			# print (rawHwColor)
			# print (arrayLitwColor)
			pass
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
			dprint2 (address, NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, (loadModList_offset, listEntryText	), advanceDLL_Offset)
			return address , NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, (loadModList_offset, listEntryText	), advanceDLL_Offset
		# print("SAVING PEB SEQUENCE: PEBPOINTS = ", pebPoints, "FOUND ", points, " POINTS")
		# print(disString)
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
			modSecName = "rawHex"
			m[o].save_PEB_info.append(tuple((address,NumOpsDis,modSecName,secNum,points)))
# print ("#############################################################################")


def printSavedPEB(): ######################## AUSTIN ###############################3
	#formatting
	#global m[o].rawData2

	dprint2 ("printSavedPEB", len(m[o].rawData2))
	dprint2 ("m[o].save_PEB_info", len(m[o].save_PEB_info))
	dprint2 ("rawhex", rawHex)
	j = 0


	if(rawHex):
		for item in m[o].save_PEB_info:
			# print("-----------------> ",item)

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

			print("PEB WALKING START = " + mag +str(hex(item[0])) + res)
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

			CODED2 = m[o].rawData2[address:(address+NumOpsDis)]

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

			CODED2 = m[o].rawData2[address:(address+NumOpsDis)]

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
			# print("Number of instructions --> ", int(retOffset, 16) - int(pushOffset, 16))
			# NumOpsDis = (int(retOffset, 16) - int(pushOffset, 16) +1 )
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
	# print ("PushRetrawhex", len(data))
	global bit32
	
	global linesForward
	address = hex(address)
	# linesGoBack = 10
	linesGoBack = linesBack
	# print("Lines Forward", linesForward)
	t = 0
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, 0x0, linesGoBack, "PushRetrawhex")  # arg: starting offset/entry point - leave 0 generally
	
	# print("------------>", orgListOffset,orgListDisassembly)
	# input()
	if(mBool[o].ignoreDisDiscovery):
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
					# print (item)
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
		print ("PushRetrawhex false" )
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
	
	global linesForward
	address = hex(address)
	linesGoBack = 10
	t = 0
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, 0x0, linesGoBack, "PushRetrawhex2")  # arg: starting offset/entry point - leave 0 generally
	# print("------------>", orgListOffset,orgListDisassembly)
	# input()
	if(mBool[o].ignoreDisDiscovery):
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

			# CODED2 = m[o].rawData2[address:(address+NumOpsDis)]
			CODED2 = m[o].rawData2[address:(printEnd)]

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
					add3 = hex (int(i.address + section.startLoc))
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
				printEnd = int(retOffset, 16) +3 - section.VirtualAdd
				# printEnd = int(retOffset, 16) + section.ImageBase
				# CODED2 = section.data2[address:(address+NumOpsDis)+2]
				# printEnd = int(retOffset, 16) - section.VirtualAdd
				CODED2 = section.data2[address:printEnd]
				# CODED2 = section.data2[address:int(retOffset, 16)]
				# print("Address: ", hex(address), "printEnd ", hex(printEnd), hex(int(retOffset, 16)))

				CODED3 = CODED2
				stopRet = False
				# print("pushret print function", CODED3.hex())
				for i in callCS.disasm(CODED3, address):
					add = hex(int(i.address))
					addb = hex(int(i.address +  section.VirtualAdd))
					add2 = str(add)
					add3 = hex (int(i.address + section.startLoc))
					add4 = str(add3)
					val = formatPrint(i, add4, addb, pe=True)

					# val =  i.mnemonic + " " + i.op_str + "\t\t\t\t"  + add4 + " (offset " + addb + ")"
					val2.append(val)
					val3.append(add2)
					# val5.append(val)
					if(addb == retOffset):
						val5.append(val)
						break
					else:

						val5.append(val)
					# checkRet= re.search( retOffset, val, re.M|re.I)
					# # if "ret" in val:
					# # 	val5.append(val)
					# # 	break
					# # else:
					# # 	val5.append(val)

					# if checkRet:
					# 	if not stopRet:
					# 		val5.append(val)
					# 		stopRet = True
					# 	else:
					# 		pass
					# if not stopRet:
					# 	val5.append(val)
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
	
	global linesBack
	# linesBack = 10
	linesBack = linesBack2
	# print("Lines Back --> ", linesBack)
	address = int(address)
	linesGoBack = 10

	t = 0
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, 0x0, linesGoBack,"FSTENVrawhex")
	# truth = False
	# print("done")
	# t = 0
	# for line in orgListDisassembly:
	# 	dprint2(hex(orgListOffset[t]), "   ", orgListDisassembly[t])
	# 	t+=1
	if(mBool[o].ignoreDisDiscovery):
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
		print ("fstenv false")
		for match in FSTENV_GET_BASE.values(): #iterate through all opcodes representing combinations of registers
			get_FSTENV(10, 15, match, secNum, data)

	# print ("o", o)
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

			# CODED2 = m[o].rawData2[(address-NumOpsBack):(address+NumOpsDis)]
			CODED2 = m[o].rawData2[int(FPU_offset, 16):(int(printEnd, 16))]
			# CODED2 = m[o].rawData2[(address - NumOpsBack):(int(printEnd, 16))]
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
	
	global maxDistance
	global linesForward

	global debugging

	# debugging = True
	address = int(address)
	linesGoBack = 10
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(address, 0x0, linesGoBack)

	print("##################DISASM HERE####################")
	for e in orgListDisassembly:
		print(e)
	print("##################DISASM HERE####################")



	if(mBool[o].ignoreDisDiscovery):
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
								# print ("got bad: ", item)
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
	
	global maxDistance
	global linesForward

	global debugging

	# debugging = True
	address = int(address)
	linesGoBack = 10
	truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(address, 0x0, linesGoBack, "callPopRawHex")
	if(mBool[o].ignoreDisDiscovery):
		truth = False

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
		print ("callpop false")
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
			CODED2 = m[o].rawData2[(origAddr):(address+NumOpsDis	)]

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
				print ("got one syscall", line)

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
				print ("saveBaseEgg",address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, eax, c0_offset )
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
		truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(addressInt, 0x0, linesGoBack, "getSyscallRawHex")  # arg: starting offset/entry point - leave 0 generally
		if(mBool[o].ignoreDisDiscovery):
			truth = False

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

			# clearTempDis()
			# print ("\n\n\n")
		if(not truth):
			print ("syscall fail")
			findAllSyscall(m[o].rawData2, "noSec")
		# if(rawHex):
		# 	m[o].save_Egg_info = helperListToSet(m[o].save_Egg_info)
		# else:
		# 	s[secNum].save_Egg_info =helperListToSet(s[secNum].save_Egg_info)

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

def print_from_directory(fName, arch=None):

	dirName = '\\'.join(fName.split("\\")[:-1])
	fileName = fName.split("\\")[-1]
	output = "******************************\n"
	output += yel + "\nFile      : " + gre + fileName + res + "\n"

	if arch:
		output += yel + "Arch      : " + gre + str(arch) + "-bit"+res + "\n"

	output += yel + "Directory : " + gre + dirName + res + "\n\n"
	output += "******************************\n\n"	

	return output




def parse32Shellcode():
	global filename
	global rawHex
	global rawBin
	global bit32
	global shellBit
	global rawData2
	global known_arch

	known_arch = True

	for i in list_of_files32:
		# print("list_of_files32 ", rawHex)
		tmpName = os.path.basename(i)
		# print("Processing ", i)
		output = print_from_directory(i, 32)
		print(output)
		filename = i
		if i[-3:] == "txt":
			# newModule()
			rawHex = True
			rawBin = False
			bit32 = True
			shellBit = 32

			init2(filename)
			newModule(o, rawData2, tmpName)
		elif i[-3:] == "bin":
			
			rawHex = True
			rawBin = True
			bit32 = True
			shellBit = 32
			f = open(i, "rb")

			rawData2 = f.read()
			newModule(o, rawData2, tmpName)
			f.close()
		startupPrint()
		clearAll()

def parse64Shellcode():
	global filename
	global rawHex
	global rawBin
	global bit32
	global shellBit
	global rawData2
	global known_arch

	known_arch = True


	for i in list_of_files64:
		# print("Processing ", i)
		tmpName = os.path.basename(i)

		output = print_from_directory(i, 64)
		print(output)
		filename = i
		# print("list_of_files64 ", rawHex)
			# newModule()
			# Extraction()
			# newModule()

		if i[-3:] == "txt":
			# newModule(o, rawData2)
			# Extraction()
			rawHex = True
			bit32 = False
			rawBin = False
			shellBit = 64
			init2(filename)
			newModule(o, rawData2, tmpName)

		elif i[-3:] == "bin":
			rawHex = True
			rawBin = True
			shellBit = 64
			bit32 = False
			# peName = i
			f = open(i, "rb")
			readRawData2 = f.read()
			newModule(o, readRawData2, tmpName)
			# print("Length of m[o].rawData2", len(m[o].rawData2))
			f.close()
		startupPrint()
		clearAll()

def parse32PE():
	global peName
	global filename
	global rawHex
	global rawBin
	global shellBit
	global bit32
	global known_arch

	known_arch = True

	for i in list_of_pe32:
			# print("Processing ", i)
		tmpName = os.path.basename(i)
		peName = i
		filename = i
		rawHex = False
		rawBin = False
		shellBit = 32
		# print(" PE 32 --> ", rawHex)
		newModule(i, 0, tmpName)

		Extraction()
		output = print_from_directory(i, 32)
		print(output)
		bit32 = True
		init2(i)

		startupPrint()

		clearAll()



def parse64PE():
	global peName
	global filename
	global rawHex
	global rawBin
	global shellBit
	global bit32
	global known_arch

	# print("############", list_of_pe64)
	known_arch = True
	for i in list_of_pe64:
		# print("Processing ", i)
		peName = i
		tmpName = os.path.basename(i)

		filename = i
		rawHex = False
		# print(" PE 64 --> ", rawHex)

		rawBin = False
		# newSection()
		newModule(i, 0, tmpName)
		Extraction()
		output = print_from_directory(i, 64)
		print(output)
		bit32 = False
		shellBit = 64
		init2(i)
		# print("64 file ", i)
		startupPrint()
		clearAll()
		# print("Cleared <,--")


def parseUnkownArch():

	global bit32
	global shellBit
	global rawHex
	global rawBin
	global filename
	global rawData2
	global current_arch
	global known_arch


	# print("parse Unknown")

	known_arch = False
	for i in list_of_unk_files:
		count = 0
		tmpName = os.path.basename(i)
		while count < 2:
			if count == 0:
				output = print_from_directory(i, 32)
			elif count == 1:
				output = print_from_directory(i, 64)

			print(output)
			filename = i
			if count == 0:
				current_arch = 32
			else:
				current_arch = 64

			if i[-3:] == "txt":
				if count == 0:
					bit32 = True
					shellBit = 32
				elif count == 1:
					bit32 = False
					shellBit = 64
				# newModule()
				rawHex = True
				rawBin = False
				

				init2(filename)
				newModule(o, rawData2, tmpName)
			elif i[-3:] == "bin":
				
				rawHex = True
				rawBin = True
				if count == 0:
					bit32 = True
					shellBit = 32
				elif count == 1:
					bit32 = False
					shellBit = 64

				f = open(i, "rb")

				rawData2 = f.read()
				# print("gName -----> ", gName)
				newModule(o, rawData2, tmpName)
				f.close()
			startupPrint()
			clearAll()

			count += 1

def work_from_directory():
	global filename
	global rawHex
	global rawBin
	global peName
	global rawData2
	global shellBit
	global bit32

	clearAll()

	readConf()

	if list_of_files32:
		parse32Shellcode()

		# for i in list_of_files32:
		# 	# print("list_of_files32 ", rawHex)

		# 	# print("Processing ", i)
		# 	output = print_from_directory(i)
		# 	print(output)
		# 	filename = i
		# 	if i[-3:] == "txt":
		# 		# newModule()
		# 		rawHex = True
		# 		rawBin = False
		# 		bit32 = True
		# 		shellBit = 32

		# 		init2(filename)
		# 	elif i[-3:] == "bin":
				
		# 		rawHex = True
		# 		rawBin = True
		# 		bit32 = True
		# 		shellBit = 32
		# 		f = open(i, "rb")

		# 		rawData2 = f.read()
		# 		newModule(o, rawData2)
		# 		f.close()
		# 	startupPrint()
		# 	clearAll()


	if list_of_files64:

		parse64Shellcode()
		# for i in list_of_files64:
		# 	# print("Processing ", i)

		# 	output = print_from_directory(i)
		# 	print(output)
		# 	filename = i
		# 	# print("list_of_files64 ", rawHex)
		# 		# newModule()
		# 		# Extraction()
		# 		# newModule()

		# 	if i[-3:] == "txt":
		# 		# newModule(o, rawData2)
		# 		# Extraction()
		# 		rawHex = True
		# 		bit32 = False
		# 		rawBin = False
		# 		shellBit = 64
		# 		init2(filename)
		# 	elif i[-3:] == "bin":
		# 		rawHex = True
		# 		rawBin = True
		# 		shellBit = 64
		# 		bit32 = False
		# 		# peName = i
		# 		f = open(i, "rb")
		# 		readRawData2 = f.read()
		# 		newModule(o, readRawData2)
		# 		# print("Length of m[o].rawData2", len(m[o].rawData2))
		# 		f.close()
		# 	startupPrint()
		# 	clearAll()

	if list_of_pe32:

		parse32PE()

		# for i in list_of_pe32:
		# 	# print("Processing ", i)

		# 	peName = i
		# 	filename = i
		# 	rawHex = False
		# 	rawBin = False
		# 	shellBit = 32
		# 	# print(" PE 32 --> ", rawHex)

		# 	newModule(i, 0)
		# 	Extraction()
		# 	output = print_from_directory(i)
		# 	print(output)
		# 	bit32 = True
		# 	init2(i)
		# 	startupPrint()
		# 	clearAll()


	if len(list_of_pe64) > 0:

		parse64PE()

		# for i in list_of_pe64:
		# 	# print("Processing ", i)

		# 	peName = i
		# 	filename = i
		# 	rawHex = False
		# 	# print(" PE 64 --> ", rawHex)

		# 	rawBin = False
		# 	newModule(i, 0)
		# 	Extraction()
		# 	output = print_from_directory(i)
		# 	print(output)
		# 	bit32 = False
		# 	shellBit = 64
		# 	init2(i)
		# 	startupPrint()
		# 	clearAll()


	if list_of_unk_files:
		parseUnkownArch()
			# print("S: ---> ", len(s))
			# for sec in s:
			# 	print("Length ", len(sec.Strings))
			# 	print("Length ", len(sec.wideStrings))
			# 	print("Length ", len(sec.pushStrings))


	# for i in list_of_files:
	# 	dirName = '\\'.join(i.split("\\")[:-1])
	# 	fileName = i.split("\\")[-1]
	# 	output = "******************************\n"
	# 	output += yel + "\nFile      : " + gre + fileName +res + "\n"
	# 	output += yel + "Directory : " + gre + dirName + res + "\n\n"
	# 	output += "******************************\n\n"
	# 	print(output)
	# 	# print("******************************"  + yel + "\nFile: " + gre + i +res + "\n******************************")

	# 	if os.path.isfile(i):
	# 		if i[-3:] == "txt":
	# 			newModule()
	# 			# Extraction()
	# 			rawHex = True
	# 		elif i[-3:] == "exe":
	# 			peName = i
	# 			rawHex = False

	# 		else:
	# 			newModule()

	# 			rawHex = True
	# 			rawBin = True
	# 			# peName = i
	# 			f = open(i, "rb")
	# 			rawData2 = f.read()
	# 			# print("Length of rawData2", len(rawData2))
	# 			f.close()
	# 		filename = i
	# 		# print(filename)
	# 		# input()
	# 		# print("O Before ", m)

	# 		init2(filename)
	# 		startupPrint()
	# 		# print("peb: ", mBool[o].bPEBFound)

	# 		clearAll()


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

			# clearTempDis()
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

				print (destLocation, "destLocation", type(destLocation))

				try:
					destRegex = "push " + destLocation  #this one was the one giving the error
				except:
					destRegex = "push " + str(destLocation)

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
				try:
					saveBaseHeaven(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, offset, "retf", destLocation = destLocation, pushOffset = int(pushOffset, 0))
				except:
					saveBaseHeaven(address, NumOpsDis, (NumOpsBack - back), modSecName, secNum, offset, "retf", destLocation = destLocation, pushOffset = pushOffset)

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
		truth, tl1, tl2, orgListOffset,orgListDisassembly = preSyscalDiscovery(0, 0x0, linesGoBack, "getHeavenRawHex")  # arg: starting offset/entry point - leave 0 generally
		if(mBool[o].ignoreDisDiscovery):
			truth = False

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

		else:
			print ("heaven's gate false")

			findAllHeaven(m[o].rawData2, "noSec")
			# clearTempDis()

		# if(rawHex):
		# 	m[o].save_Heaven_info = helperListToSet(m[o].save_Heaven_info)
		# else:
		# 	s[secNum].save_Heaven_info =helperListToSet(s[secNum].save_Heaven_info)
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

def cleanOutput(data):

	data = data.replace("\t", "")

	allInstr = data.split(" ")
	# print("Everything ---> ", allInstr)
	mnemonic = allInstr[0]
	add4 = allInstr[-3]
	addb = allInstr[-2:]
	op_str = ' '.join(allInstr[1:-3])
	return mnemonic, op_str, add4, addb

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

			# converted = [string.replace("\t", "") for string in converted]

			for line in converted:
				if line != "":
					mnemonic, op_str, add4, addb = cleanOutput(line)
					convOut = formatPrint(mnemonic + "|" + op_str, add4, addb, syscall=True)

					print(gre + convOut + res)
					# allInstr = line.split(" ")
					# # print("Everything ---> ", allInstr)
					# mnemonic = allInstr[0]
					# add4 = allInstr[-3]
					# addb = allInstr[-2:]
					# op_str = ' '.join(allInstr[1:-3])

					# print("----> mnemonic" , mnemonic, type(mnemonic))
					# print("-----> op_str", op_str, type(op_str))
					# input()
					
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



def printSavedSyscall(bit = 32, showDisassembly = True): ######################## AUSTIN ###############################3
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
					if line != "":
						# print("Line --> ", line)
						# input()
						mnemonic, op_str, add4, addb = cleanOutput(line)
						convOut = formatPrint(mnemonic + "|" + op_str, add4, addb, syscall=True)
						print(gre + convOut + res)

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
			get_FSTENV(10, 15, match, "noSec", m[o].rawData2) 


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
	# print("Data2 --> ",type(data2))
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
	# print ("findAllPebSequences", mode, binaryToStr(m[o].rawData2),)
	if(rawHex):
		# print("in check")

		if shellBit == 32:
			for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
				# ans=get_PEB_walk_start(mode, 19, match, "noSec", data2) #19 hardcoded for now, seems like good value for peb walking sequence
				ans=get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
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
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_ADC.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_OR.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_XOR.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_XCHG.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
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
	# print ("findAllPebSequences", mode, binaryToStr(m[o].rawData2),)
	if(rawHex):
		# print("in check")

		if shellBit == 32:
			for match in PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
				# ans=get_PEB_walk_start(mode, 19, match, "noSec", data2) #19 hardcoded for now, seems like good value for peb walking sequence
				ans=get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
				# print ("ans", ans)

				if mode=="decrypt" and ans is not None:
					print ("good, get peb walk")
					print (ans)
					return (ans)
		else:
			for match in PEB_WALK_MOV_64.values():
				get_PEB_walk_start_64(28, match, "noSec", m[o].rawData2)

		# for match in PEB_WALK_ADD.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_ADC.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_OR.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_XOR.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
		# for match in PEB_WALK_XCHG.values(): #iterate through all opcodes representing combinations of registers
		# 	get_PEB_walk_start(mode, 19, match, "noSec", m[o].rawData2) #19 hardcoded for now, seems like good value for peb walking sequence
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
	if rawHex:
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
			get_PushRet_start(4, match, "noSec", m[o].rawData2)

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
												#wordSize=int(len(word)/2)  # MESSES UP DISASSEMBLY PRNITING
												wordSize=int(len(word))

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
								# wordSize=int(len(word)/2)  # MESSES UP DISASSEMBLY PRNITING
								wordSize=int(len(word))

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
						UsesPusByte=False
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
											UsesPusByte=True
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
						if UsesPusByte:
							finalWord=stripWhite(finalWord)
							finalWord=finalWord[ :  :-1]
							word4+=finalWord+"*"
							UsesPusByte=False
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
	# o = 0
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
		findAllCallpop(m[o].rawData2, 'noSec')

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
	# 		getSyscallPE(20, 20, match, 'noSec', m[o].rawData2) 

	if(rawHex):
		getSyscallRawHex(0, 8, 'noSec', m[o].rawData2)
		getHeavenRawHex(0, 8, 'noSec', m[o].rawData2)

	printSavedSyscall()
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
		data2 = m[o].rawData2

		if(doPeb):
			findAllPebSequences_old(data2, "noSec")
		if(doCallpop):
			findAllCallpop(data2, "noSec")
		if(doPushret):
			findAllPushRet(data2, "noSec")
		if(doFstenv):
			findAllFSTENV(data2, "noSec")
		if(doSyscall):
			getSyscallRawHex(0, 8, 'noSec', m[o].rawData2)
		if(doHeaven):
			getHeavenRawHex(0, 8, 'noSec', m[o].rawData2)
	


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
	printSavedSyscall()
	print("######################## HEAVEN ########################")
	printSavedHeaven()



def AustinTesting2():

	start = timeit.default_timer()
	print("before austinEncode")


	if rawBin == False:
		# filename=shellArg

		rawBytes=readShellcode("daltonShell2.txt") 

		m[o].rawData2=rawBytes
		# print("read dalton, data here: ", m[o].rawData2)
		# printBytes(rawBytes)
		# print (disHereShell(rawBytes, False, False, "ascii", True))


	


	# print ("Sizem[o].rawData2", len(m[o].rawData2))
	rawBytes=m[o].rawData2
	# print("NORMAL BYTES")
	# print(binaryToStr(rawBytes))
	# print ("rawbytes class", type(rawBytes))
	# print("m[o].rawData2 BEFORE ENCODE IN TEST FUNC: ", m[o].rawData2)
	encoded=encodeShellcode(m[o].rawData2)
	# print("encoded dalton, data here: ", encoded)




	# austinEncodeDecodeWork("daltonShell2.txt", ["^", "^", "-", "+", "^"])
	# austinEncodeDecodeWork("daltonShell2.txt", ["^", "^", "-", "+"])
	# austinEncodeDecodeWork("daltonShell2.txt", ["^", "^", "-"])

	decryptShellcode(encoded, ["^", "^", "-"], distributed = False, findAll = False, cpuCount = 32, fastMode = False, outputFile = True,)
	stop = timeit.default_timer()
	print("Total time AUSTIN: " + str(stop - start))
	# rawBytes=readShellcode(shellArg) 

	# m[o].rawData2=rawBytes
	# # # printBytes(rawBytes)
	# print (disHereShell(rawBytes, False, False, "ascii", True))
	# print ("Sizem[o].rawData2", len(m[o].rawData2))
	# rawBytes=m[o].rawData2
	# print ("rawbytes class", type(rawBytes))

	# disassembly, disassemblyNoC, assemblyBytes=takeBytes(data2,(len(data2)-10))
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



def goodString(data,word, size):
	global stringsDeeper
	global stringReadability
	global GoodStrings
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

	if wordSize < size: 
		if word.lower() in GoodStrings:
			return True
	 

		# for each in GoodStrings:	### maybe too computationally expensive if long list??
		# 	if each.lower() in word.lower():
		# 		return True

	return False

  
def goodStringWide(data,word, size):   #deprecate d- use other goodstrings
	global stringsDeeper
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
# shellcode='shellcode.txt'
shellcode2='shellcode2.txt'
shellcode3='shellcode3.txt'
shellcode4='shellcode4.txt'
shellcode5='shellcode5.txt'
shellcode6='shellcode6.txt'
shellcode7='shellcode7.txt'
shellcode8="shellcode8.txt"


def show1(int1):
	show = "{0:02x}".format(int1) #
	return show

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

def checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, off_PossibleBad,data, num_bytes):
	# print ("checkForValidAddress2")
	# val_b=checkForValidAddress(val_a,val_b1, val_b2, sizeShell, off_PossibleBad)
	val_b=val_b1+ " " +  val_b2 
	try:
		if str(val_b2) in off_PossibleBad:
			# dprint2 ("oh noes "  + val_b2)
			# dprint2(val_a, val_b1, val_b2)
			# res=specialDisDB(data, int(val_a,16))
			# val_b=res
			addy=int(val_a,16)
			modifysByRange(data, addy,addy+num_bytes,"d","checkForValidAddress2")
			# val_b =  val_b+ " (??)"
			
			# dprint2 ("check2: valb: "  + val_b + " " + str(num_bytes) )
			
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
		val_b, num_bytes =checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, off_PossibleBad,data,num_bytes)
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


def addEntryPoint():
	dprint("addEntryPoint")
	
	
	
	
	

	index=sBy.shAddresses.index(str(hex(shellEntry)))

	dprint2 (index, sBy.shDisassemblyLine[index], sBy.shAddresses[index])
	dprint(sBy.shDisassemblyLine[index])
	# old= sBy.shDisassemblyLine[index]
	# sBy.shDisassemblyLine[index] =  "*.0x"+str(shellEntry) + "" + old +"12345678910" + "AHAHAHAHAHAHA" 

	old= sBy.shDisassemblyLine[index-1]
	sBy.shDisassemblyLine[index-1] =  old = "\t\t[*]Shellcode Entrypoint:" 
	dprint(sBy.shDisassemblyLine[index-1])
	dprint("done")
def addDis(address, line=None, mnemonic=None, op_str=None, id2="NA"):
	# print("      [*] addDis id", id2, hex(address), "line", line, "mnemonic", mnemonic, op_str)
	# print (type(address), "address type")
	# print (mnemonic, op_str, id2, "\n")

	sBy.shDisassemblyLine.append(line)
	sBy.shAddresses.append(address)
	sBy.shCodes.append(id2)
	sBy.shMnemonic.append(mnemonic)
	sBy.shOp_str.append(op_str)

def printTempDis():
	global off_Label
	global labels
	
	
	t=0
	out=""
	for each in sBy.shDisassemblyLine:
		truth,res=checkForLabel((sBy.shAddresses[t]),labels)
		if truth:
			each="\t"+res+each
		controlFlow= re.search( r'\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bja\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bret\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', each, re.M|re.I)
		if controlFlow:
			print ("cfi")
			each=each+"\n"
		out+=each+"\n"

		t+=1
	print (out)

def createDisassemblyLists(Colors=True, caller=None):
	# print ("createDisassemblyLists")
	global off_Label
	global labels
	global res
	
	maxOpDisplay=mBool[o].maxOpDisplay

	btsV=mBool[o].btsV
	
	showOpcodes = mBool[o].bDoshowOpcodes
	showLabels = mBool[o].bShowLabels
	if caller=="final" and mBool[o].bDoEnableComments:
		addComments()

	mode="ascii"
	if not mBool[o].bDoShowOffsets:
		mode="NoOffsets"
	j=0
	nada=""
	finalOutput="\n"
	myStrOut=""
	myHex=""

	# print ("By.pushStringEnd")
	# new=[]
	# for each in  sBy.pushStringEnd:
	# 	each =hex(each)
	# 	new.append(each)
	# print (new)

	for cAddress in sBy.shAddresses:
		pAddress= gre+str(hex(cAddress))+res2  #print address
		startHex=cAddress
		try:
			endHex=sBy.shAddresses[j+1]
		except:
			endHex=len(m[o].rawData2)
		sizeDisplay=endHex-startHex
		if mode=="ascii":
			try:
				if sizeDisplay > maxOpDisplay:
					myHex=red+binaryToStr(m[o].rawData2[startHex:startHex+maxOpDisplay],btsV)+"..."+res2+""
					myStrOut=cya+" "+toString(m[o].rawData2[startHex:endHex])+res2+""
				else:
					myHex=red+binaryToStr(m[o].rawData2[startHex:endHex],btsV)+res2+""
					if mBool[o].bDoShowAscii:
						myStrOut=cya+" "+toString(m[o].rawData2[startHex:endHex])+res2+""
					else:
						myStrOut=""
			except Exception as e:
				print ("ERROR: ", e)


			if not showOpcodes:	 # If no hex, then move ASCII to left
				myHex=myStrOut
				myStrOut=""
			out='{:<12s} {:<45s} {:<33s}{:<10s}\n'.format(pAddress, whi+sBy.shMnemonic[j] + " " + sBy.shOp_str[j], myHex,myStrOut )
			if re.search( r'align|db 0xff x', sBy.shMnemonic[j], re.M|re.I):
				myHex=red+binaryToStr(m[o].rawData2[startHex:startHex+4],btsV)+"..."+res2+""
				if mBool[o].bDoShowAscii:
					myStrOut=cya+" "+toString(m[o].rawData2[startHex:startHex+4])+"..."+res2+""
				else:
					myStrOut=""

				if not showOpcodes:   # If no hex, then move ASCII to left
					myHex=myStrOut
					myStrOut=""
				out='{:<12s} {:<45s} {:<33s}{:<10s}\n'.format(pAddress, whi+sBy.shMnemonic[j] + " " + sBy.shOp_str[j], myHex, myStrOut)
				pass

			# out=out+"\n"
		elif mode=="NoOffsets":
			try:
				if sizeDisplay > maxOpDisplay:
					myHex=red+binaryToStr(m[o].rawData2[startHex:startHex+maxOpDisplay],btsV)+"..."+res2+""
					myStrOut=cya+" "+toString(m[o].rawData2[startHex:endHex])+res2+""
				else:
					myHex=red+binaryToStr(m[o].rawData2[startHex:endHex],btsV)+res2+""
					if mBool[o].bDoShowAscii:
						myStrOut=cya+" "+toString(m[o].rawData2[startHex:endHex])+res2+""
					else:
						myStrOut=""
			except Exception as e:
				print ("Error:",e)

			if not showOpcodes: # If no hex, then move ASCII to left
				myHex=myStrOut
				myStrOut=""
			out='   {:<45s} {:<33s}{:<10s}\n'.format(whi+sBy.shMnemonic[j] + " " + sBy.shOp_str[j], myHex,myStrOut )
			if re.search( r'align|db 0xff x', sBy.shMnemonic[j], re.M|re.I):
				myHex=red+binaryToStr(m[o].rawData2[startHex:startHex+4],btsV)+"..."+res2+""
				if mBool[o].bDoShowAscii:
					myStrOut=cya+" "+toString(m[o].rawData2[startHex:startHex+4])+"..."+res2+""
				else:
					myStrOut=""

				if not showOpcodes: # If no hex, then move ASCII to left
					myHex=myStrOut
					myStrOut=""
				out='   {:<45s} {:<33s}{:<10s}\n'.format(pAddress, whi+sBy.shMnemonic[j] + " " + sBy.shOp_str[j], myHex, myStrOut)
				pass
		else:	
			out=('{:<12s} {:<35s}\n'.format(pAddress, sBy.shMnemonic[j] + " " + sBy.shOp_str[j]))

		if mBool[o].bDoEnableComments:
			if sBy.comments[cAddress] !="":
				val_b2=sBy.comments[cAddress]
				val_comment =('{:<10s} {:<45s} {:<33s}{:<10s}\n'.format(mag+nada, val_b2, nada, nada))
				out+=val_comment		
		
		if showLabels:
			truth,myLabel=checkForLabel( str(hex(cAddress)),labels)
			if truth:
				out=yel+myLabel+res2+out
		if re.search( r'\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bja\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bret\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', sBy.shMnemonic[j], re.M|re.I):
			out=out+"\n"



		# valCheck=i.mnemonic + " " + i.op_str 
		# controlFlow= re.match( r'\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bja\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bret\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', valCheck, re.M|re.I)
		# if controlFlow:
		# 	val=val+"\n"	
		############Stack strings begin
		try:
			cur=cAddress
			if (sBy.pushStringEnd[cur]-2) == cur:
				msg="; "+sBy.pushStringValue[cur] + " - Stack string"
				newVal =('{:<12} {:<45s} {:<33}{:<10s}\n'.format("", msg, nada, nada))
				out= newVal+out
		except Exception as e:
			# print ("weird error", e)
			pass
		finalOutput+=out
		j+=1		
	finalOutput= finalOutput+res2+""
	# print(finalOutput)

	finalOutputNoColors=cleanColors(finalOutput)
	# pMnemonic= i.mnemonic

	
	# print ("sBy.shDisassemblyLine")
	# for each in sBy.shDisassemblyLine:
	# 	print (each)
	# print (sBy.shDisassemblyLine)

	# print (len(sBy.shDisassemblyLine), len(sBy.shAddresses))

	return finalOutputNoColors, finalOutput


def clearTempDis():
	# print ("clearTempDis", len(sBy.shDisassemblyLine))

	sBy.shDisassemblyLine.clear()
	sBy.shAddresses.clear()
	sBy.shMnemonic.clear()
	sBy.shOp_str.clear()

	# print("cleared")


def checkForBad00(data, offset, end):
	dprint2("checkForBad00")
	
	
	# dprint2 (len(sBy.shAddresses), len(sBy.shDisassemblyLine))
	sample="add byte ptr \[eax], al"
	ans=[]
	for x in range(4):
		if str(hex(offset)) in sBy.shAddresses:
			# print("FOUND candidate", str(hex(offset)))
			index=sBy.shAddresses.index(str(hex(offset)))

			print (index, len(sBy.shDisassemblyLine), len(sBy.shAddresses))
			dprint2 (index, sBy.shDisassemblyLine[index], sBy.shAddresses[index])

			findBad00= re.search(sample, sBy.shDisassemblyLine[index], re.M|re.I)
			if findBad00:

				dprint2 ("    ", sBy.shAddresses[index], "gots it")

				ans.append(int(sBy.shAddresses[index],16))
				ans.append(int(sBy.shAddresses[index],16) +1)
		offset+=1
	dprint2 (ans)
	if len(ans)>0:
		size=len(ans)-1
		distance = ans[size]-ans[0]
		dprint2(distance)
		dprint2 (ans[0], ans[distance])
		modifysBySpecial(data, ans[0], end, "al")
		modifysByRange(data, ans[0], end,  "d","checkForBad00")
	# print ("got bad one")
	# input()


def disHereMakeDB2Edited(data,offset, end, mode, CheckingForDB):  #### new one
	dprint2("dis: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	num_bytes=end-offset
	dprint2 (num_bytes)
	printAllsByRange(offset,offset+num_bytes)

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
	instr=""
	# for x in range (length):
		# if offset >= length:
		# 	break

	maxSize=offset+length
	sample=""
	while offset < maxSize:
		stop=offset+1
		sample=data[offset:stop]
		bytesRes= (binaryToStr(data[offset:stop]))
		instr="db 0"+bytesRes[1:]+" (!)"
		Ascii2=makeAsciiforDB(bytesRes)
		val +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
		# sVal +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
		dprint2 ("checkingDis", hex(offset), hex(length))
	

		if sBy.strings[offset]==True: # and sBy.boolspecial[offset]==False:
			dbFlag=True
			stringInProgress=True
			stringval=val
			# addDis(offset,stringVal)
			truth,res=checkForLabel(str(hex(offset)),labels)
			if truth:
				val=res + val
				stringVal=res + stringVal
			stringStart, stringDistance=sBy.stringsStart[offset]
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
				stringVala=sBy.stringsValue[offset]+" ; string"
				# bprint ("\t\t\tmaking strings", stringVala)

				# input()
				dbOut+=(binaryToStr(data[t:t+1]))
				dprint2 (stringVala)
				
			if offset>stringStart:
				dprint2 (stringVala)
				dprint2 ("dbout ", hex(t))
				dbOut+=(binaryToStr(data[t:t+1]))
		if (sBy.strings[offset]==False):#  and sBy.boolspecial[offset]==False:
			dprint2("FoundNOTSTRING", hex(stringStart), hex(offset),"off")

			stringInProgress=False
			if dbFlag==False  and sBy.boolspecial[offset]==False:
				# print ("dbflag=False")
				truth,res=checkForLabel(str(hex(offset)),labels)
				if truth:
					val=val+res
					stringVal=stringVal+res
				# curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				

				# print ("sStart1", hex(sStart1))
				# Ascii3=toString(m[o].rawData2[sStart1:offset])
				# print ("Ascii2", Ascii22)
				# print ("Ascii3", Ascii3)
				Ascii2=""
				bytesRes=""
				instr=""
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), "", "", ""))

				stringVal+=curDisassembly
				# bytesRes="0x"+binaryToStr(data[offset:offset+1],2)
				bytesRes="0x"+data[offset:offset+1].hex()
				addDis(offset, "db" + " " +bytesRes, "db", bytesRes,"A.")
				# print ("y offset", hex(t))
		
				# stringVal= beforeS + stringVal
				skip=True
			if dbFlag==True:

				# print ("sV, offset: ", hex(offset), "value ", sBy.stringsValue[offset])
				nada=""
				truth,res=checkForLabel(str(hex(offset)),labels)
				if truth:
					val=val+res
					stringVal=stringVal+res
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(startAddString, stringVala+"",dbOut,nada ))
				stringVal+=curDisassembly
				# print ("addy", hex(offset))
				# print ("startAddString", startAddString, type(startAddString))
				# addDis(int(startAddString, 16),curDisassembly, "string","", "B")  #old
				addDis(int(startAddString,16),"",stringVala, "", "StringB")   # new Fixed

				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				if  sBy.boolspecial[offset]==False:
					stringVal+=curDisassembly
					# addDis(offset,curDisassembly, "db", "0x"+bytesRes[2:],"C")
					bytesRes="0x"+data[offset:offset+1].hex()
					addDis(offset, "db" + " " +bytesRes, "db", bytesRes,"BD")  # new - not tested
				if len(beforeS) > 0:
					stringVal= beforeS +"\n"+ "C."+curDisassembly
				dprint2 ("stringVal", stringVal)
				dbOut=""
				dprint2 (stringVal)
				dbFlag=False
				skip=True
			if not skip:
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				stringVal+=curDisassembly
				# addDis(offset,stringVal, "db", "0x"+bytesRes[2:], "BD")  # old
				bytesRes="0x"+data[offset:offset+1].hex()
				addDis(offset, "db" + " " +bytesRes, "db", bytesRes,"BD")  # new - not tested
			skip=False
		# "bytesres
		if sBy.boolspecial[offset]==True:
			mes=sBy.specialVal[offset]
			offset=sBy.specialEnd[offset]-1
			t=offset
			w=offset
			distanceStr =str(hex(sBy.specialEnd[offset]-sBy.specialStart[offset] ))
			if sBy.specialVal[t] == "al":
				stringValSp="align " +distanceStr
			elif sBy.specialVal[t] == "ff":
				stringValSp="db 0xff x"  + distanceStr 
			else:
				stringValSp="align " +distanceStr
			nada=""
			dbOutSp=(binaryToStr(data[sBy.specialStart[offset]:sBy.specialEnd[offset]]))
			curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(sBy.specialStart[offset])), stringValSp,dbOutSp,nada ))
			stringVal+=""+curDisassembly
			if sBy.specialVal[t] == "al":
				stringValSp="align " +distanceStr
				bytesRes= (binaryToStr(sample,2))
				bytesOut="db 0x"+bytesRes+"\n"
				# addDis(sBy.specialStart[offset],curDisassembly, bytesOut*int(len(dbOutSp)/4), "","D1")   #doesn't seem to be used  - old

				mnemonicVal="align " + hex(sBy.specialEnd[offset] - sBy.specialStart[offset])
				print ("distanceAlign", hex(sBy.specialStart[offset]), hex(sBy.specialEnd[offset]))
				print (mnemonicVal)

				addDis(sBy.specialStart[offset],mnemonicVal , mnemonicVal, "","D1")   		 #doesn't seem to be used   --> new 

			elif sBy.specialVal[t] == "ff":
				stringValSp="db 0xff x"  + distanceStr 
				bytesRes= (binaryToStr(sample,2))
				bytesOut="db 0x"+bytesRes+"\n"
				# addDis(sBy.specialStart[offset],curDisassembly,bytesOut*int(len(dbOutSp)/4), "","D2")   # old


				mnemonicVal="db 0xff x " + hex(sBy.specialEnd[offset] - sBy.specialStart[offset])


				addDis(sBy.specialStart[offset],mnemonicVal,mnemonicVal, "","D2")		# new
			else:
				bytesRes= (binaryToStr(sample,2))
				bytesOut="db 0x"+bytesRes+"\n"
				# addDis(sBy.specialStart[offset],curDisassembly, (bytesOut)*int(len(dbOutSp)/4), "","D3")   	 #old	# this is the one used
				stringValSp="align " +distanceStr

				mnemonicVal="align " + hex(sBy.specialEnd[offset] - sBy.specialStart[offset])
				print ("distanceAlign", hex(sBy.specialStart[offset]), hex(sBy.specialEnd[offset]))
				print (mnemonicVal)

				addDis(sBy.specialStart[offset],mnemonicVal , mnemonicVal, "","D3")   		# this is the one used    ---> new

			# addDis(sBy.specialStart[offset],"D."+curDisassembly, "db 0xff\n"*int(len(dbOutSp)/4), "")
			# print ("got it align", hex(offset))
			dprint2(hex(len(sBy.boolspecial)))

			# sBy.specialVal[t]=dataType
			# sBy.specialStart[t]=start
			# sBy.specialEnd[t]=end
			# sBy.boolspecial[t]=True
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
				# curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(startAddString, stringVala+"cat","","" ))
				stringVal+=curDisassembly
				# print ("findme")
				# print (stringVala)
				# print (dbOut)
				addDis(int(startAddString,16),"",stringVala, "", "EndStringMaker")
				# stringVal= beforeS + stringVal
				dbOut=""
				dbFlag=False
				if len(dbOut)>0:
					curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
					stringVal+=curDisassembly
					addDis(offset,curDisassembly,"F")
			w=0
	# print("ending: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	dprint2("returnDB2\n", val)
	dprint2("stringval\n")
	dprint2(stringVal)
	dprint2 ("")
	val=stringVal
	return val
def disHereMakeDB2(data,offset, end, mode, CheckingForDB):  #### new one
	bprint("dis: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	# dprint2 (num_bytes)
	# printAllsByRange(offset,offset+num_bytes)
	global labels
	# t=offset
	w=0
	length=end-offset
	dbFlag=False
	skip=True
	startAddString=""
	stringVala=""
	stringStart=0
	stringInProgress=False
	maxSize=offset+length
	dbOut=""
	# print ("maxsize", hex(maxSize), "offset-start", hex(offset), "end", hex(end))
	# print ("sBy.strings", hex(len(sBy.strings)))
	# print (hex(len(m[o].rawData2)))
	while offset < maxSize:
		# print ("of", hex(offset))
		check=sBy.strings[offset]

		if sBy.strings[offset]==True: # and sBy.boolspecial[offset]==False:
			dbFlag=True
			stringInProgress=True
			stringStart, stringDistance=sBy.stringsStart[offset]
			# dprint2("FoundSTRING", hex(stringStart), hex(offset),"off")
			if stringStart==offset:
				startAddString=str(hex(offset))
				stringVala=sBy.stringsValue[offset]+mag+" ; string"+res2+"\t\t"
				# bprint ("\t\t\tmaking strings", stringVala)
		elif (sBy.strings[offset]==False):#  and sBy.boolspecial[offset]==False:
			# dprint2("FoundNOTSTRING", hex(stringStart), hex(offset),"off")
			stringInProgress=False
			if dbFlag==False  and sBy.boolspecial[offset]==False:
				bytesRes="0x"+data[offset:offset+1].hex()
				addDis(offset, "db" + " " +bytesRes, "db", bytesRes,"A.")
				skip=True
			elif dbFlag==True:
				addDis(int(startAddString,16),"",stringVala, "", "StringB")   # new Fixed
				if  sBy.boolspecial[offset]==False:
					bytesRes="0x"+data[offset:offset+1].hex()
					addDis(offset, "db" + " " +bytesRes, "db", bytesRes,"BD")  # new - not tested
				dbFlag=False
				skip=True
			if not skip:
				bytesRes="0x"+data[offset:offset+1].hex()
				addDis(offset, "db" + " " +bytesRes, "db", bytesRes,"BD")  # new - not tested
			skip=False
		if sBy.boolspecial[offset]==True:
			offset=sBy.specialEnd[offset]-1
			# t=offset
			# w=offset
			if sBy.specialVal[offset] == "al":
				mnemonicVal="align " + hex(sBy.specialEnd[offset] - sBy.specialStart[offset])
				# print ("distanceAlign", hex(sBy.specialStart[offset]), hex(sBy.specialEnd[offset]))
				# print (mnemonicVal)
				addDis(sBy.specialStart[offset],mnemonicVal , mnemonicVal, "","D1")   		 #doesn't seem to be used   --> new 
			elif sBy.specialVal[offset] == "ff":
				mnemonicVal="db 0xff x " + hex(sBy.specialEnd[offset] - sBy.specialStart[offset])
				addDis(sBy.specialStart[offset],mnemonicVal,mnemonicVal, "","D2")		# new
			else:
				mnemonicVal="align " + hex(sBy.specialEnd[offset] - sBy.specialStart[offset])
				# print ("distanceAlign", hex(sBy.specialStart[offset]), hex(sBy.specialEnd[offset]))
				# print (mnemonicVal)
				addDis(sBy.specialStart[offset],mnemonicVal , mnemonicVal, "","D3")   		# this is the one used    ---> new
			# dprint2(hex(len(sBy.boolspecial)))
		offset +=1
		# t+=1
		w+=1
		if w==(length):
			if dbFlag==True:
				addDis(int(startAddString,16),"",stringVala, "", "EndStringMaker")
				dbFlag=False
			w=0
	return ""

def disHereMakeDB233(data,offset, end, mode, CheckingForDB):
	dprint2("dis: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	num_bytes=end-offset
	dprint2 (num_bytes)
	printAllsByRange(offset,offset+num_bytes)

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
	instr=""
	# for x in range (length):
		# if offset >= length:
		# 	break

	maxSize=offset+length
	sample=""
	while offset < maxSize:
		stop=offset+1
		sample=data[offset:stop]
		bytesRes= (binaryToStr(data[offset:stop]))
		instr="db 0"+bytesRes[1:]+" (!)"
		Ascii2=makeAsciiforDB(bytesRes)
		val +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
		# sVal +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
		dprint2 ("checkingDis", hex(offset), hex(length))
	

		if sBy.strings[offset]==True: # and sBy.boolspecial[offset]==False:
			dbFlag=True
			stringInProgress=True
			stringval=val
			# addDis(offset,stringVal)
			truth,res=checkForLabel(str(hex(offset)),labels)
			if truth:
				val=res + val
				stringVal=res + stringVal
			stringStart, stringDistance=sBy.stringsStart[offset]
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
				stringVala=sBy.stringsValue[offset]+" ; string"
				# print ("\t\t\tmaking strings", stringVala)

				# input()
				dbOut+=(binaryToStr(data[t:t+1]))
				dprint2 (stringVala)
				
			if offset>stringStart:
				dprint2 (stringVala)
				dprint2 ("dbout ", hex(t))
				dbOut+=(binaryToStr(data[t:t+1]))
		if (sBy.strings[offset]==False):#  and sBy.boolspecial[offset]==False:
			dprint2("FoundNOTSTRING", hex(stringStart), hex(offset),"off")

			stringInProgress=False
			if dbFlag==False  and sBy.boolspecial[offset]==False:
				# print ("dbflag=False")
				truth,res=checkForLabel(str(hex(offset)),labels)
				if truth:
					val=val+res
					stringVal=stringVal+res
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				stringVal+=curDisassembly

				addDis(offset,curDisassembly, "db", "0x"+bytesRes[2:],"A.")
				# print ("y offset", hex(t))
		
				# stringVal= beforeS + stringVal
				skip=True
			if dbFlag==True:

				# print ("sV, offset: ", hex(offset), "value ", sBy.stringsValue[offset])
				nada=""
				truth,res=checkForLabel(str(hex(offset)),labels)
				if truth:
					val=val+res
					stringVal=stringVal+res
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(startAddString, stringVala,dbOut,nada ))
				stringVal+=curDisassembly
				# print ("addy", hex(offset))
				# print ("startAddString", startAddString, type(startAddString))
				addDis(int(startAddString, 16),curDisassembly, "string","", "B")
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				if  sBy.boolspecial[offset]==False:
					stringVal+=curDisassembly
					addDis(offset,curDisassembly, "db", "0x"+bytesRes[2:],"C")
				if len(beforeS) > 0:
					stringVal= beforeS +"\n"+ "C."+curDisassembly
				dprint2 ("stringVal", stringVal)
				dbOut=""
				dprint2 (stringVal)
				dbFlag=False
				skip=True
			if not skip:
				curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				stringVal+=curDisassembly
				addDis(offset,stringVal, "db", "0x"+bytesRes[2:], "BD")
			skip=False
		# "bytesres
		if sBy.boolspecial[offset]==True:
			mes=sBy.specialVal[offset]
			offset=sBy.specialEnd[offset]-1
			t=offset
			w=offset
			distanceStr =str(hex(sBy.specialEnd[offset]-sBy.specialStart[offset] ))
			if sBy.specialVal[t] == "al":
				stringValSp="align " +distanceStr
			elif sBy.specialVal[t] == "ff":
				stringValSp="db 0xff x"  + distanceStr 
			else:
				stringValSp="align " +distanceStr
			nada=""
			dbOutSp=(binaryToStr(data[sBy.specialStart[offset]:sBy.specialEnd[offset]]))
			curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(sBy.specialStart[offset])), stringValSp,dbOutSp,nada ))
			stringVal+=""+curDisassembly
			if sBy.specialVal[t] == "al":
				stringValSp="align " +distanceStr
				bytesRes= (binaryToStr(sample,2))
				bytesOut="db 0x"+bytesRes+"\n"
				addDis(sBy.specialStart[offset],curDisassembly, bytesOut*int(len(dbOutSp)/4), "","D1")   #doesn't seem to be used
			elif sBy.specialVal[t] == "ff":
				stringValSp="db 0xff x"  + distanceStr 
				bytesRes= (binaryToStr(sample,2))
				bytesOut="db 0x"+bytesRes+"\n"
				addDis(sBy.specialStart[offset],curDisassembly,bytesOut*int(len(dbOutSp)/4), "","D2")
			else:
				bytesRes= (binaryToStr(sample,2))
				bytesOut="db 0x"+bytesRes+"\n"
				addDis(sBy.specialStart[offset],curDisassembly, (bytesOut)*int(len(dbOutSp)/4), "","D3")   		# this is the one used
				stringValSp="align " +distanceStr
			# addDis(sBy.specialStart[offset],"D."+curDisassembly, "db 0xff\n"*int(len(dbOutSp)/4), "")
			# print ("got it align", hex(offset))
			dprint2(hex(len(sBy.boolspecial)))

			# sBy.specialVal[t]=dataType
			# sBy.specialStart[t]=start
			# sBy.specialEnd[t]=end
			# sBy.boolspecial[t]=True
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
				# print ("findme")
				# print (stringVala)
				# print (dbOut)
				addDis(int(startAddString,16),curDisassembly,stringVala, "", "E")
				# stringVal= beforeS + stringVal
				dbOut=""
				dbFlag=False
				if len(dbOut)>0:
					curDisassembly =('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
					stringVal+=curDisassembly
					addDis(offset,curDisassembly,"F")
			w=0
	# print("ending: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	dprint2("returnDB2\n", val)
	dprint2("stringval\n")
	dprint2(stringVal)
	dprint2 ("")
	val=stringVal
	return val
def dprint4(*args):
	debugging=True
	dprint3(*args)
	debugging=False

# debugging=False
def dprint(*args):
	# print("Debug")
	# if debugging==True:
		# print(info)
	dprint2(*args)

def dprint2(*args):

	if debugging:
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


def bprint(*args):
	brDebugging=False
	if brDebugging:
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
	# dprint2("remove offset ", notBad)
	global off_PossibleBad
	# for x in off_PossibleBad.copy():
	# 	# print (x, type(x))
	# 	if x == notBad:
	# 		print ("it gone")
	# 		off_PossibleBad.remove (x)

	if notBad in off_PossibleBad.copy():
		off_PossibleBad.remove (notBad)

					
	# dprint2 (off_PossibleBad)


def removeLabels(notLabel, val):
	# dprint2("remove labels ", notLabel)
	# labels.add(str(hex(destination)))
	# off_Label.add(int(i.op_str, 16))
	global labels

	if val in labels.copy():
		labels.remove (val)
	# for x in labels.copy():
	# 	# print (x, type(x))
	# 	if x == val:
	# 		dprint ("labels it gone")
	# 		labels.remove (x)
	# 		# del off_Label[t]
	# 		dprint ("labels it gone2")
	# 	t+=1

def optimizedFind2(data,patternMatch, funcName):
	start=0
	while True:
		start = data.find(patternMatch , start)

		# print (start)
		if funcName=="hiddencalls":
			if start != -1:
				# print ("\n\nhidden!!!!", patternMatch, hex(start),)
				anaFindCallsNew(start, data)
		if funcName=="hiddenjmps":
			if start != -1:
				# print ("\n\nhiddenjmps!!!!", patternMatch, hex(start),)
				anaFindShortJumpsNew(start, data)
		if start == -1:
			break
		else:
			start += len(patternMatch)

def hiddencalls(val):
	print ("TEST hidden calls:", hex(val))
def analysisFindHiddenCalls(data, startingAddress, caller=None):   #new!
	dprint2("analysisFindHiddenCalls " + str(startingAddress))
	current=0
	start=startingAddress
	max=len(sBy.bytesType)-1
	finalPrint=""
	
	mBool[o].bAnaHiddenCallsDone = True
	mBool[o].bAnaHiddenCnt=mBool[o].bAnaHiddenCnt+1
	if mBool[o].bAnaHiddenCnt>0:
		mBool[o].bAnaHiddenCallsDone = True
		# print ("hidden TRUE--> stop!", mBool[o].bAnaHiddenCallsDone)
	# print ("\t\t", gre+"inside analysisFindHiddenCalls!!!!!!!!!!!!!"+res, caller)
	# print (start, "start")
	start, current, distance, typeBytes = findRange2(current)
	# print (start, "AFTER FIRST")
	reset = False

	# optimizedFind2(data,b"\xe8","hiddencalls")

	# optimizedFind2(data,b"\xe9","hiddenjmps")
	# optimizedFind2(data,b"\xeb","hiddenjmps")
	# # optimizedFind2(data,b"\xe8","hiddenjmps")


	# while 1==222:
	while current < max:
	# for each in sBy.bytesType:
		# dprint (start, "end2")
		# print ("trackFindRange 1:               ",  "start", hex(start), "current", hex(current),  hex(distance))
		if max==current:
			current+=1
		# dprint2(binaryToStr(data[start:current]))
		if not typeBytes:
			dprint2 ("AN: above is data")
			# anaFindCalls(data,start, start+distance)
			# anaFindShortJumps(data,start, start+distance)
			anaCombined(data,start, start+distance)
			# anaFindCalls(data,start, start+distance)

		# print ("trackFindRange 2: hidden BEFORE ", "start", hex(start),"current", hex(current), hex(distance), typeBytes )
		start, current, distance, typeBytes = findRange2(current)
		# print ("trackFindRange 3: hidden AFTER  ", "start", hex(start),"current", hex(current), hex(distance), typeBytes )

		if current==max:
			# print ("gotme")
			pass
		#reset once done - do analysis again to catch any changes 
		if (current) == max and reset != True:
			reset=True
			# dprint ("reset")
			current=0
	# print ("finished!!!")




def analysisFindHiddenCalls222(data, startingAddress, caller=None): # original!!!!!
	dprint2("analysisFindHiddenCalls " + str(startingAddress))
	current=0
	start=startingAddress
	max=len(sBy.bytesType)-1
	finalPrint=""
	
	mBool[o].bAnaHiddenCallsDone = True
	mBool[o].bAnaHiddenCnt=mBool[o].bAnaHiddenCnt+1
	if mBool[o].bAnaHiddenCnt>0:
		mBool[o].bAnaHiddenCallsDone = True
		# print ("hidden TRUE--> stop!", mBool[o].bAnaHiddenCallsDone)
	# print ("\t\t", gre+"inside analysisFindHiddenCalls!!!!!!!!!!!!!"+res, caller)
	# print (start, "start")
	start, current, distance, typeBytes = findRange2(current)
	# print (start, "AFTER FIRST")
	reset = False
	while current < max:
	# for each in sBy.bytesType:
		# dprint (start, "end2")
		# dprint2 ("1ana",  "start", hex(start), "current", hex(current),  hex(distance))
		if max==current:
			current+=1
		# dprint2(binaryToStr(data[start:current]))
		if not typeBytes:
			dprint2 ("AN: above is data")
			anaFindCalls(data,start, start+distance)
			anaFindShortJumps(data,start, start+distance)
		# print ("hidden b4", hex(start), hex(current), hex(distance), typeBytes )
		start, current, distance, typeBytes = findRange2(current)
		# print ("hidden AFTER  ", hex(start), hex(current), hex(distance), typeBytes )

		if current==max:
			# print ("gotme")
			pass
		#reset once done - do analysis again to catch any changes 
		if (current) == max and reset != True:
			reset=True
			# dprint ("reset")
			current=0
	# print ("finished!!!")


def anaFindAlign2(data):
	# global FFInstructions
	dprint2("anaFindF2")
	OP_FF=b"\x00"
	offset=0
	maxV=len(data)
	escape=False
	# modifysByRange(data, 0x170, 0x175, "d")
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


		while (test == OP_FF) and (sBy.bytesType[offset]==False):
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
			# modifysByRange(data, offset, offset+distance+total, "d")
			# modifyStringsRange(offset, offset+distance+total, "s", word)
			if total > 6:
				modifysByRange(data, offset+3, offset+distance+total, "d","anaFindAlign2")

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
	mBool[o].bAnaConvertBytesDone = True
	dprint2("analysisConvertBytes", startingAddress)
	current=0
	start=startingAddress
	max=len(sBy.bytesType)-1
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
					modifysByRange(data, dataRangeEnd[t-1],dataRangeEnd[t-1]+distance, "d","analysisConvertBytes")
			else: 
				dprint2 (str(hex(dataRangeEnd[t-1])),"****in labels")
		except:
			pass
		dprint2 (hex(distance))
		dprint2 ("*************************\n")
		t+=1



def anaFindCallsNew(start, data):   #nEW
	global offsets
	global labels
	# print ("anna: " + " "  + str(hex(start)) )#+ " " + str(hex(current)) )
	OP_CALL =  b"\xe8"
	OP_ff =  b"\xff"
	# dprint2 (binaryToStr(data[start:current]))
	t=0
	destination=99999999
	searchFor=[]
	# for opcode in data[start:current]:
	test=int(data[start+t])
	# print ("test", hex(test))
	if test==ord(OP_CALL):
		# print("FOUND 0xe8!")
		ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
		# print (ans, valb_1, valb_2)
		if valb_1=="call":
			modifysByRange(data, start+t,start+t+5,"i")
			###check to see if = FF FF FF  - negative - otherwise, positive!
			# print ("checking ff")
			# print (int(data[start+t+4]), ord(OP_ff))
			if (int(data[start+t+4]))==ord(OP_ff):
				if (int(data[start+t+3]))==ord(OP_ff):
					signedNeg=signedNegHexTo(int(valb_2,16))
					destination=(start+t) +signedNeg
					ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
					# print (valb_2)
					# print("ff destination: " + str(hex(destination)))
					if str(hex(destination)) not in labels:
						# print  ("1 appending label** " + str(hex(destination)))
						labels.add(str(hex(destination)))
			#ok, it is positive
			elif (int(data[start+t+4]))==0:
				# if (int(data[start+t+3]))==0:
				ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
				destination = (start+t) + int(valb_2,16)
				# print ((hex(start+t)))
				# print(hex(signedNeg))
				# print("00 destination: " + str(hex(destination)))
				if str(hex(destination)) not in labels:
					# print  ("2 appending label " + str(hex(destination)))
					labels.add(str(hex(destination)))
			if str(hex(destination)) not in searchFor:
				searchFor.append(str(hex(destination)))
				offsets.add(destination)
				modifysByRange(data, destination-2, destination,"d")

	t+=1


def anaCombined(data, start, current):   #original
	global offsets
	global labels
	# print ("annaFindShortJumps: " + " "  + str(hex(start)) + " " + str(hex(current)) )
	OP_SHORT_JUMP =  b"\xeb"
	OP_SHORT_JUMP_NEG =  b"\xe9"
	OP_CALL =  b"\xe8"
	OP_ff =  b"\xff"
	t=0
	destination=99999999
	searchFor=[]
	for opcode in data[start:current]:
		test=int(data[start+t])
		# print (hex(test))
		if test==ord(OP_SHORT_JUMP):
			# print("FOUND 0xeb!", hex(start+t))
			
			if b"\xff" in data[start+t:start+t+5]:
				ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
			else:
				ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+2])
			# print (ans, valb_1, valb_2)
			# print ("ans:",ans)
			if valb_1=="jmp":
				# print ("checking short jump")
				modifysByRange(data, start+t,start+t+num_bytes,"i","anaCombined")
				if "ff" in valb_2:
					# print ("has  ff")
					signedNeg=signedNegHexTo(int(valb_2,16))
					# print ("signedNeg", signedNeg)
					valb_2=str(hex(signedNeg))
				destination = (start+t) + int(valb_2,16)
				# print("eb destination: " + str(hex(destination)))
				if str(hex(destination)) not in labels:
					labels.add(str(hex(destination)))
					# print  ("3 appending label " + str(hex(destination)))
				
				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))
		# FINE, IT IS NEGATIVE
		elif test==ord(OP_SHORT_JUMP_NEG):
			# print("FOUND 0xe9!")
			
			if b"\xff" in data[start+t:start+t+5]:
				ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
			else:
				ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+2])
			# print (ans, valb_1, valb_2)
			if valb_1=="jmp":
				modifysByRange(data, start+t,start+t+num_bytes,"i","anaCombined")
				if "ff" in valb_2:
					# print ("has  ff")
					signedNeg=signedNegHexTo(int(valb_2,16))
					# print ("signedNeg", signedNeg)
					valb_2=str(hex(signedNeg))
				# print ("checking short jump negative")
				destination = (start+t) + int(valb_2,16)
				# print("neg e9 destination: " + str(hex(destination)))
				if str(hex(destination)) not in labels:
					labels.add(str(hex(destination)))
					# print  ("4 appending label " + str(hex(destination)))

				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))

		elif test==ord(OP_CALL):
			# print("FOUND 0xe8!")
			ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
			# print (ans, valb_1, valb_2)
			if valb_1=="call":
				modifysByRange(data, start+t,start+t+5,"i","anaCombined")
				###check to see if = FF FF FF  - negative - otherwise, positive!
				# print ("checking ff")
				# print (int(data[start+t+4]), ord(OP_ff))
				if (int(data[start+t+4]))==ord(OP_ff):
					if (int(data[start+t+3]))==ord(OP_ff):
						signedNeg=signedNegHexTo(int(valb_2,16))
						destination=(start+t) +signedNeg
						ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
						# print (valb_2)
						# print("ff destination: " + str(hex(destination)))
						if str(hex(destination)) not in labels:
							# print  ("1 appending label " + str(hex(destination)))
							labels.add(str(hex(destination)))
				#ok, it is positive
				elif (int(data[start+t+4]))==0:
					# if (int(data[start+t+3]))==0:
					ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
					destination = (start+t) + int(valb_2,16)
					# print ((hex(start+t)))
					# print(hex(signedNeg))
					# print("00 destination: " + str(hex(destination)))
					if str(hex(destination)) not in labels:
						# print  ("2 appending label " + str(hex(destination)))
						labels.add(str(hex(destination)))
				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))
					offsets.add(destination)
					modifysByRange(data, destination-2, destination,"d", "findAna")

		t+=1
	for addy in searchFor:
		if int(addy,16) in offsets:
			# print("In offsets")
			pass
		else:
			# print("Not in offsets")
			# print ("addy", addy)
			offsets.add(int(addy, 16))
			removeBadOffsets(addy)
			# print (type(each))
			modifysByRange(data, int(addy,16)-2, int(addy,16),"d", "findAna")


def anaFindShortJumps(data, start, current):   #original
	global offsets
	global labels
	print ("annaFindShortJumps: " + " "  + str(hex(start)) + " " + str(hex(current)) )
	OP_SHORT_JUMP =  b"\xeb"
	OP_SHORT_JUMP_NEG =  b"\xe9"
	OP_ff =  b"\xff"
	# print (binaryToStr(data[start:current]))
	t=0
	destination=99999999
	searchFor=[]
	for opcode in data[start:current]:
		test=int(data[start+t])
		# print ("sj", hex(start+t), ": ", hex(test), hex(ord(OP_SHORT_JUMP)))
		# IT IS A POSITIVE JUMP
		if test==ord(OP_SHORT_JUMP):
			print("FOUND 0xeb!", hex(start+t))
			
			if b"\xff" in data[start+t:start+t+5]:
			# print ("in it ")
				ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
			else:
			# print ("not in it")
				ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+2])
			print (ans, valb_1, valb_2)
			print ("ans:",ans)
			if valb_1=="jmp":
				print ("checking short jump")
				modifysByRange(data, start+t,start+t+num_bytes,"i")
				if "ff" in valb_2:
					# print ("has  ff")
					signedNeg=signedNegHexTo(int(valb_2,16))
					# print ("signedNeg", signedNeg)
					valb_2=str(hex(signedNeg))
				destination = (start+t) + int(valb_2,16)
				print("eb destination: " + str(hex(destination)))
				if str(hex(destination)) not in labels:
					labels.add(str(hex(destination)))
					print  ("3 appending label " + str(hex(destination)))

				
				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))
		# FINE, IT IS NEGATIVE
		if test==ord(OP_SHORT_JUMP_NEG):
			print("FOUND 0xe9!")
			
			if b"\xff" in data[start+t:start+t+5]:
			# print ("in it ")
				ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
			else:
			# print ("not in it")
				ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+2])
			print (ans, valb_1, valb_2)
			print ("ans:",ans)
			if valb_1=="jmp":
				modifysByRange(data, start+t,start+t+num_bytes,"i")
				if "ff" in valb_2:
					# print ("has  ff")
					signedNeg=signedNegHexTo(int(valb_2,16))
					# print ("signedNeg", signedNeg)
					valb_2=str(hex(signedNeg))
				print ("checking short jump negative")
				destination = (start+t) + int(valb_2,16)
				print("neg e9 destination: " + str(hex(destination)))
				if str(hex(destination)) not in labels:
					labels.add(str(hex(destination)))
					print  ("4 appending label " + str(hex(destination)))

				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))




		t+=1
	for addy in searchFor:
		if int(addy,16) in offsets:
			print("In offsets")
		else:
			print("Not in offsets")
			print ("addy", addy)
			offsets.add(int(addy, 16))
			removeBadOffsets(addy)
			# print (type(each))
			modifysByRange(data, int(addy,16)-1, int(addy,16),"d")


def anaFindCalls(data, start, current):   #original
	global offsets
	global labels
	print ("annafindCalls: " + " "  + str(hex(start)) + " " + str(hex(current)) )
	OP_CALL =  b"\xe8"
	OP_ff =  b"\xff"
	# print (binaryToStr(data[start:current]))
	t=0
	destination=99999999
	searchFor=[]
	for opcode in data[start:current]:
		test=int(data[start+t])
		if test==ord(OP_CALL):
			print("FOUND 0xe8!")
			ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
			print (ans, valb_1, valb_2)
			if valb_1=="call":
				modifysByRange(data, start+t,start+t+5,"i")
				###check to see if = FF FF FF  - negative - otherwise, positive!
				print ("checking ff")
				print (int(data[start+t+4]), ord(OP_ff))
				if (int(data[start+t+4]))==ord(OP_ff):
					if (int(data[start+t+3]))==ord(OP_ff):
						signedNeg=signedNegHexTo(int(valb_2,16))
						destination=(start+t) +signedNeg
						ans, valb_1, valb_2, num_bytes= disHereTiny(data[start+t:start+t+5])
						print (valb_2)
						print("ff destination: " + str(hex(destination)))
						if str(hex(destination)) not in labels:
							print  ("1 appending label " + str(hex(destination)))
							labels.add(str(hex(destination)))
				#ok, it is positive
				elif (int(data[start+t+4]))==0:
					# if (int(data[start+t+3]))==0:
					ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
					destination = (start+t) + int(valb_2,16)
					# print ((hex(start+t)))
					# print(hex(signedNeg))
					print("00 destination: " + str(hex(destination)))
					if str(hex(destination)) not in labels:
						print  ("2 appending label " + str(hex(destination)))
						labels.add(str(hex(destination)))
				if str(hex(destination)) not in searchFor:
					searchFor.append(str(hex(destination)))
					offsets.add(destination)
					modifysByRange(data, destination-2, destination,"d")

		t+=1

	# for addy in searchFor:
	# 	if addy in offsets:
	# 		dprint2("In offsets")
	# 	else:
	# 		if int(addy,16) not in offsets:
	# 			offsets.add(int(addy,16))
	# 		dprint2("Not in offsets")
	# 		# removeBadOffsets(addy)
	# 		modifysByRange(data, int(addy,16)-2, int(addy,16),"d")
	# print ("got anafindcalls")
	# print ("labels**",  len(labels))


def anaFindShortJumpsNew(start, data):   # NEW 
	global offsets
	global labels
	dprint2 ("anna2: " + " "  + str(hex(start)))# + " " + str(hex(current)) )
	OP_SHORT_JUMP =  b"\xeb"
	OP_SHORT_JUMP_NEG =  b"\xe9"
	OP_ff =  b"\xff"
	# dprint2 (binaryToStr(data[start:current]))
	t=0
	destination=99999999
	searchFor=[]

	test=int(data[start+t])
	# print ("sj", hex(start+t), ": ", hex(test), hex(ord(OP_SHORT_JUMP)))
	# IT IS A POSITIVE JUMP
	if test==ord(OP_SHORT_JUMP):
		# print("FOUND 0xeb!", hex(start+t))

		if b"\xff" in data[start+t:start+t+5]:
			# print ("in it ")
			ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
		else:
			# print ("not in it")
			ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+2])

		# print (ans, valb_1, valb_2)
		# print ("ans:",ans)
		if valb_1=="jmp":
			# print ("checking short jump")
			modifysByRange(data, start+t,start+t+num_bytes,"i")
			if "ff" in valb_2:
				# print ("has  ff")
				signedNeg=signedNegHexTo(int(valb_2,16))
				# print ("signedNeg", signedNeg)
				valb_2=str(hex(signedNeg))
			destination = (start+t) + int(valb_2,16)
			# print("eb destination: " + str(hex(destination)))
			if str(hex(destination)) not in labels:
				labels.add(str(hex(destination)))
				# print  ("3 appending label " + str(hex(destination)))

			
			if str(hex(destination)) not in searchFor:
				searchFor.append(str(hex(destination)))
	# FINE, IT IS NEGATIVE
	if test==ord(OP_SHORT_JUMP_NEG):
		# print("FOUND 0xe9!")
		if b"\xff" in data[start+t:start+t+5]:
			# print ("in it ")
			ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+5])
		else:
			# print ("not in it")
			ans, valb_1, valb_2,num_bytes= disHereTiny(data[start+t:start+t+2])

		# print (ans, valb_1, valb_2)
		# print ("ans:",ans)
		if valb_1=="jmp":
			modifysByRange(data, start+t,start+t+num_bytes,"i")
			if "ff" in valb_2:
				# print ("has  ff")
				signedNeg=signedNegHexTo(int(valb_2,16))
				# print ("signedNeg", signedNeg)
				valb_2=str(hex(signedNeg))
			# print ("checking short jump negative")
			destination = (start+t) + int(valb_2,16)
			# print("neg e9 destination: " + str(hex(destination)))
			if str(hex(destination)) not in labels:
				labels.add(str(hex(destination)))
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
			offsets.add(int(addy, 16))
			removeBadOffsets(addy)
			# print (type(each))
			modifysByRange(data, int(addy,16)-1, int(addy,16),"d")



def disHereShellcurrentgood(data,offset, end, mode, CheckingForDB, bit): #   LATESTNEW
	global labels
	global offsets
	global off_Label
	global off_PossibleBad
	global bit32
	disHereShell_start = time.time()
	
	# printAllsByRange(offset,end)
	dprint2 ("dis: dishereshell - range  "  + str(hex(offset)) + " " + str(hex(end)))
	dprint2(binaryToStr(data[offset:end]))
	dprint2(binaryToStr(data))

	start = time.time()
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
	val5 =[]
	startAdd=[]
	nextAdd=[]
	bytesPerLine=[]
	cntLines=0
	bytesEachLine=[]
	asciiPerLine=[]
	CODED3 = CODED2

	end = time.time()
	print("\t\t[-] inital ", end-start)
	
	start = time.time()
	for i in callCS.disasm(CODED3, address):
		cntLines+=1
		val=i.mnemonic + " " + i.op_str 
		offsets.add((int(i.address)))
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

				labels.add(val)
				off_Label.add(int(i.op_str, 16))
	current=0
	end= time.time()
	print("\t\t[-] loop 1 ", end-start)
	start = time.time()
	
	for i in callCS.disasm(CODED3, address):
		if current>0:
			nextAd=sadd1
			nextAdd.append(nextAd)
		sadd1=int(i.address )
		startAdd.append(int(sadd1))
		current+=1
	for labOff in off_Label:
		if labOff not in offsets:
			# print ("bad " + str(hex(labOff)))
			if str(hex(labOff)) not in off_PossibleBad:
				off_PossibleBad.add((str(hex(labOff))))
	
	end= time.time()
	print("\t\t[-] loop 2 ",end-start)
	start= time.time()
	dprint2 ("possible bad label offsets", off_PossibleBad)
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

	end= time.time()
	print("\t\t[-] loop 3 ", end-start)
	
	start= time.time()

	t=0
	for i in callCS.disasm(CODED3, address): 
		ans= binaryToStr(CODED3[cnt:cnt+bytesPerLine[t]]) #+ " " + str(t) + "\n"
		res=""
		for y in CODED3[cnt:cnt+bytesPerLine[t]]:
			zz=show1(y) 
			old="nope"
			if ((y > 31) & (y < 127)):
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
	end= time.time()
	print("\t\t[-] loop 4 ", end-start)
	# try:
	# 	add = hex(int(i.address))
	# except Exception as e:
	# 	dprint2 ("weird error - investigate")
	# 	dprint (e)
	# 	dprint(traceback.format_exc())
	# 	pass
	
	start= time.time()
	
	callCS.skipdata = True
	sizeShell=len(CODED2)
	for i in callCS.disasm(CODED2, address):
		val_b=i.mnemonic + " " + i.op_str 
		num_bytes=0
		try:
			val_c= bytesEachLine[t] 
			val_d=asciiPerLine[t] 
		except:
			val_c=""
			val_d=""
		if CheckingForDB:    # CheckingForDB=False
			try:
				num_bytes=int(len(val_c)/4)
			except:
				num_bytes=1
			val_b, num_bytes =checkForValidAddress2(hex(int(i.address)),i.mnemonic, i.op_str, sizeShell, off_PossibleBad,data,num_bytes)
		if mode=="ascii":
			val =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(hex(int(i.address)), val_b, val_c, val_d))
			addDis(i.address, val, i.mnemonic, i.op_str,"Main2")
		else:
			val =  hex(int(i.address)) + ":\t" + i.mnemonic + " " + i.op_str+"\n"
			val=('{:<10s} {:<35s}\n'.format(hex(int(i.address)), val_b))
			addDis(i.address, val, i.mnemonic, i.op_str,"Main3")

		####ADD COMMENTS
		if sBy.comments[i.address] !="":
			val_b=sBy.comments[int(hex(int(i.address)),16)]
			val_comment =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(nada, val_b, nada, nada))
			val+=val_comment
		#### ADD COMENTS END
		truth,res=checkForLabel( hex(int(i.address)),labels)
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
			cur=i.address
			# print (hex(sBy.pushStringEnd[cur]), add, "pushending")
			if (sBy.pushStringEnd[cur]-2) == cur:
				# dprint2 ("push match", sBy.pushStringValue[cur])
				nada=""
				msg="; "+sBy.pushStringValue[cur] + " - Stack string"
				newVal =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(nada, msg, nada, nada))
				val= newVal+val
				dprint2 (val)
		except Exception as e:
			# print ("weird error", e)
			pass

		val5.append(val)
		t+=1
	
	end= time.time()
	print("\t\t[-] loop 5 ", end-start)

	returnString="".join(val5)

	# dprint2 ("off_PossibleBad")
	# dprint2 (off_PossibleBad)
	
	disHereShell_end = time.time()

	return returnString

def disHereShellOLD(data,offset, end, mode, CheckingForDB, bit): #
	global labels
	global offsets
	global off_Label
	global off_PossibleBad
	global bit32
	global o

	disHereShell_start = time.time()
	
	# printAllsByRange(offset,end)
	# dprint2 ("dis: dishereshell - range  "  + str(hex(offset)) + " " + str(hex(end)))
	# dprint2(binaryToStr(data[offset:end]))
	# dprint2(binaryToStr(data))
	start = time.time()
	nada=""
	callCS = cs
	if(bit32):
		callCS = cs
	else:
		callCS = cs64
	callCS.skipdata = True
	callCS.skipdata_setup = ("db", None, None)
	CODED2=data[offset:end]
	val =""
	val5 =[]
	CODED3 = CODED2
	address=offset
	end = time.time()
	print("\t\t[-] inital ", end-start)
	
	start = time.time()
	for i in callCS.disasm(CODED3, address):
		offsets.add((int(i.address)))
		if re.match( r'\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bja\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', i.mnemonic, re.M|re.I):	
			val=i.op_str
			isHex= re.match( "^[0-9][x]*[A-Fa-f0-9 -]*",val, re.M|re.I)
			if isHex:
				# dprint2("addlabel: shell call " + val)
				is0x=re.match("0x",val, re.M|re.I)
				if not is0x:
					val="0x"+val
				# dprint2  ("6 appending label " + val)
				labels.add(val)
				off_Label.add(int(i.op_str, 16))
				if int(i.op_str, 16) not in offsets:
					if str(hex(int(i.op_str, 16))) not in off_PossibleBad:
						off_PossibleBad.add(str(hex(int(i.op_str, 16))))		
	end= time.time()
	print("\t\t[-] loop 1 ", end-start)
	start = time.time()
	
	#this is only used one place??? just have it be checked there. - comment out - save in case problems.
	# for labOff in off_Label:
	# 	if labOff not in offsets:
	# 		# print ("bad " + str(hex(labOff)))
	# 		if str(hex(labOff)) not in off_PossibleBad:
	# 			off_PossibleBad.add((str(hex(labOff))))
	
	end= time.time()
	print("\t\t[-] loop 2 ",end-start)
	start= time.time()
	dprint2 ("possible bad label offsets", off_PossibleBad)
	# t=0
	# ans=0
	# total=0
	# for each in startAdd:
	# 	try:
	# 		ans=int(startAdd[t+1]) - int(each)
	# 		bytesPerLine.append(ans)
	# 		total+=ans
	# 	except:
	# 		ans2= hex(len(data)-total)
	# 		bytesPerLine.append(int(ans2,16))
	# 	t+=1
	# cnt=0

	end= time.time()
	print("\t\t[-] loop 3 ", end-start)
	
	start= time.time()

	# t=0
	# for i in callCS.disasm(CODED3, address): 
	# 	ans= binaryToStr(CODED3[cnt:cnt+bytesPerLine[t]]) #+ " " + str(t) + "\n"
	# 	res=""
	# 	for y in CODED3[cnt:cnt+bytesPerLine[t]]:
	# 		zz=show1(y) 
	# 		old="nope"
	# 		if ((y > 31) & (y < 127)):
	# 			try: 
	# 				zz=int(zz,16)
	# 				zz = chr(zz)
	# 			except:
	# 				zz = chr(zz)
	# 		else:
	# 			zz="."
	# 		old=zz
	# 		res += zz # stripWhite(zz)#chr(zz)
	# 	asciiPerLine.append(res)
	# 	bytesEachLine.append(ans)
	# 	cnt+=bytesPerLine[t]
	# 	t+=1	
	# t=0
	# end= time.time()
	print("\t\t[-] loop 4 ", end-start)
	
	start= time.time()
	callCS.skipdata = True
	sizeShell=len(CODED2)
	pOp_str= pMnemonic=val=""
	t=prev=pAddress=0
	###this is it!
	for i in callCS.disasm(CODED2, address):
		val_b=i.mnemonic + " " + i.op_str 
		num_bytes=0
		val_d=val_c=""
		# if CheckingForDB:    # CheckingForDB=False
		# 	num_bytes=1   
		# 	val_b, num_bytes =checkForValidAddress2(hex(int(i.address)),i.mnemonic, i.op_str, sizeShell, off_PossibleBad,data,num_bytes)
		if t>0:
			if CheckingForDB:    # CheckingForDB=False
				num_bytes= 1
			#current here -- do not use prev
				val_b, num_bytes =checkForValidAddress2(hex(int(i.address)),i.mnemonic, i.op_str, sizeShell, off_PossibleBad,data,num_bytes)
			
			if mode=="ascii":
				# val =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(hex(int(i.address)), val_b, val_c, val_d))
				## secret sauce
				val=('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(hex((pAddress)), prev, binaryToStr(m[o].rawData2[pAddress:i.address]), toString(m[o].rawData2[pAddress:i.address])))
				addDis(pAddress, prev, pMnemonic, pOp_str,"main5")
				print ("prev", prev)
			else:
				# val =  hex(int(i.address)) + ":\t" + i.mnemonic + " " + i.op_str+"\n"
				val=('{:<10s} {:<35s}\n'.format(hex((pAddress)), val_b))
				addDis(pAddress, prev, pMnemonic, pOp_str,"main6")
			####ADD COMMENTS
			if sBy.comments[pAddress] !="":
				# val_b=sBy.comments[int(hex(int(i.address)),16)]
				# val_b=sBy.comments[int(hex(int(pAddress)),16)]
				val_b2=sBy.comments[pAddress]
				val_comment =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(nada, val_b2, nada, nada))
				val+=val_comment
			#### ADD COMENTS END
			truth,res=checkForLabel( hex(int(pAddress)),labels)
			if truth:
				val=res+val
			if re.match( r'\bjmp\b|\bje\b|\bjne\b|\bjg\b|\bjge\b|\bja\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bret\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', pMnemonic, re.M|re.I):
				val=val+"\n"

			############Stack strings begin
			try:
				# cur=i.address
				cur=pAddress
				# print (hex(sBy.pushStringEnd[cur]), add, "pushending")
				if (sBy.pushStringEnd[cur]-2) == cur:
					# dprint2 ("push match", sBy.pushStringValue[cur])
					msg="; "+sBy.pushStringValue[cur] + " - Stack string"
					newVal =('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format("", msg, nada, nada))
					val= newVal+val
					# dprint2 (val)
			except Exception as e:
				# print ("weird error", e)
				pass
		pMnemonic= i.mnemonic
		pOp_str= i.op_str 
		prev=val_b
		pAddress=i.address
		val5.append(val)
		t+=1
	val=('{:<10s} {:<35s} {:<26s}{:<10s}\n'.format(hex((pAddress)),"*"+ prev, binaryToStr(CODED2[pAddress:len(CODED2)]), toString(CODED2[pAddress:len(CODED2)])))
	truth,res=checkForLabel( hex(int(pAddress)),labels)
	if truth:
		val=res+val
	val5.append(val)
	addDis(pAddress, prev, pMnemonic, pOp_str,"main6")

	end= time.time()
	print("\t\t[-] loop 5 ", end-start)
	returnString="".join(val5)

	# dprint2 ("off_PossibleBad")
	# dprint2 (off_PossibleBad)
	
	disHereShell_end = time.time()
	return returnString

def disHereShell(data,offset, end, mode, CheckingForDB, bit, caller=None): #current good 1/8/2022
	bprint ("------------dshell", len(data),hex(offset), hex(end), "caller: ", caller)
	global labels
	global offsets
	global off_Label
	global off_PossibleBad
	global bit32
	global o

	disHereShell_start = time.time()
	
	# printAllsByRange(offset,end)
	# dprint2 ("dis: dishereshell - range  "  + str(hex(offset)) + " " + str(hex(end)))
	# dprint2(binaryToStr(data[offset:end]))
	# dprint2(binaryToStr(data))
	callCS = cs
	if(bit32):
		callCS = cs
	else:
		callCS = cs64
	callCS.skipdata = True
	callCS.skipdata_setup = ("db", None, None)
	CODED2=data[offset:end]
	val =""
	start = time.time()
	
	start = time.time()
	for i in callCS.disasm(CODED2, offset):
		offsets.add((int(i.address)))
		if re.match( r'\bcall\b|\bjmp\b|\bje\b|\bjne\b|\bja\b|\bjg\b|\bjge\b|\bjl\b|\bjle\b|\bjb\b|\bjbe\b|\bjo\b|\bjno\b|\bjz\b|\bjnz\b|\bjs\b|\bjns\b|\bjcxz\b|\bjrcxz\b|\bjecxz\b|\bloop\b|\bloopcc\b|\bloope\b|\bloopne\b|\bloopnz\b|\bloopz\b|\bjnae\b|\bjc\b|\bjnb\b|\bjae\b|\bjnc\b|\bjna\b|\bjnbe\b|\bjnge\b|\bjnl\b|\bjng\b|\bjnle\b|\bjp\b|\bjpe\b|\bjnp\b|\bjpo\b', i.mnemonic, re.M|re.I):	
			val=i.op_str
			if re.match( "^[0-9][x]*[A-Fa-f0-9 -]*",val, re.M|re.I):
				if "x" not in val:
					val="0x"+val
				labels.add(val)
				off_Label.add(int(i.op_str, 16))
				if int(i.op_str, 16) not in offsets:
					off_PossibleBad.add(i.op_str)		
	end= time.time()
	# print("\t\t[-] loop 1 ", end-start)
	start = time.time()

	sizeShell=len(CODED2)
	for i in callCS.disasm(CODED2, offset): 
		val_b, num_bytes =checkForValidAddress2(hex(int(i.address)),i.mnemonic, i.op_str, sizeShell, off_PossibleBad,data,i.size)
		addDis(i.address, i.mnemonic + " " + i.op_str, i.mnemonic, i.op_str,"main5")
	end= time.time()
	# print("\t\t[-] loop 5 ", end-start)
	disHereShell_end = time.time()
	# print ("\t[*]disHereShell:", disHereShell_end- disHereShell_start)
	return ""

def disHereAnalysisOlder(data,offset, end, mode, CheckingForDB): #origianl mostly unedited
	global labels
	global offsets
	global off_Label
	global off_PossibleBad
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
		offsets.add((int(i.address)))
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

				# labels.add(val)
				# print  ("5 appending label ", val, hex(t))
				# print (i.mnemonic, i.op_str)
				# off_Label.append(int(i.op_str, 16))
		t+=1

	current=0
	for i in cs.disasm(CODED3, address):
		if current>0:
			nextAd=sadd1
			nextAdd.append(nextAd)
		sadd1=int(i.address )

		startAdd.append(int(sadd1))
		current+=1

	for labOff in off_Label:
		if labOff not in offsets:
			# print ("bad " + str(hex(labOff)))
			if str(hex(labOff)) not in off_PossibleBad:
				off_PossibleBad.append((str(hex(labOff))))
				# modifysByRange(data, labOff,labOff+1,"d")
	dprint2 (off_PossibleBad)
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
			val_b, num_bytes =checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, off_PossibleBad,data,num_bytes)
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


def disHereAnalysis(data,offset, end, mode, CheckingForDB): #
	bprint ("------------dAnalysis", len(data),hex(offset), hex(end))
	global offsets
	global off_PossibleBad
	# dprint2 ("disHereAnalysis - range  "  + str(offset) + " " + str(end))
	global o
	CODED3=data[offset:end]
	sizeShell=len(CODED3)

	t=0
	for i in cs.disasm(CODED3, offset):
		offsets.add((int(i.address)))
		val_a=hex(int(i.address))#"\t"#\t"
		val_b1=i.mnemonic
		val_b2=i.op_str
		val_b, num_bytes =checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, off_PossibleBad,data,i.size)
		t+=1

def disHereAnalysis2(data,offset, end, mode, CheckingForDB): #
	global labels
	global offsets
	global off_Label
	global off_PossibleBad
	dprint2 ("disHereAnalysis - range  "  + str(offset) + " " + str(end))
	global o
	address=offset
	CODED2=data[offset:end]
	val =""
	startAdd=[]
	nextAdd=[]
	bytesPerLine=[]
	bytesEachLine=[]
	CODED3 = CODED2
	sizeShell=len(CODED2)

	current=0
	for i in cs.disasm(CODED3, address):
		offsets.add((int(i.address)))
		if (int(i.address)) not in offsets:
			if str(hex((int(i.address)))) not in off_PossibleBad:
				off_PossibleBad.add(hex((int(i.address))))
		if current>0:
			nextAd=sadd1
			nextAdd.append(nextAd)
		sadd1=int(i.address )
		startAdd.append(int(sadd1))
		current+=1

	cnt=t=ans=0
	for each in startAdd:
		try:
			ans=int(startAdd[t+1]) - int(each)
			bytesPerLine.append(ans)
		except:
			ans2= hex(len(data)-t)
			bytesPerLine.append(int(ans2,16))
		ans= binaryToStr(CODED3[cnt:cnt+bytesPerLine[t]]) #+ " " + str(t) + "\n"
		bytesEachLine.append(ans)
		cnt+=bytesPerLine[t]
		t+=1
	
	t=0
	for i in cs.disasm(CODED2, address):
		add = hex(int(i.address))
		addb = hex(int(i.address))
		add2 = str(add)
		val_a=addb#"\t"#\t"
		val_b=i.mnemonic + " " + i.op_str 
		val_b1=i.mnemonic
		val_b2=i.op_str
		num_bytes=0
		val_c= bytesEachLine[t] 
		if CheckingForDB:
			try:
				num_bytes=int(len(val_c)/4)
			except:
				num_bytes=1
			val_b, num_bytes =checkForValidAddress2(val_a,val_b1, val_b2, sizeShell, off_PossibleBad,data,num_bytes)
		truth,res=checkForLabel(addb,labels)
		while (num_bytes>0):	
			if num_bytes>0:
				val, num_bytes,val_c =makeDBforUnknownBytes(num_bytes, val_c, addb)
				truth,res=checkForLabel(addb,labels)

# urnString
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


def modifysByRangeUser():
	print ("Type x to exit")
	global sBy
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
			for x in sBy.bytesType:
				if (t>=start) and (t < end):
					sBy.bytesType[t]=BytesBool
					# dprint2("changing value @ " + str(t))
				t+=1

		print (sBy.bytesType)


def modifysByRange(data, start,end, dataType, mode=None):  # 1/8/2002
	# print ("modRange ", hex(start),hex(end),dataType, mode)
	global sBy
	BytesBool=False
	t=0
	if dataType=="d":
		BytesBool=False
	if dataType=="i":
		BytesBool=True

	if dataType=="d":
		pass
		# dprint2 ("magic")
		# out=disHereCheck(data[start:end])
		# dprint2(out)
	for x in sBy.bytesType:
		if (t>=start) and (t < end):
			# print ("before", sBy.bytesType[t])
			sBy.bytesType[t]=BytesBool
# 
			# print("changing value @ " + str(hex(t)), "\t\t", mode)
			# print (sBy.bytesType[t], " value: ", hex(sBy.values[t]))
			if BytesBool:
				sBy.boolspecial[t]=False
		t+=1
	
	if mode=="findAna":
		patternMatch=b"\x00"
		###### special check to make sure it doesn't overwrite jmps/calls
		if b'\xeb' in data[end-4:end] and BytesBool==False:
			patternMatch=b'\xeb'
		elif b'\xe9' in data[end-4:end] and BytesBool==False:
			patternMatch=b'\xe9'
		else:
			return
		# print ("found an eb!!!", BytesBool)
		start1=0
		result1=0
		while True:
			start1 = data[end-4:end].find(patternMatch , start1)

			if start1 !=-1:
				# print ("got a start", start1, hex(end-start1))
				result1=end-start1
			if start1 == -1:
				break
			else:
				start1 += len(patternMatch)
		# print ("res", hex(result1))
		t=result1
		for x in sBy.bytesType[result1:end]:
		# if (t>=start) and (t < end):
			# print ("before", sBy.bytesType[t])
			sBy.bytesType[t]=True
			# print("Special: changing value @ " + str(hex(t)))
			# print (sBy.bytesType[t], " value: ", hex(sBy.values[t]))
			t+=1


def modifysBySpecial(data, start,end, dataType):
	dprint2 ("modRangeSpecial ", hex(start),hex(end),dataType)
	global sBy
	BytesBool=False
	t=0
	spec=""
	if dataType=="al":
		spec="align"
	if dataType=="ff":
		spec="ff"

	for x in sBy.bytesType:
		if (t>=start) and (t < end):
			dprint2 ("before", sBy.specialVal[t])
			sBy.specialVal[t]=spec
			sBy.specialStart[t]=start
			sBy.specialEnd[t]=end
			sBy.boolspecial[t]=True
			dprint2("changing value align @ " + str(hex(t)))
			dprint2 (sBy.specialVal[t], " value: ", hex(sBy.values[t]))
			dprint2(sBy.boolspecial[t], hex(sBy.specialStart[t]), hex(sBy.specialEnd[t]) )
		t+=1

	# dprint2 (sBy.bytesType)
def modifyStringsRange(start,end, dataType, word):
	dprint2 ("modStrings " )
	dprint2 (hex(start),hex(end),dataType)
	global sBy
	BytesBool=False
	t=0
	if dataType=="ns":
		BytesBool=False
	if dataType=="s":
		BytesBool=True
	for x in sBy.bytesType:
		if (t>=start) and (t < end):
			# dprint2 (sBy.strings[t])
			sBy.strings[t]=BytesBool
			sBy.stringsStart[t]=(tuple((start, end-start)))
			sBy.stringsValue[t]=word
			dprint2("changing Strings value @ " + str(hex(t)))
			dprint2 (sBy.strings[t], " value: ", hex(sBy.values[t]))
			dprint2 (hex(t))
			# dprint2 (sBy.stringsValue[t])

			# dprint2 (hex(sBy.stringsStart[t]), " value: ", hex(sBy.values[t]))
			x,y=sBy.stringsStart[t]
			dprint2 (x,y)
		t+=1
	# dprint2 (sBy.bytesType)

def modifyPushStringsRange(start,end, dataType, word):
	dprint2 ("modStringPush " )
	# dprint2 (hex(start),hex(end),datfaType)
	global sBy
	BytesBool=False
	t=0
	if dataType=="ns":
		BytesBool=False
	if dataType=="s":
		BytesBool=True
	for x in sBy.bytesType:
		if (t>=start) and (t < end):
			# dprint2 (sBy.strings[t])
			sBy.strings[t]=False
			sBy.stringsStart[t]=(tuple((0, 0)))
			sBy.stringsValue[t]=""
			sBy.pushStringEnd[t]= end
			sBy.pushStringValue[t]=word
			sBy.boolPushString[t]=BytesBool
			dprint2("changing StringsPush value @ " + str(hex(t)))

			dprint2 (sBy.boolPushString[t], " value: ", hex(sBy.values[t]))
			dprint2 ("end", sBy.pushStringEnd[t])
			dprint2 (hex(t))
			# dprint2 (sBy.stringsValue[t])

			# dprint2 (hex(sBy.stringsStart[t]), " value: ", hex(sBy.values[t]))
			x,y=sBy.stringsStart[t]
			dprint2 (x,y)
		t+=1
	# dprint2 (sBy.bytesType)
def printAllsBy():
	dprint2("printAllsBy")
	t=0
	out=""
	d=0
	for off in sBy.offsets:
		out+= (str(hex(off )) + ": " + str(sBy.bytesType[t])) + " ("+str(hex(sBy.values[t])) +")\t"
		t+=1
		d+=1
		if d==5:
			out+="\n"
			d=0
	dprint2 (out)


def printAllsByStrings():
	dprint2("printAllsByStrings")
	t=0
	out=""
	d=0
	for off in sBy.offsets:
		sVal=""
		if sBy.strings[t]:
			sVal="ST"
		else:
			sVal="NO"
		out+= str(hex(off )) + ": " + sVal + " ("+str(hex(sBy.values[t])) +")\t"
		t+=1
		d+=1
		if d==5:
			out+="\n"
			d=0
	dprint2 (out)

def printAllsByRange(start,end):
	dprint2("printAllsBy " + str(hex(start)) + " "  + str(hex(end) ))
	t=0
	out=""
	d=0
	t=0
	for off in sBy.offsets:
		if (t >= start) and (t<end):
			out+= (str(hex(off )) + ": " + str(sBy.bytesType[t])) + " ("+str(hex(sBy.values[t])) +")\t"
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





def preSyscalDiscoverold(startingAddress, targetAddress, linesGoBack, caller=None):
	global filename
	global m
	global sBy
	bprint ("preSyscalDiscovery", caller)
	
	# mBool[o].bDoFindStrings2 =	mBool[o].bDoFindStrings 

	# mBool[o].bDoFindStrings2 = False
	clearTempDis()
	shellBytes=m[o].rawData2
	# print (hex(len(shellBytes)), "myshell")
	
	# print (len(shellBytes), "shellbytes")
	i=startingAddress
	for x in shellBytes:
		sBy.offsets.append(i)
		sBy.values.append(x)
		sBy.bytesType.append(True) # True = instructions
		sBy.strings.append(False)
		sBy.stringsStart.append(0xffffffff)
		sBy.stringsValue.append("")
		sBy.pushStringEnd.append(-1)
		sBy.pushStringValue.append("")
		sBy.boolPushString.append(False)
		sBy.specialVal.append("")
		sBy.boolspecial.append(False)
		sBy.specialStart.append(0)
		sBy.specialEnd.append(0)
		sBy.comments.append("")
		i+=1
	if mBool[o].bDoFindStrings and not mBool[o].bPreSysDisDone:
		findStrings(shellBytes,3)
		findStringsWide(shellBytes,3)
		findPushAsciiMixed(shellBytes,3)
	anaFindFF(shellBytes)

	if not mBool[o].bPreSysDisDone:
		out=findRange(shellBytes, startingAddress, len(sBy.offsets)-1, "preSyscalDiscovery: " + caller)  #1st time helps do corrections
		out=findRange(shellBytes, startingAddress, len(sBy.offsets)-1, "preSyscalDiscovery: " + caller)  #1st time helps do corrections
		mBool[o].bPreSysDisDone = True


	# anaFindFF(shellBytes)

	# l1, l2=createDisassemblyLists()
	# print (l2)
	# saveDB()

	
	

	tl1=sBy.shAddresses
	tl2=sBy.shDisassemblyLine
	# clearDisassemblyBytesClass()

	# print ("checking class of temp addresses ORIGINAL")
	
	# t=0
	# for x in sBy.shAddresses:
	# 	print(t, type(x), x)
	# 	t+=1
	# print (tl1)
	# truth, tl1, tl2= findTargetAddressReturnPrior(targetAddress, linesGoBack, l1, l2)

	# print("\tsizel1 ", len(l1),len(l2))
	# print (l1)
	# input()

	# print ("checking class of temp addresses")

	# t=0
	# for x in tl1:
	# 	print(t, type(x), x)
	# 	t+=1
	if len(tl1)>0:
		return True, tl1, tl2, tl1, tl2
	else:
		return False, tl1, tl2, tl1, tl2
	return truth, tl1, tl2, l1,l2


def preSyscalDiscovery(startingAddress, targetAddress, linesGoBack, caller=None):
	global shellSizeLimit
	shellBytes=m[o].rawData2
	silent=None
	if not mBool[o].bPreSysDisDone:
		clearDisassemblyBytesClass()
	# print ("takeBytes:", hex(startingAddress))

	# print ("inside preSyscalDiscovery now")
	# shellSizeLimit=0
	shellSize=len(shellBytes)/1000
	if shellSize>  shellSizeLimit or mBool[o].ignoreDisDiscovery:
		print ("Too big")
		print ("preSyscalDiscovery size1", shellSize )
		return False, [], [], [],[]

	# print ("preSyscalDiscovery size2", shellSize )
	global sBy
	global shellEntry

	takeBytesS = time.time()

	startingAddress=0
	i=startingAddress
	for x in shellBytes:
		sBy.offsets.append(i)
		sBy.values.append(x)
		# sBy.instructions.append(True)
		# sBy.data.append(False)
		sBy.bytesType.append(True) # True = instructions
		sBy.strings.append(False)
		sBy.stringsStart.append(0xffffffff)
		sBy.stringsValue.append("")
		sBy.pushStringEnd.append(-1)
		sBy.pushStringValue.append("")
		sBy.boolPushString.append(False)
		sBy.specialVal.append("")
		sBy.boolspecial.append(False)
		sBy.specialStart.append(0)
		sBy.specialEnd.append(0)
		sBy.comments.append("")
			
		i+=1

	start = time.time()
	if mBool[o].bDoFindStrings and not mBool[o].bPreSysDisDone:
		# import sharem
		dprint4 ("\nfinding strings")
		findStrings(shellBytes,3)
		findStringsWide(shellBytes,3)
		findPushAsciiMixed(shellBytes,3)
		dprint4 ("\nfound strings")

	end = time.time()
	bprint ("\n[*] Find strings", end-start)
	
	start = time.time()
	# anaFindFF(shellBytes)
	# addComments()
	end = time.time()
	bprint ("\n[*] anaFindFF", end-start)

	if not mBool[o].bPreSysDisDone:
		start = time.time()
		out=findRange(shellBytes, startingAddress,len(sBy.offsets)-1, "takeBytes")  #1st time helps do corrections
		end = time.time()
		bprint ("\n[*] findrange #1", end-start)

		anaFindFF(shellBytes)
		clearTempDis()   # we must call this function before making new diassembly
		

		start2 = time.time()
		out2=findRange(shellBytes, startingAddress,len(sBy.offsets)-1, "takeBytes") # makes sure all corrections fully implemented # this creates final disassembly
		end = time.time()
		bprint ("\n\t[*] findrange 2", end-start2)
		mBool[o].bPreSysDisDone = True
		# print ("setting bPreSysDisDone true")

	bprint ("\n\t[*] TakeBytes:", end-takeBytesS)
	# print ("**Sizes:  ")
	# print("\t\tlabels, size:",len(labels))
	# print("\t\tofsets, size:",len(offsets))
	# print("\t\tlabel offsets, size:",len(off_Label))
	# print("\t\tpossiblebadlabel offsets, size:",len(off_PossibleBad))

	# printAllsBy()
	# print ("printing final\n")
	# allowPrint()
	colorama.init()
	disassembly, disassemblyC =createDisassemblyLists(True, "preSyscalDiscovery")
	# dontPrint()
	t=0
	assembly=binaryToText(shellBytes)   # this creates the string literal, raw hex, etc.
	tl1=sBy.shAddresses
	tl2=sBy.shDisassemblyLine

	if len(tl1)>0:
		return True, tl1, tl2, tl1, tl2
	else:
		return False, tl1, tl2, tl1, tl2
	return truth, tl1, tl2, l1,l2


def takeBytes(shellBytes,startingAddress, silent=None):
	# bprint ("takeBytes:", hex(startingAddress))
	global sBy
	global shellEntry
	global gDisassemblyText
	takeBytesS = time.time()
	startingAddress=0
	i=startingAddress

	# bprint  ("mBool[o].bPreSysDisDone",  mBool[o].bPreSysDisDone)

	if not mBool[o].bPreSysDisDone:
		print ("takeBytes: still entering it???")
		clearDisassemblyBytesClass()
		for x in shellBytes:
			sBy.offsets.append(i)
			sBy.values.append(x)
			# sBy.instructions.append(True)
			# sBy.data.append(False)
			sBy.bytesType.append(True) # True = instructions
			sBy.strings.append(False)
			sBy.stringsStart.append(0xffffffff)
			sBy.stringsValue.append("")
			sBy.pushStringEnd.append(-1)
			sBy.pushStringValue.append("")
			sBy.boolPushString.append(False)
			sBy.specialVal.append("")
			sBy.boolspecial.append(False)
			sBy.specialStart.append(0)
			sBy.specialEnd.append(0)
			sBy.comments.append("")
				
			i+=1

		start = time.time()
		if mBool[o].bDoFindStrings:
			# import sharem
			dprint4 ("\nfinding strings")
			findStrings(shellBytes,3)
			findStringsWide(shellBytes,3)
			findPushAsciiMixed(shellBytes,3)
			dprint4 ("\nfound strings")

		end = time.time()
		bprint ("\n[*] Find strings", end-start)
		
		start = time.time()
		anaFindFF(shellBytes)
		# addComments()
		end = time.time()
		bprint ("\n[*] anaFindFF", end-start)

		start = time.time()
		out=findRange(shellBytes, startingAddress,len(sBy.offsets)-1, "takeBytes")  #1st time helps do corrections
		end = time.time()
		bprint ("\n[*] findrange #1b", end-start)

		anaFindFF(shellBytes)
		clearTempDis()   # we must call this function before making new diassembly
		

		start2 = time.time()
		out2=findRange(shellBytes, startingAddress,len(sBy.offsets)-1, "takeBytes") # makes sure all corrections fully implemented # this creates final disassembly
		end = time.time()
		bprint ("\n\t[*] findrange 2b", end-start2)

		bprint ("\n\t[*] TakeBytes:", end-takeBytesS)
	# print ("**Sizes:  ")
	# print("\t\tlabels, size:",len(labels))
	# print("\t\tofsets, size:",len(offsets))
	# print("\t\tlabel offsets, size:",len(off_Label))
	# print("\t\tpossiblebadlabel offsets, size:",len(off_PossibleBad))

	# printAllsBy()
	# print ("printing final\n")
	# allowPrint()
	colorama.init()
	# print ("final!!!!!")
	disassembly, disassemblyC=createDisassemblyLists(True,"final")
	gDisassemblyText =disassemblyC
	print (disassemblyC)
	# print (disassembly)
	# dontPrint()
	t=0

	assembly=binaryToText(shellBytes)   # this creates the string literal, raw hex, etc.

	return disassemblyC, disassembly,assembly

def regenerateDisassemblyForPrint():
	global gDisassemblyText
	disassembly, disassemblyC=createDisassemblyLists(True,"final")
	gDisassemblyText =disassemblyC
def addComments():
	# print("addcomments:", hex(len(sBy.comments)), hex(len(sBy.bytesType)))

	# print (loggedList)
	for each in loggedList:
		api=each[0]
		apiAddress=int(each[1],16)
		# print (hex(apiAddress), 42000000, each[1])
		apiAddress=apiAddress-0x42000000
		# print (hex(apiAddress))
		sBy.comments[apiAddress]=mag+"; call to " + api +res +" "
		# print (api, apiAddress, each[1])
# 	input()
# 1107296317 


# 42000000 
# 4200003d
	comC=mag
	for item in m[o].save_PEB_info:
		# print("ITEMS HERE")
		# print(item)
		tib=item[5]
		sBy.comments[int(tib,16)] = comC + "; load TIB" + res2 + ""
		ldr=item[6]
		sBy.comments[int(ldr,16)] = comC + "; load PEB_LDR_DATA LoaderData" + res2 + ""
		mods=item[7]
		modAdd=mods[0]
		modText=mods[1]
		# sBy.comments[int(mods,16)] = "; LIST_ENTRY InMemoryOrderModuleList"
		sBy.comments[int(modAdd,16)] = comC + "; "+ modText + res2 + ""

		adv=item[8]
		for each in adv:
			try:
				if each != -1:
					sBy.comments[int(each,16)] = comC + "; advancing DLL flink" + res2 + ""
			except:
				pass
				# print (type(each))
				# print (each)
	for item in m[o].save_PushRet_info:

		#(495, 4, 'rawHex', -1, 0, ('0x1ef', 'ebx'), '0x1f0')
		# print ("sBy.comments,",len(sBy.comments))
		push=item[5]
		pushOffset=push[0]
		pushReg=push[1]
		retOffset=item[6]
		sBy.comments[int(pushOffset,0)] = comC + "; pushing return address " + res2 + ""
		sBy.comments[int(retOffset,0)] =  comC +"; returning to " + pushReg + res2 + ""


	for item in m[o].save_Callpop_info:
		call_offset = item[0]
		pop_offset=item[5]
		# sBy.comments[int(call_offset,16)] = " ; using call for GetPC"
		sBy.comments[int(pop_offset,16)] = comC +" ; GetPC" +res2+""

	for item in m[o].save_FSTENV_info:
		FPU_offset = item[5]
		FSTENV_offset = item[6]
		sBy.comments[int(FPU_offset,16)] =  comC +" ; floating point to set up GetPC" + res2 + ""
		sBy.comments[int(FSTENV_offset,16)] =  comC +" ; GetPC" + res2 + ""

	for item in m[o].save_Heaven_info:
		heaven_offset = item[5]
		pushOffset=item[6]
		destLocation=item[7]
		sBy.comments[int(heaven_offset,16)]=  comC +" ; invoking Heaven's Gate technique" + res2 + ""
		try:
			sBy.comments[(pushOffset)]= comC + " ; Heaven's gate destination address: " + str(destLocation) + res2 + ""
		except:
			sBy.comments[int(pushOffset,16)]= comC + " ; Heaven's gate destination address: " + str(destLocation) + res2 + ""
	for item in m[o].save_Egg_info:
		eax = item[5]
		c0_offset = item[6]
		print (hex(int(c0_offset,16)), hex(len(sBy.comments)))
		try:
			sBy.comments[int(c0_offset	,16)] = comC + " ; Calling Windows syscall - value: " + eax  + res2 + ""
		except:
			pass
	cur=sBy.comments[shellEntry]
	sBy.comments[shellEntry] = cur + comC+" ; ***Shellcode Entry Point, offset " + str(hex(shellEntry)) +"***" +res2+""
	
	cur=sBy.comments[shellEntry-1]

	# sBy.comments[shellEntry-1] =  cur + "\n\n\t\t[*] Shellcode Entry Point\n" 
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

#findrange
def findRange(data, startingAddress, end2, caller=None):

	global bit32
	
	global shellEntry
	if bit32:
		bit=32
	else:
		bit=64
	current=0

	start=startingAddress
	current=startingAddress
	max=len(sBy.bytesType)-1
	dprint2 ("fr size: ", hex(max))
	finalPrint0=""

	dprint2("findRange start**", hex(startingAddress))
	distance=0

	end =len(sBy.bytesType)-1
	fr1 = time.time()

	# print ("disAnalysisDone", mBool[o].disAnalysisDone, "caller", caller)
	if not mBool[o].disAnalysisDone and "preSyscalDiscovery" in caller:
		print ("inside disana")
		disHereAnalysis(data, startingAddress, end, "ascii", True)
		mBool[o].disAnalysisDone=True
	elif caller=="takeBytes":
		disHereAnalysis(data, startingAddress, end, "ascii", True)

	fr_end = time.time()
	bprint ("[*] disHereAnalysis", fr_end-fr1)

	# frHid = time.time()
	# print ("\t\t", red+"beforeHidden"+whi)
	# print ("bAnaHiddenCallsDone1", mBool[o].bAnaHiddenCallsDone)
	# if not mBool[o].bAnaHiddenCallsDone and  "preSyscalDiscovery" in caller:
	# 	print ("inside hc")
	# 	analysisFindHiddenCalls(data, startingAddress, caller+" PS")
	# elif caller=="takeBytes":
	# 	print ("inside hctb")

	# 	bprint ("callerTakeBytes hidden")
	# 	analysisFindHiddenCalls(data, startingAddress, caller)
	# fr_Hidend = time.time()
	# print ("\t\t", red+"afterHidden"+whi)
	# bprint ("\n\t[*] analysisFindHiddenCalls 1", fr_Hidend-frHid)

	fr1 = time.time()
	if not mBool[o].bAnaConvertBytesDone and  "preSyscalDiscovery" in caller:
		analysisConvertBytes(data, startingAddress)
		# bprint ("callerpresyscall CBytes")
	elif caller=="takeBytes":
		analysisConvertBytes(data, startingAddress)
		# bprint ("callerTakeBytes CBytes")

	fr_end = time.time()
	bprint ("[*] analysisConvertBytes", fr_end-fr1)

	# fr1 = time.time()

	# analysisFindHiddenCalls(data, startingAddress)
	# fr_end = time.time()
	# print ("[*] analysisFindHiddenCalls", fr_end-fr1)
	
	fr1 = time.time()
	# print ("bAnaHiddenCallsDone2", mBool[o].bAnaHiddenCallsDone)
	if not mBool[o].bAnaHiddenCallsDone and "preSyscalDiscovery" in caller:
		# print ("inside hc")
		analysisFindHiddenCalls(data, startingAddress, caller + " PS")
	elif caller=="takeBytes" and mBool[o].bDoFindHiddenCalls:
		analysisFindHiddenCalls(data, startingAddress, caller)
	fr_end = time.time()
	bprint ("\n\t[*] analysisFindHiddenCalls", fr_end-fr1)

	fr12 = time.time()
	shellEntryPassed=False
	# if mBool[o].bDoFindStrings:
	# 	anaFindStrings(data,startingAddress)
	# fr_end = time.time()
	# print ("[*] anaFindStrings", fr_end-fr12)

	shellEntryPassed=False
	if mBool[o].bDoFindStrings and not mBool[o].bAnaFindStrDone:
		anaFindStrings(data,startingAddress)
	fr_end = time.time()
	bprint ("\n\t[*] anaFindStrings", fr_end-fr12)

	finalPrint=""
	# dprint2 ("final disprint", len(finalPrint))

	s1 = time.time()
	s2 = time.time()
	inside_shell=s2-s1
	inside_MakeDB=s2-s1


	s1 = time.time()
	while current < max:
		start, current, distance, typeBytes = findRange2(current)
		# print ("fr:   start", hex(start), "current", hex(current), "end", hex(end))

		# dprint2 ("start+current+distance+both", hex(start), hex(current), hex(distance), hex(start+distance))
		if shellEntryPassed==False:
			if shellEntry != 0:
				# dprint2(start, 1)
				if current>shellEntry-1:
					newDis=shellEntry-current-1
					current=shellEntry
					distance=newDis
					shellEntryPassed=True
					# print("reset to ", current)
					# dprint2("reset to ", current)
					# print("new", hex(current), hex(distance))
					# finalPrint=""
					

				if current==shellEntry:
					shellEntryPassed=True
		finalPrint0=""
		dprint2 ("findrange: max: " + str(hex(max)),  "Current:  "+str(hex(current)))
		

		if max==current:
			current+=1
		dprint2("findrange:", binaryToStr(data[start:current]))
		
		if typeBytes:

			dprint2 ("above is instructions")

			dShell = time.time()

			res= (disHereShell(data, start, current, "ascii", True, bit, caller))
			dShellEnd=time.time()
			inside_shell+=dShellEnd-dShell
			finalPrint0+= res
			dprint2("adding ", len(res), "total", len(finalPrint))
			dprint2(res)

		if not typeBytes:
			dprint2 ("above is data")

			makeDB = time.time()

			res= (disHereMakeDB2(data, start, current, "ascii", True))
			makeDBEnd=time.time()
			inside_MakeDB+=makeDBEnd-makeDB
			finalPrint0+= res
			dprint2("adding ", len(res), "total", len(finalPrint))
			dprint2(res)

		# dprint2 (finalPrint0)
		finalPrint+=finalPrint0
		dprint2("big ", len(finalPrint0), "total", len(finalPrint))

		# analysisFindHiddenCalls(data, startingAddress)
	fr_end = time.time()
	bprint ("[*] inside dshell", inside_shell, caller)
	bprint ("[*] inside makeDB", inside_MakeDB, caller)
	bprint ("[*] big loop", fr_end-s1)
	
	# dprint2 ("final disprint", len(finalPrint))

	# dprint2 ("\n* * * * * * * * * * * * * * * * * * * * * * * * * * * * * *\n"+finalPrint)
	# dprint2 ("\n\n")
	# dprint2 (binaryToStr(data))
	# dp(finalPrint+str(hex(len(m[o].rawData2))))
	
	return finalPrint


def getNextBool(pattern,test):
	try:
		found=test.index(pattern)
	except:
		found=len(sBy.bytesType)-1

		pass
	# print  ("*", hex(found))
	return found


def findRange2(current):
	# print (sBy.bytesType)
	# print ("findRange2", hex(current))

	initialBool=sBy.bytesType[current]
	# print ("initialBool", initialBool)
	seeking=False
	if not initialBool:
		seeking = True
	# print ("seeking", seeking)
	# print ("sbytes size", len(sBy.bytesType[current:]))
	foundStop=getNextBool(seeking, sBy.bytesType[current:])

	foundStop+=current
	distance=foundStop-current

	if foundStop > len(m[o].rawData2):
		foundStop = len(m[o].rawData2)-1
	# print ("r: -end", hex(current), hex(foundStop), hex(distance), (initialBool))

	return current, foundStop, distance, initialBool



def findRange2222(current):
	# print("findrange2 ", hex(current))
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
	dprint2 ("size", len(sBy.bytesType))
	if sBy.bytesType[begin]==False:
		typeData="data"
		# dprint2 ("*********making data" )
	else:
		typeData="inst"
		# dprint2 ("********making inst")
	if typeData=="data":
		for x in sBy.bytesType:
			if t > current:
				if x == False: # until no longer false (i.e. NOT DATA)
					if first:
						start=current
					first=False
					typeBytes=False
					current=t 
				if x==True:
					current+=1
					print ("FIN: data done!")
					distance=current-start
					print ("r d-:",hex(start), hex(current), hex(distance), typeBytes)
					print ("returning", hex(start), hex(current), hex(distance), (typeBytes))

					return start, current, distance, typeBytes
			t+=1
	t=0
	if typeData=="inst":
		# dprint2 ("ins")
		for x in sBy.bytesType:
			if t > current:	
				if x == True:  # until no longer true (i.e. IS NOT INSTRUCTIONS)
					if first:
						start=current
					first=False
					typeBytes=True
					current=t 
				if x==False: # & inProgress:
					current+=1
					print("FIN: instructions done!")
					distance=current-start
					print ("r: i-",hex(start), hex(current), hex(distance), typeBytes)
					print ("returning", hex(start), hex(current), hex(distance), (typeBytes))

					return start, current, distance, typeBytes
			t+=1
	distance=current-start
	print ("r: -end", hex(start), hex(current), hex(distance), (typeBytes))
	return start, current, distance, typeBytes

def findRange2old(current):
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
	dprint2 ("size", len(sBy.bytesType))
	if sBy.bytesType[begin]==False:
		typeData="data"
		# dprint2 ("*********making data" )
	else:
		typeData="inst"
		# dprint2 ("********making inst")
	# if typeData=="data":
	for x in sBy.bytesType:

		if t > current and typeData == "data":
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
		if t > current and typeData == "inst":
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
	t=0


	# if typeData=="inst":
	# 	# dprint2 ("ins")
	# 	for x in sBy.bytesType:
	# 		if t > current:	
	# 			if x == True:  # until no longer true (i.e. IS NOT INSTRUCTIONS)
	# 				if first:
	# 					start=current
	# 				first=False
	# 				typeBytes=True
	# 				current=t 
	# 			if x==False: # & inProgress:
	# 				current+=1
	# 				dprint2("FIN: instructions done!")
	# 				distance=current-start
	# 				dprint2 ("r: i-",hex(start), hex(current), hex(distance), typeBytes)
	# 				return start, current, distance, typeBytes
	# 		t+=1
	distance=current-start
	dprint2 ("r: -end", hex(start), hex(current), hex(distance), (typeBytes))
	return start, current, distance, typeBytes

FindStrings=True

def anaFindStrings(data, startingAddress):
	# print ("anaFindStrings")
	# global FFInstructions
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp
	global minStrLen
	# bprint("\t\tinside anaFindStrings")
	# dprint2 (sharem.stringsTemp)
	OP_FF=b"\xff"
	mBool[o].bAnaFindStrDone=True

	for word,offset,distance  in stringsTemp:# and stringsTemp:
		dprint2 ("\t"+ str(word) + "\t" + str(hex(offset)) + "\t" + str(hex(distance))) 

		if goodString(data,word,6):
			modifysByRange(data, offset, offset+distance, "d", "anaFindStrings")
			modifyStringsRange(offset, offset+distance, "s", word)
			total=0			
			v=1
			w=0
			test=b"\xff"
			# while (test == OP_FF):
			# 	# dprint2(word, "2binaryToStrCheck", binaryToStr(data[offset+distance:offset+distance+v]))
			# 	test=(data[offset+distance+w:offset+distance+v])
			# 	test2=(data[offset+distance+w:offset+distance+v+1])
			# 	# dprint2 ("test2", len(test2), hex(offset+distance+w), hex(offset+distance+v+1))
			# 	if test==(OP_FF) and (test2 not in FFInstructions):
			# 		print ("ff gots one") # this just counts how many FF's there are that are not part of a more import instruciton'
			# 		print ("ff1")
			# 		total+=1
			# 	v+=1
			# 	w+=1
			# # dprint2 ("fftotal",total)
			# if total > 1:
			# 	modifysByRange(data, offset, offset+distance+total, "d", "anaFindStrings")

	##WIDE			
	# print ("wideStringsStart")	
	try:
		# print ("size stw", len(stringsTempWide))
		for word,offset,distance  in stringsTempWide:# and stringsTemp:
			# print (type(word), type(offset), type(distance))
			# print ("\t"+ str(word) + "\t" + str(hex(offset)) + "\t" + str(hex(distance))) 

			# dprint2 (word, offset, distance, "before modify range")
			# modifyStringsRange(offset, offset+distance, "s", word)
			# dprint2 (goodString(data,word,6),"goodstring", word)
			# if goodString(data,word,5):
			# print ("before good")
			if goodString(data,word,6):
				# print ("after good")
			
				modifysByRange(data, offset, offset+distance, "d", "anaFindStrings")
				modifyStringsRange(offset, offset+distance, "s", word)
				total=0			
			# 	v=1
			# 	w=0
			# ### start
			# 	test=b"\xff"
			# 	while (test == OP_FF):

			# 		# dprint2(word, "2binaryToStrCheck", binaryToStr(data[offset+distance:offset+distance+v]))
			# 		test=(data[offset+distance+w:offset+distance+v])
			# 		test2=(data[offset+distance+w:offset+distance+v+1])
			# 		# if test==(OP_FF) and (test2 != inc_esi):
			# 		# dprint2 ("test2", len(test2), hex(offset+distance+w), hex(offset+distance+v+1))
			# 		if test==(OP_FF) and (test2 not in FFInstructions):
			# 			# dprint2("gots one") # this just counts how many FF's there are that are not part of a more important instruciton'
			# 			dprint ("ff2")
			# 			total+=1
			# 		v+=1
			# 		w+=1
			# 	dprint2 ("fftotal",total)
			# 	if total > 1:
			# 		modifysByRange(data, offset, offset+distance+total, "d", "anaFindStrings")
	except Exception as e:
		print ("Exception")
		print (e)
		print(traceback.format_exc())
		# input()
		pass
	

	for word, offset, wordLength,instructionsLength in pushStringsTemp:
		try:
			dprint2 ("word", word, "starting offset:", hex(offset), "; ending offset:", hex(offset+instructionsLength))
		except:
			word="error"
			dprint2 ("word", word, "starting offset:", hex(offset), "; ending offset:", hex(offset+instructionsLength))
			dprint2 ("pushmixed error")
	

	distance=0

	# print ("bPushStackStrings")
	for word, offset, wordLength,instructionsLength in pushStringsTemp:
		# offset=ofset-2
		try:
			print ("word", word, "starting offset", hex(offset), "ending offset", hex(offset+instructionsLength))
		except:
			word="error"
			print ("pushmixed error2")
		distance=instructionsLength
		dprint2 ("instructionsLength", instructionsLength, type(instructionsLength))
		if goodString(data,word,6):
			dprint2 ("push mixed change", word, hex(offset), hex(offset+distance), hex(len(data)))
			modifysByRange(data, offset-2, offset+distance, "i", "anaFindStrings") # -2 is a correction
			modifyPushStringsRange(offset, offset+distance, "s", word)
			# total=0			
			# v=1
			# w=0
			# test=b"\xff"
			# while (test == OP_FF):
			# 	dprint2(word, "pushstrings", binaryToStr(data[offset+distance:offset+distance+v]))
			# 	test=(data[offset+distance+w:offset+distance+v])
			# 	test2=(data[offset+distance+w:offset+distance+v+1])
			# 	dprint2 ("test2", len(test2), hex(offset+distance+w), hex(offset+distance+v+1))
			# 	if test==(OP_FF) and (test2 not in FFInstructions):
			# 		dprint2("gots one PS") # this just counts how many FF's there are that are not part of a more import instruciton'
			# 		dprint ("ff3")
			# 		total+=1
			# 	v+=1
			# 	w+=1
			# dprint2 ("PS fftotal",total)
			# if total > 1:
			# 	modifysByRange(data, offset, offset+distance+total, "d","anaFindStrings")


	###$$$$$$$$$$$$$$$$$$4 END STUFF 
	
	if 1==3:  ####i think this just prints debugging info - nothing of consequence otherwise
		print  ("endStuffStrings???")
		current=0
		start=startingAddress
		max=len(sBy.bytesType)-1
		start, current, distance, typeBytes = findRange2(current)
		reset = False
		while current < max:
			if max==current:
				current+=1
			print(binaryToStr(data[start:current]))
			if not typeBytes:
				print ("AFS: above is data", hex(start))
				if sBy.strings[start]==True:
					xStart, ydis=sBy.stringsStart[start]
					print (hex(start))
					print ("AFS: strings ", hex(xStart), hex(ydis), sBy.stringsValue[start])
			start, current, distance, typeBytes = findRange2(current)
			##reset once done - do analysis again to catch any changes 
			if (current) == max and reset != True:
				reset=True
				print ("reset")
				current=0
		print (sBy.stringsValue)




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
			modifysByRange(data, offset, offset+distance+total, "d","anaFindFF")
			modifysBySpecial(data, offset, offset+distance+total, "ff")
			# modifyStringsRange(offset, offset+distance+total, "s", word)
		if total2 > 4:
			dprint2 (total2, "00Total2")
			modifysByRange(data, offset+4, offset+distance+total2, "d","anaFindFF")
			modifysBySpecial(data, offset+4, offset+distance+total2, "al")
			
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

	# print (binaryToStr(m[o].rawData2))
	shells=""
	for each in m[o].rawData2:
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

	# print (binaryToStr(m[o].rawData2))
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

	# print (binaryToStr(m[o].rawData2))
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

	print (binaryToStr(m[o].rawData2))
	shells=""

	encodeBytes=bytearray()
	for each in m[o].rawData2:
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

	print (binaryToStr(m[o].rawData2))
	encodeBytes=bytearray()
	for each in m[o].rawData2:
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

	print (binaryToStr(m[o].rawData2))
	encodeBytes=bytearray()
	t=0
	rawData3=m[o].rawData2
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
	ObtainAndExtractSections()
	print ("basic info")


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



def bramwellStart3():

	ObtainAndExtractSections()
	print ("basic info")



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
	print(giveLoadedModules("save"))
	print ("end InMem2")


	findEvilImports()
	print(showImports())

##### START
def init1():

	if(not rawHex):
		ObtainAndExtractSections()
	if (rawHex):#(rawBin == False) and not isPe: 
		rawBytes=readShellcode(filename) 
		m[o].rawData2=rawBytes


def init2(filename):
	# print("init2")
	global gName
	global rawData2
	if(not rawHex):
		ObtainAndExtractSections()
	if (rawHex):#(rawBin == False) and not isPe: 
		# print("in rawhex part")
		# print(filename)
		# print(filename[-4:])
		if(filename[-4:] == ".txt"): #don't need to call readShellcode if it is a binary file
			rawData2=readShellcode(filename) 

			# readRawData2=readShellcode(filename) 
			# newModule(o,readRawData2, gName+"--3")



# Extraction()

# starting()
# AustinStart()
# AustinTesting()


# bramwellStart()
# testing8Start()


# testing8Start()

def saveBinAscii():
	if not rawHex:
		print ("\nThis is for shellcode only.")
		return

	init2(filename)
	# print (binaryToStr(m[o].rawData2))
	if not os.path.exists(directory+'bins'):
		os.makedirs(directory+'bins')
	assembly=binaryToText(m[o].rawData2)
	newBin = open(directory+"bins\\"+filename[:-4]+".bin", "wb")
	newBin.write(m[o].rawData2)
	newBin.close()
	newDis = open(directory+"bins\\ascii-"+filename[:-4]+".txt", "w")
	print (directory+"bins\\ascii-"+filename[:-4]+".txt")
	print (directory+"bins\\"+filename[:-4]+".bin")
	newDis.write(assembly)
	newDis.close()

def bramwellEncodeDecodeWork(shellArg):
	global filename

		
	if rawBin == False:
		filename=shellArg
		rawBytes=readShellcode(shellArg) 

		m[o].rawData2=rawBytes
		# printBytes(rawBytes)
		# print (disHereShell(rawBytes, False, False, "ascii", True))




	print ("Sizem[o].rawData2", len(m[o].rawData2))
	rawBytes=m[o].rawData2
	print ("rawbytes class", type(rawBytes))
	encoded=encodeShellcode(m[o].rawData2)
	old=m[o].rawData2
	decoded=decodeShellcode(encoded)

	t=0
	# for x in range (1000):
	# 	encoded=encodeShellcodeProto(m[o].rawData2, 32, t, 55)
	# 	t+=1
	print ("new\n\n\n\n")
	r=encodeShellcodeProto(m[o].rawData2, 32,2,55)
	r=decodeShellcodeProto(r, 32,2,55)
	m[o].rawData2=r
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
		m[o].rawData2=new
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
	m[o].rawData2=new
	mode=""
	findAllPebSequences(mode)
	disassembly, disassemblyNoC, assemblyBytes=takeBytes(new,0)
	res=disassembly+assemblyBytes
	print ("decrypted disassembly")
	print (disassembly)
	if not os.path.exists(directory+'outputs'):
		os.makedirs(directory+'outputs')
	print (directory+"outputs\\"+filename[:-4]+".bin")
	newBin = open(directory+"outputs\\decrypted-"+filename[:-4]+".bin", "wb")
	newBin.write(rawBytes)
	newBin.close()
	newDis = open(directory+"outputs\\decrypted-"+filename[:-4]+"-disassembly.txt", "w")
	newDis.write(res)
	newDis.close()



	### example of shellcode from ML - combining decoder + decoded
	yes=3
	if yes==2:
		disassembly, disassemblyNoC, assemblyBytes=takeBytes(old,0)
		print ("old disassembly")
		print (disassembly)
		final=old[:0x23] +new[0x23:]
		clearDisassemblyBytesClass()
		disassembly, disassemblyNoC, assemblyBytes=takeBytes(final,0)

		print ("combined")
		print (disassembly)


	##### end example


	yes=5
	if yes==3:

		encoded=encodeShellcode3(old)
		print ("encoding done")
		decoded=decodeShellcode3(encoded,old)
		print ("decoding done")
		clearDisassemblyBytesClass()
		disassembly, disassemblyNoC, assemblyBytes=takeBytes(decoded,0)
		print ("old disassembly")
		print (disassembly)

	# disassembly, disassemblyNoC, assemblyBytes=takeBytes(rawBytes,0)


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
	# try using threading instead of parallel x
	# try to optimize decoder x
	# fix the int/str issues in analyzedecoder x 
	#use newmodule to save decoded part as new module to use DONE
	#	m[shdec] to analyze decoded shellcode
	# set bools in shellcode obj appropriately
	# change analyzedecoder stubs to determine WHETHER it has a decoderstub DONE
	# check w/ bramwell about automation of brute force + checking for success on other things than peb like callpop, ftsenv, etc
	# for decrypt, covert pebpoints to 3 if below and ask for confirmation
	# analyzedecoderstubs -- need to check if ops or nums are empty -- split find/analyze into 2 func?
	# 		try all values if ops but no values
	# email ip regex to jacob
	# fix some formatting/wording on decoder stub

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
############## added ability to change sensitivity of decrypt match to prevent false positives
############## changed analyzedecoderstubs to try to detect whether a stub exists or not -- prone to false positives however 
############## analyzedecoderstubs also splits up into stub and body if found
############## when shellcode is decoded a new module is set and appropriate properties of the shellcode class is also set
############## hashes are generated of encoded/decoded shell
############## took out setting for number of nodes for distributed, now autofinds
############## distributed mode sanity checks given IPs and rejects invalid ipv4s with a warning
############## 

def decryptShellcode(encodedShell, operations,  findAll = False, fastMode = False, distributed = False, cpuCount = "auto", nodesFile = "nodes.txt", outputFile = True, mode = "default", stubParams = ([],[]), listComp = False, successPoints = pebPoints):

	global shellEntry
	global decodedBytes	
	global filename
	global sh
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

	if(distributed and not (mode == "stub")):
			nodeIPs = []
			with open(nodesFile, 'r') as f:
				for row in f:
					isIP = re.search("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", row, re.IGNORECASE)
					if(isIP):
						nodeIPs.append(row.rstrip('\n'))
					else:
						print("WARNING - Invalid node IP: ", row)
			# print("NODES HERE", nodeIPs)
			
			# decodeOps_aus = [strXor, strAdd, strSub]
			# decodeOps = [strXor, strXor, strSub]

			# run decoding func
			numNodes = len(nodeIPs)
			# print("setting numNodes = ", numNodes)
			decodeInfo = doDistr(decodeOps, encodedShell, numNodes, nodeIPs, findAll = findAll, successPoints = successPoints)

			if(fastMode):
				# to get full decrypted shellcode we need to do a single pass with full encodedShell using correct vals we found during fastmode run
				decodeInfo = decodeInfo[0][0]
				# print("TESTD IS =", testd)
				# print("DECODEINFO IS = ", decodeInfo)
				singleVals = decodeInfo[2]
				or7der = decodeInfo[3]
				# print("GOT SINGLEVALS = ", singleVals)
				# print("GOT ORDER = ", order)

				outputs,earlyFinish,startVals = austinDecode(decodeOps, originalEncoded	, findAll = findAll, mode = "single", starts = singleVals, order = order, successPoints = successPoints)
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
			outputs,earlyFinish,startVals = austinDecode(decodeOps, encodedShell, findAll = findAll, cpuCount = cpuCount, mode = "stub", stubParams = stubParams, successPoints	= successPoints	)
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
				outputs,earlyFinish,startVals = austinListComp(decodeOps, encodedShell, findAll = findAll, cpuCount = cpuCount, successPoints = successPoints)
				decodeInfo = outputs
			else:
				outputs,earlyFinish,startVals = austinDecode(decodeOps, encodedShell, findAll = findAll, cpuCount = cpuCount, successPoints = successPoints)
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
					outputs,earlyFinish,startVals = austinDecode(decodeOps, originalEncoded	, findAll = findAll, mode = "single", starts = singleVals, order = order, successPoints	= successPoints)
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

	# sh.setDecodedBody(decodedBytes)
	# hashShellcode(decodedBytes, unencryptedShell)
	if(len(decodeInfo) > 0):
		sh.setDecodedBody(decodedBytes)
		sh.decryptSuccess = True
		if(mode == "stub"):
			hashShellcode(decodedBytes, unencryptedBodyShell)
		else:
			hashShellcode(decodedBytes, unencryptedShell)
		#create newModule for decrypted shellcode
		newModule(shDec, decodedBytes)
		o = shDec
		print("Setting default to decoded shellcode...")


		if(outputFile):
			disassembly, disassemblyNoC, assemblyBytes=takeBytes(decodedBytes, shellEntry)
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

#initialize decryptFile to be the name of m[o].rawData2 arg by default DONE
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
		print("Couldn't read command line input file, please provide only a shellcode file.")
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
			if(stubEnd != -1):	
				if(sameFile):
					decryptBytes = decryptBytes[stubEnd:]
				print("Got these values from stub: ", numVals)
				print("Got these operations from stub: ", opTypes)
				print("Got stubEnd offset: ", stubEnd)
				input("press enter to proceed...")
				decodedBytes = decryptShellcode(decryptBytes, decryptOpTypes, findAll = dFindAll, fastMode = dFastMode, distributed = dDistr, cpuCount = dCPUcount, nodesFile = dNodesFile, outputFile = dOutputFile, mode = "stub", stubParams = (numVals,opTypes))
			else:
				print("No decoder detected.")

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
				print(m[shDec])
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

	

def toggleDecodedModule():
	global sh
	global o
	global m


	# hashShellcodeTestShow2()

	if(sh == None or sh.decryptSuccess == False):
		print("No shellcode has been decoded. To decode an obfuscated shellcode, use the \"b - Brute-force deobfuscation of shellcode.\" option.")
		# print("o = <<<", o,">>>")
	else:
		if(o == shOrg):
			print("Currently performing operations on obfuscated shellcode. Switch to deobfuscated shellcode?")
			# print("o = <<<", o,">>>")
			while(True):
				userAns = input(" y/n>")
				if(userAns == "y" or userAns == "Y"):
					print("Switching to deobfuscated shellcode...")
					o = shDec
					return
				elif(userAns == "n" or userAns == "N"):
					return
		elif (o == shDec):
			print("Currently performing operations on deobfuscated shellcode. Switch back to obfuscated shellcode?")
			# print("o = <<<", o,">>>")
			while(True):
				userAns = input("y/n>")
				if(userAns == "y" or userAns == "Y"):
					print("Switching to obfuscated shellcode...")
					o = shOrg
					return
				elif(userAns == "n" or userAns == "N"):
					return



#stubEnd goes to end of file by default
#returns: 1. list of detected values | 2. list of detected operations | 3. offset for the end of the decoder stub portion 
def analyzeDecoderStubs(shellArg="default", entryPoint = 0, stubEnd = -1):
	global sh
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
		#
		numeric = re.search("(0x)?([0-9a-f]+)$", i.op_str, re.IGNORECASE)
		isLoop = re.match("^((jmp)|(ljmp)|(jo)|(jno)|(jsn)|(js)|(je)|(jz)|(jne)|(jnz)|(jb)|(jnae)|(jc)|(jnb)|(jae)|(jnc)|(jbe)|(jna)|(ja)|(jnben)|(jl)|(jnge)|(jge)|(jnl)|(jle)|(jng)|(jg)|(jnle)|(jp)|(jpe)|(jnp)|(jpo)|(jczz)|(jecxz)|(jmp)|(loop)|(jns))", i.mnemonic, re.M|re.I)
		
		if(numeric and not isLoop):
			numVals.append(numeric.group())
		elif(isLoop):
			print("Decoder disasm: ")
			print(disString)
			#return if we hit a jump -- this is probably the loop portion of our stub
			#add size of loop instruction with offset to start of the instruction to get offset to first encoded byte
			# print("STUB PORTION:")
			# print(binaryToStr(rawBytes[:(int(addb, 16) + int(size, 16))]))
			# print("\nSHELL PORTION:")
			# print(binaryToStr(rawBytes[(int(addb, 16) + int(size, 16)):]))
			sh.setDecoderStub(rawBytes[:(int(addb, 16) + int(size, 16))])
			sh.isEncoded = True
			hashShellcode(rawBytes[:(int(addb, 16) + int(size, 16))], decoderShell)
			# print(binaryToStr(sh.decoderStub))
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

	# sh.setDecoderStub(rawBytes[:(int(addb, 16) + int(size, 16))])
	# hashShellcode(rawBytes[:(int(addb, 16) + int(size, 16))], decoderShell)
	return -1,-1,-1

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

			m[o].rawData2=rawBytes
			# printBytes(rawBytes)
			# print (disHereShell(rawBytes, False, False, "ascii", True))


		

		print ("Sizem[o].rawData2", len(m[o].rawData2))
		rawBytes=m[o].rawData2
		print("NORMAL BYTES")
		print(binaryToStr(rawBytes))
		print ("rawbytes class", type(rawBytes))
		print("m[o].rawData2 BEFORE ENCODE IN WORKING FUNC: ", m[o].rawData2)
		encoded=encodeShellcode(m[o].rawData2)

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
				m[o].rawData2=new
				# print (binaryToStr(new))
				if(fastMode):
					m[o].rawData2 = m[o].rawData2[:40]
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
						m[o].rawData2 = new
						
						# print("EACHHERE")
						# print(item[3])
						# print("CONVERTED SINGLE HERE")
						# print(binaryToStr(m[o].rawData2))

						disassembly, disassemblyNoC, assemblyBytes=takeBytes(new,0)
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
			m[o].rawData2=new
			if(fastMode):
					m[o].rawData2 = m[o].rawData2[:40]
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
						m[o].rawData2 = new
						
						# print("EACHHERE")
						# print(item[3])
						# print("CONVERTED SINGLE HERE")
						# print(binaryToStr(m[o].rawData2))
				if(outputFile):
					disassembly, disassemblyNoC, assemblyBytes=takeBytes(new,0)
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
			# m[o].rawData2=new
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
		# # 	encoded=encodeShellcodeProto(m[o].rawData2, 32, t, 55)
		# # 	t+=1
		# print ("new\n\n\n\n")
		# r=encodeShellcodeProto(m[o].rawData2, 32,2,55)
		# r=decodeShellcodeProto(r, 32,2,55)
		# m[o].rawData2=r
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
		# 	m[o].rawData2=new
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
		# m[o].rawData2=new
		# mode=""
		# findAllPebSequences(mode)
		# disassembly, disassemblyNoC, assemblyBytes=takeBytes(new,0)
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
		# 	disassembly, disassemblyNoC, assemblyBytes=takeBytes(old,0)
		# 	print ("old disassembly")
		# 	print (disassembly)
		# 	final=old[:0x23] +new[0x23:]
		# 	clearDisassemblyBytesClass()
		# 	disassembly, disassemblyNoC, assemblyBytes=takeBytes(final,0)

		# 	print ("combined")
		# 	print (disassembly)


		# ##### end example


		# yes=5
		# if yes==3:

		# 	encoded=encodeShellcode3(old)
		# 	print ("encoding done")
		# 	decoded=decodeShellcode3(encoded,old)
		# 	print ("decoding done")
		# 	clearDisassemblyBytesClass()
		# 	disassembly, disassemblyNoC, assemblyBytes=takeBytes(decoded,0)
		# 	print ("old disassembly")
		# 	print (disassembly)

		# # disassembly, disassemblyNoC, assemblyBytes=takeBytes(rawBytes,0)


		# # ### Saving disassembly and .bin
		# # print (filename)
		# # print ("before split")
		# # directory, filename= (splitDirectory(filename))




def dp(out):
	txtDis = open("dp-out.txt", "w")
	txtDis.write(out)
	txtDis.close()



def dp2(out):
	txtDis = open("logging.txt", "a")
	txtDis.write(out+"\n")
	# txtDis.close()


def dprint3(*args):


	try:
		if  (len(args) == 1):
			if(type(args[0]) == list):
				dp2(args[0])
				return

		if  (len(args) > 1):
			strList = ""
			for each in args:
				try:
					strList += each + " "
				except:
					strList += str(each) + " "
			dp2(strList)

		else:
			for each in args:
				try:
					dp2 (str(each) + " ")
				except:
					dp2 ("dprint error: 1")
					dp2 (each + " ")
	except Exception as e:
		dp2 ("dprint error: 3")
		dp2 (e)
		dp2(traceback.format_exc())
		dp2 (args)

def shellDisassemblyInit(shellArg, silent=None):
	bprint ("shellDisassemblyInit")
	global filename

	global gDisassemblyText
	global save_bin_file
	global shellEntry

	startAddress=shellEntry

	mode=""

	if not mBool[o].bFstenvFound:
		findAllFSTENV(shellArg, "noSec")
	if not mBool[o].bPushRetFound:
		findAllPushRet(shellArg, "noSec")
	if not mBool[o].bCallPopFound:
		findAllCallpop(shellArg, "noSec")
	if not mBool[o].bHeavenFound:
		getHeavenRawHex(0, 8, "noSec", shellArg)
	if not mBool[o].bSyscallFound:
		getSyscallRawHex(0, 8, "noSec", shellArg)
	if not mBool[o].bPEBFound:
		findAllPebSequences("normal", shellArg, 'noSec')
	if 1==2:
		print ("find peb results:")
		printSavedPEB()

	mBool[o].bAnaFindStrDone=False
	mBool[o].bAnaHiddenCallsDone=False
	mBool[o].bAnaHiddenCnt=0
	mBool[o].bAnaConvertBytesDone=False
	mBool[o].disAnalysisDone=False


	#parameterize
	disassembly, disassemblyNoC, assemblyBytes=takeBytes(shellArg,startAddress, silent)
	   # main one
	# dp(disassembly)

	allowPrint()
	colorama.init()
	gDisassemblyText = disassembly

	### Saving disassembly and .bin

	dirPath = '\\'.join(filename.split("\\")[:-1])
	filename = os.path.basename(filename)

	directory=""

	bytesOutput=shellArg
	# import os

	# filename=shHash.md5
	if not os.path.exists(directory+'disassembly'):
		os.makedirs(directory+'disassembly')
	# print (directory+"outputs\\"+filename[:-4]+".bin")
	# newBin = open(directory+"outputs\\"+filename[:-4]+".bin", "wb")
	# newBin.write(rawBytes)
	# newBin.close()

	global useHash
	global filename2
	

	allowPrint()
	colorama.init()

	if not useHash:
		txtDis = open(directory+"disassembly\\"+filename[:-4]+"-disassembly.txt", "w")
		printOUT= ("\tDisassembly printed to disassembly\\"+filename[:-4]+"-disassembly.txt")
		if save_bin_file:
			binDis = open(directory+"disassembly\\"+filename[:-4]+"-disassembly.bin", "wb")
			binDis.write(bytesOutput)
			binDis.close()
			("\tRaw binary saved to disassembly\\"+filename[:-4]+"-disassembly.bin")

	else:
		
		txtDis = open(directory+"disassembly\\"+filename2+"-disassembly.txt", "w")
		printOUT= ("\tDisassembly printed to disassembly\\"+filename2+"-disassembly.txt")
		if save_bin_file:
			binDis = open(directory+"disassembly\\"+filename2+"-disassembly.bin", "wb")
			binDis.write(bytesOutput)
			binDis.close()
			("\tRaw binary saved to disassembly\\"+filename2+"-disassembly.bin")

	if not silent=="silent":
		print (printOUT)

	txtDis.write(disassemblyNoC+assemblyBytes)

	txtDis.close()

	
	# input()
	# print (directory)
	# print (filename)
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



def disPrintStyleMenu():

	while True:
		print(yel + " Sharem>" + cya + "Disasm>" + res + whi + "PrintStyle> " + res, end="")

		choice = input()
		if choice == "g":
			disPrintStyleTogg()
		elif choice == "x":
			break
		elif choice == "h":
			disPrintStyle(mBool[o].bPreSysDisDone, toggList)
		elif choice == "m":
			opnum = input(" Enter maximum opcodes number: ")
			try:
				opnum = int(opnum)
				mBool[o].maxOpDisplay = opnum
				toggList['max_opcodes'] = opnum

			except:
				print(red + "\tPlease enter integer, not string." + res)
				continue
		elif choice == "p":
			pstyle = input(" Enter opcode print style [1-3]: ")
			try:
				pstyle = int(pstyle)
				if pstyle > 3 or pstyle <1:
					print(red +"\t Please enter number between 1 and 3." +res)
					continue

				mBool[o].btsV = pstyle
				toggList['binary_to_string'] = pstyle

			except:
				print(red + "\tPlease enter integer, not string." + res)
				continue

		elif choice == "r":
			
			if gDisassemblyText != "":
				regenerateDisassemblyForPrint()
				print(gDisassemblyText)
			else:

				print(red + "\tDisassembly is not generated."+res)
				mchoice = input(" Do you want to generate the disassembly first [y/n] ? ")
				mchoice = mchoice.lower()
				if mchoice == "y":
					if rawHex:
						if bfindShell:

							# print ("hello??")
							# dontPrint()
							shellDisassemblyInit(m[o].rawData2, "silent")
							# allowPrint()

							if gDisassemblyText == "":
								print("\nUnable to find any disassembly.\n")
							else:
								# print("\nFound disassembly instructions.\n")
								mBool[o].bDisassemblyFound = True
				else:
					continue


		else:
			print("Invalid input.")


def disPrintStyleTogg():
	print("Enter input delimited by commas or spaces. (x to exit)")
	print("\tE.g. c, a, o, l, f\n")
	while True:
		print(yel + " Sharem>" + cya + "Disasm>" + res + whi + "PrintStyle> " + res, end="")

		togg = input()
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
			
					
			if t == "d":
				toggList['deobfCode'] = not toggList['deobfCode']
				bdeobfCode = not bdeobfCode

			elif t == "c":

				toggList['comments'] = not toggList['comments']
				mBool[o].bDoEnableComments = not mBool[o].bDoEnableComments
			
			elif t == "o":
				toggList['opcodes'] = not toggList['opcodes']
				mBool[o].bDoShowOpcodes = not mBool[o].bDoShowOpcodes

			elif t == "a":
				toggList['show_ascii'] = not toggList['show_ascii']
				mBool[o].bDoShowAscii = not mBool[o].bDoShowAscii

			elif t=="l":
				toggList['labels'] = not toggList['labels']
				mBool[o].bShowLabels = not mBool[o].bShowLabels

			elif t == "f":
				toggList['offsets'] = not toggList['offsets']
				mBool[o].bDoShowOffsets = not mBool[o].bDoShowOffsets

			elif t == "x":
				return

		disPrintStyle(mBool[o].bPreSysDisDone, toggList) 
		return

def disassembleSubMenu():

	#disToggleMenu()
	global shellSizeLimit
	global shellEntry
	while True:
		print(yel + " Sharem>" + cya + "Disasm> " + res, end="")
		choice = input()
		choice = choice.lower()
		if choice == "":
			continue
		elif choice == "x":
			#print("\nGoing back to main menu..\n")
			break
		elif choice == "m":
			tmp = input(" Enter new shellcode size: ")
			try:
				tmp = int(tmp)
			except:
				print(red + " Please enter integer only." + res)
				continue

			print(yel + " Shellcode size has been changed." + res)
			shellSizeLimit = tmp

			# modifysByRangeUser()
		elif choice == "h" or choice == "help":
			disToggleMenu(shellEntry,shellSizeLimit,mBool[o].bPreSysDisDone, toggList) 
			# disassembleUiMenu(shellEntry)
		elif choice == "g":

			disassembleToggles()

		elif choice == "r":
			disPrintStyle(mBool[o].bPreSysDisDone, toggList)
			disPrintStyleMenu()
		elif choice == "e":
			changeEntryPoint()
		elif choice == "j":
			raw_shellcode = binaryToText(m[o].rawData2, "json")
			Text2Json(raw_shellcode)
		elif choice == "u":
			useMd5asFilename()
		elif choice == "p":
			if gDisassemblyText != "":
				print(gDisassemblyText)

		elif choice == "i":
			mBool[o].ignoreDisDiscovery = not mBool[o].ignoreDisDiscovery
			toggList['ignore_dis_discovery'] = not toggList['ignore_dis_discovery']
		elif choice == "z" or choice =="d":
			if rawHex:
				if bfindShell:

					# print ("hello??")
					# dontPrint()
					shellDisassemblyInit(m[o].rawData2, "silent")
					# allowPrint()

					if gDisassemblyText == "":
						print("\nUnable to find any disassembly.\n")
					else:
						# print("\nFound disassembly instructions.\n")
						mBool[o].bDisassemblyFound = True
			else:
				print("\nThis option is for shellcode only")
			

			#print(gDisassemblyText)

		else:
			print("Invalid input??")

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

# toggList = {'findString':True, 
# 			'deobfCode':False,
# 			'findShell':False,
# 			'comments':True,
# 			'hidden_calls':True,
# 			'show_ascii':True,
# 			'ignore_dis_discovery':False,
# 			'opcodes':True,
# 			'labels':True,
# 			'offsets':True,
# 			'max_opcodes':8,
# 			'binary_to_string':3}

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
				toggList['findString'] = not toggList['findString']
				mBool[o].bDoFindStrings = not mBool[o].bDoFindStrings
					
			elif t == "d":
				toggList['deobfCode'] = not toggList['deobfCode']
				bdeobfCode = not bdeobfCode
				

			

			elif t == "c":
				toggList['hidden_calls'] = not toggList['hidden_calls']
				mBool[o].bDoFindHiddenCalls = not mBool[o].bDoFindHiddenCalls


			

			elif t == "i":
				toggList['ignore_dis_discovery'] = not toggList['ignore_dis_discovery']
				mBool[o].ignoreDisDiscovery = not mBool[o].ignoreDisDiscovery


		disToggleMenu(shellEntry,shellSizeLimit,mBool[o].bPreSysDisDone,  toggList) 
		return
		

	

def bramwellDisassembly2():
	# global shellcode4
	# global filename

	global shellEntry
	# print ("m[o].rawData2 a", len(m[o].rawData2))
	# print (shellEntry)
	shellDisassemblyInit(m[o].rawData2)  #shellcode data, start address

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
	global minStrLen
	global maxDistance
	global sharem_out_dir

	listofStrings = ['pushret', 'callpop', 'fstenv', 'syscall', 'heaven', 'peb', 'disassembly', 'pebpresent', 'bit32','max_bytes_forward','max_bytes_backward','max_lines_forward', 'max_lines_backward','print_to_screen', 'push_stack_strings', 'ascii_strings', 'wide_char_strings', 'fast_mode', 'find_all', 'dist_mode', 'cpu_count', 'nodes_file', 'output_file', 'dec_operation_type', 'decrypt_file', 'stub_file', 'use_same_file', 'stub_entry_point', 'stub_end', 'shellEntry', 'pebpoints', 'minimum_str_length', 'max_callpop_distance', 'default_outdir']
	listofBools = [bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, pebPresent, bit32, bytesForward, bytesBack, linesForward, linesBack,p2screen, bPushStackStrings, bAsciiStrings, bWideCharStrings, dFastMode, dFindAll, dDistr, dCPUcount, dNodesFile, dOutputFile, decryptOpTypes, decryptFile, stubFile, sameFile, stubEntry, stubEnd, shellEntry, pebPoints, minStrLen, maxDistance, sharem_out_dir]

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
	global minStrLen
	global sharem_out_dir
	global maxDistance
	global bPrintEmulation
	global emulation_verbose
	global emulation_multiline
	global bpEvilImports
	global bpModules
	global shellSizeLimit
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
		print(red +"\n\nConfig file Error:", yel + dNodesFile + res, red + "doesn't exist!" + res)
	dOutputFile = conr['SHAREM DECRYPT']['output_file']
	decryptOpTypes = conr['SHAREM DECRYPT']['dec_operation_type']
	try:
		 decryptOpTypes = ast.literal_eval(decryptOpTypes)
	except:
		print(yel + "The value of", red + decryptOpTypes, yel + "is not correct or malformed!!"+ res)
		sys.exit()
	decryptFile = conr['SHAREM DECRYPT']['decrypt_file']
	if not (os.path.exists(decryptFile)):
		print(red +"\n\nConfig file Error:", yel + decryptFile + res, red + "doesn't exist!" + res)
	stubFile = conr['SHAREM DECRYPT']['stub_file']
	if not (os.path.exists(stubFile)):
		print(red +"\n\nConfig file Error:", yel + stubFile + res, red + "doesn't exist!" + res)

	sameFile = conr.getboolean('SHAREM DECRYPT','use_same_file')
	try:
		stubEntry = int(conr['SHAREM DECRYPT']['stub_entry_point'])
	except:
		stubEntry = int(conr['SHAREM DECRYPT']['stub_entry_point'],16)

	try:
		stubEnd = int(conr['SHAREM DECRYPT']['stub_end'])
	except:
		stubEnd = int(conr['SHAREM DECRYPT']['stub_end'],16)



	# print(dFastMode, dFindAll, dDistr, dCPUcount, dNodesFile, dOutputFile, decryptOpTypes, decryptFile, stubFile, sameFile, stubEntry, stubEnd)


#===============================================

	mBool[o].bDoFindHiddenCalls = conr.getboolean('SHAREM DISASSEMBLY','enable_hidden_calls')
	mBool[o].bDoEnableComments = conr.getboolean('SHAREM DISASSEMBLY','enable_assembly_comments')
	mBool[o].bDoShowAscii = conr.getboolean('SHAREM DISASSEMBLY','enable_assembly_ascii')
	mBool[o].bDoFindStrings = conr.getboolean('SHAREM DISASSEMBLY','enable_find_strings')
	mBool[o].ignoreDisDiscovery = conr.getboolean('SHAREM DISASSEMBLY','ignore_dis_discovery')
	mBool[o].maxOpDisplay = int(conr['SHAREM DISASSEMBLY']['max_disassembly_operands'])
	mBool[o].btsV = int(conr['SHAREM DISASSEMBLY']['binary_to_string'])
	shellSizeLimit = int(conr['SHAREM DISASSEMBLY']['shellcode_size_limit'])
	mBool[o].bDoShowOffsets = conr.getboolean('SHAREM DISASSEMBLY','show_disassembly_offsets')
	mBool[o].bDoShowOpcodes = conr.getboolean('SHAREM DISASSEMBLY','show_disassembly_opcodes')
	mBool[o].bDoShowLabels = conr.getboolean('SHAREM DISASSEMBLY','show_disassembly_labels')













#===============================================

	sharem_out_dir = conr['SHAREM SEARCH']['default_outdir']
	maxDistance = int(conr['SHAREM SEARCH']['max_callpop_distance'])
	bPushRet= conr.getboolean('SHAREM SEARCH','pushret')
	bCallPop= conr.getboolean('SHAREM SEARCH','callpop')
	bFstenv= conr.getboolean('SHAREM SEARCH','fstenv')
	bSyscall= conr.getboolean('SHAREM SEARCH','syscall')
	bHeaven= conr.getboolean('SHAREM SEARCH','heaven')
	bPEB= conr.getboolean('SHAREM SEARCH','peb')
	save_bin_file = conr.getboolean('SHAREM SEARCH','save_bin_file')
	bDisassembly= conr.getboolean('SHAREM SEARCH','disassembly')
	pebPresent = conr.getboolean('SHAREM SEARCH','pebpresent')
	bPrintEmulation = conr.getboolean('SHAREM SEARCH', 'print_emulation_result')
	emulation_verbose = conr.getboolean('SHAREM SEARCH', 'emulation_verbose_mode')
	emulation_multiline = conr.getboolean('SHAREM SEARCH', 'emulation_multiline')
	bpEvilImports = conr.getboolean('SHAREM SEARCH', 'imports')




	if rawHex and not bit32_argparse:
		bit32 = conr.getboolean('SHAREM SEARCH','bit32')

		if bit32:
			shellBit = 32
		else:
			shellBit = 64



	p2screen =  conr.getboolean('SHAREM SEARCH','print_to_screen')


	#==================== Strings ================================
	bPushStackStrings =  conr.getboolean('SHAREM STRINGS','push_stack_strings')

	bAsciiStrings =  conr.getboolean('SHAREM STRINGS','ascii_strings')
	bWideCharStrings =  conr.getboolean('SHAREM STRINGS','wide_char_strings')
	minStrLen = int(conr['SHAREM STRINGS']['minimum_str_length'])
	#============================================================


	# malformed = "print('malformed')"
	pebPoints = int(conr['SHAREM SEARCH']['pebpoints'])
	if pebPoints > 4:
		pebPoints=4
	try:
		shellEntry = int(conr['SHAREM SEARCH']['shellEntry'])
	except:
		shellEntry = int(conr['SHAREM SEARCH']['shellEntry'], 16)
	try:
		bytesForward = int(conr['SHAREM SEARCH']['max_bytes_forward'])
	except:
		bytesForward = int(conr['SHAREM SEARCH']['max_bytes_forward'],16)

	try:
		bytesBack = int(conr['SHAREM SEARCH']['max_lines_backward'])
	except:
		bytesBack = int(conr['SHAREM SEARCH']['max_lines_backward'],16)

	try:
		linesForward = int(conr['SHAREM SEARCH']['max_lines_forward'])
	except:
		linesForward = int(conr['SHAREM SEARCH']['max_lines_forward'],16)

	try:
		linesBack = int(conr['SHAREM SEARCH']['max_lines_backward'])
	except:
		linesBack = int(conr['SHAREM SEARCH']['max_lines_backward'],16)

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

	# print ("shellEntry init", shellEntry)

	if not startupBool:
		return False
	else:
		return True
			# print(os.code, os.name, os.category, os.toggle)



def isFound():

	if mBool[o].bPushRetFound:
		print('Pushret instructions found')
	else:
		print('Pushret instructions Not found')

	if mBool[o].bCallPopFound:
		print('Callpop instructions found')
	else:
		print('Callpop instructions Not found')


	if mBool[o].bDisassemblyFound:
		print('Disassembly found')
	else:
		print('Disassembly Not found')

	if mBool[o].bFstenvFound:
		print('Fstenv instructions found')
	else:
		print('Fstenv instructions Not found')

	if mBool[o].bSyscallFound:
		print('Syscall instructions found')
	else:
		print('Syscall instructions Not found')

	if mBool[o].bPEBFound:
		print('Peb instructions found')
	else:
		print('Peb instructions Not found')

def discoverUnicodeStrings(max_len=None):
	global bWideCharStrings
	
	if max_len==None:
		max_len=42
	mBool[o].bWideStringFound = False
	print("\n"+yel + " Finding unicode strings..", end="")
	curLen = len("Finding unicode strings..")

	if rawHex:
		findStringsWide(m[o].rawData2,3)
		if (len(stringsTempWide) > 0):
			mBool[o].bWideStringFound = True
			mBool[o].bStringsFound=True
	else:
		t=0
		for sec in pe.sections:
			if bWideCharStrings and not mBool[o].bWideStringFound:
				findStringsWide(s[t].data2,minStrLen)
			t+=1
		t = 0
		mBool[o].bWideStringFound = False
		for sec in pe.sections:
			if (len(s[t].wideStrings) > 0):
				mBool[o].bWideStringFound = True
				mBool[o].bStringsFound=True

			t+=1
	if mBool[o].bWideStringFound:
		print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))
	else:
		print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

def discoverAsciiStrings(max_len=None):
	global bAsciiStrings
	if max_len==None:
		max_len=42

	curLen = len("Finding Ascii strings..")
	print(yel + " Finding Ascii strings.."+res, end="")
	if rawHex:
		findStrings(m[o].rawData2,3)
		if (len(stringsTemp) > 0):
			mBool[o].bStringsFound = True
	else:		
		t=0
		for sec in pe.sections:
			if bAsciiStrings and not mBool[o].bStringsFound:
				findStrings(s[t].data2,minStrLen)
			t+=1
		t = 0
		for sec in pe.sections:
			if (len(s[t].Strings) > 0):
				mBool[o].bStringsFound = True
			t+=1
	if mBool[o].bStringsFound:
		print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))
	else:
		print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))

def discoverStackStrings(max_len=None):
	global bPushStackStrings
	if max_len==None:
		max_len=42

	print(yel + " Finding push stack strings..", end="")
	curLen = len("Finding push stack strings..")
	if rawHex:
		findPushAsciiMixed(m[o].rawData2,3)
		if (len(pushStringsTemp) > 0):
			mBool[o].bPushStringsFound = True
	else:
		t=0
		for sec in pe.sections:
			if bPushStackStrings and not mBool[o].bPushStringsFound:
				findPushAsciiMixed(s[t].data2,5, t)
			t+=1
		t = 0
		for sec in pe.sections:
			if (len(s[t].pushStrings) > 0):
				mBool[o].bPushStringsFound = True
			t+=1
	if mBool[o].bPushStringsFound:
		print("{:>{x}}{}".format("", gre + "[Found]"+res, x=15+(max_len-curLen)))
	else:
		print("{:>{x}}{}".format("", red + "[Not Found]"+res, x=15+(max_len-curLen)))
	

class emulationOptons:
	def __init__(self):
		self.verbose = False
		self.maxEmuInstr = 500000
		self.cpuArch = 32
		self.breakLoop = True
		self.numOfIter = 30000


def under_dev_function():
	print(red + "\tThis feature is under development.\n" + res)
	

def emu_max_instruction():
	while True:
		try:
			minst = input(" Enter maximum instructions number: ")
			if minst == "x":
				break
			minst = int(minst)
			emuObj.maxEmuInstr = minst
			break
		except:
			print(red + "\tPlease enter only a number." + res)
			break




def emulationSubmenu():
	em.maxCounter=emuObj.maxEmuInstr
	
	while True:
		print(yel + " Sharem>" + cya + "Emulator> " +res, end="")
		choice = input()
		if choice == "z":
			emuArch = emuObj.cpuArch
			startEmu(emuArch, m[o].rawData2, emuObj.verbose)
			emulation_txt_out(loggedList)
			pass # Initiate emulator
		elif choice == "x":
			return
		elif choice == "h":
			emulatorUI(emuObj)
		elif choice == "v":
			print ("\tVerbosity changed.\n")
			emuObj.verbose = not emuObj.verbose
		elif choice == "b":
			under_dev_function()
			# emuObj.breakLoop = not emuObj.breakLoop
		elif choice == "m":

			while True:
				try:
					minst = input(" Enter maximum instructions number: ")
					if minst == "x":
						break
					minst = int(minst)
					emuObj.maxEmuInstr = minst
					em.maxCounter=minst
					# sharemu.maxCounter = minst
					break
				except:
					print(red + "\tPlease enter only a number." + res)
					break
		elif choice == "n":
			under_dev_function()
			# while True:
			# 	try:
			# 		minst = input(" Enter maximum number of iterations: ")
			# 		if minst == "x":
			# 			break
			# 		minst = int(minst)
			# 		emuObj.numOfIter = minst
			# 		break
			# 	except:
			# 		print(red + "\tPlease enter only a number." + res)
			# 		break
		elif choice == "a":
			under_dev_function()
			# while True:
			# 	try:
			# 		minst = input(" Enter cpu architecture: ")
			# 		if minst == "x":
			# 			break
			# 		minst = int(minst)
			# 		if minst == 32 or minst == 64:
			# 			emuObj.numOfIter = minst
			# 			break
			# 		else:
			# 			print(red + "\tInvalid cpu architecture.\n" + res)
			# 			continue
					
			# 	except:
			# 		print(red + "\tPlease enter only a number." + res)
			# 		break
			# emulatorUI(emuObj)




def startupPrint():
	global bAsciiStrings
	global bWideCharStrings
	global bPushStackStrings
	
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
	global bPrintEmulation
	global rawHex
	global bEvilImportsFound
	global bpEvilImports
	global modulesMode
	elapsed_time=0

	mBool[o].bPushRetFound = mBool[o].bCallPopFound = mBool[o].bDisassemblyFound = mBool[o].bFstenvFound = mBool[o].bHeavenFound = mBool[o].bPEBFound = mBool[o].bStringsFound = mBool[o].bWideStringFound = mBool[o].bPushStringsFound = False
	# minStrLen = 7
	l_of_strings = ["Finding Ascii strings..", "Finding unicode strings..", "Finding push stack strings..","Searching for disassembly..", "Searching for Fstenv instructions..", "Searching for push ret instructions..", "Searching for call pop instructions..", "Searching for heaven's gate instructions..", "Searching for syscall instructions..", "Searching for PEB instructions.."]
	max_len = get_max_length(l_of_strings)

	
	print(cya + "\n\n Finding Strings\n\n" + res)
	
	if bAsciiStrings and not mBool[o].bStringsFound:
		discoverAsciiStrings(max_len)
	if bWideCharStrings and not mBool[o].bWideStringFound:
		discoverUnicodeStrings(max_len)
	if bPushStackStrings and not mBool[o].bPushStringsFound:
		discoverStackStrings(max_len)
	
	print("\n\n")
	if bFstenv and not mBool[o].bFstenvFound:
		newTime= discoverFstenv(max_len)
		elapsed_time += newTime
				
	if bPushRet and not mBool[o].bPushRetFound:
		newTime= discoverPushRet(max_len)
		elapsed_time += newTime
		
	if bCallPop and  not mBool[o].bCallPopFound:
		newTime=discoverCallPop(max_len)
		elapsed_time += newTime

	if bHeaven and not mBool[o].bHeavenFound:
		newTime= discoverHeaven(max_len)
		elapsed_time += newTime

	if bSyscall and  not mBool[o].bSyscallFound:
		newTime	= discoverSyscal(max_len)
		elapsed_time += newTime

	if bPEB and not mBool[o].bPEBFound:
		newTime	= discoverPEB(max_len)
		elapsed_time += newTime

	if bPrintEmulation and not mBool[o].bEmulationFound:
		newTime	= discoverEmulation(max_len)
		elapsed_time += newTime

	
	if bDisassembly and not mBool[o].bDisassemblyFound:
		newTime= discoverDisassembly(max_len)

	if bpEvilImports and not mBool[o].bEvilImportsFound:
		if not rawHex:
			findEvilImports()

			print(showImports())
	if not rawHex:
		modulesMode = 3
		runInMem()
		print(giveLoadedModules())
		giveLoadedModules("save")


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
		print(yel + " Configuration has been Saved.\n" + res)
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
	global rawhex
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
	bPushStrings = True
	bShellcodeAll = True
	bExportAll = True
	bpAll = True
	stringsDeeper = False
	checkGoodStrings = True
	# minStrLen = 7
	# maxDistance = 15
	modulesMode = 3
	pushStringRegisters = 'unset'
	showDisassembly = True
	stringReadability = .65
	# initSysCallSelect()
	# clearConsole()

	x = ""
	con = Configuration(conFile)

	# 	for item in section.save_PushRet_info:
	# for item in m[o].save_PushRet_info:
	# print("Bits: ", shellBit)

	showOptions(shellBit, rawHex,m[o].name, m[o].getMd5())
	while x != "e":		#Loops on keyboard input
		try:			#Will break the loop on entering x
			print(yel + " Sharem> " + res, end="")
			userIN = input()
			print(res)
			if userIN[0:1] == "x":
				print("\nExiting program.\n")
				break
			
			elif userIN[0:1] == "h":
				showOptions(shellBit, rawHex,m[o].name, m[o].getMd5())
			
			elif userIN[0:1] == "D":
				if not rawHex:
					print("\nThis option is for shellcode only.\n")
				else:
					shellDisassemblyInit(rawData2)
					# bramwellStart2()
			elif userIN[0:1] == "d":
				disToggleMenu(shellEntry,shellSizeLimit,mBool[o].bPreSysDisDone,  toggList) 

				# disToggleMenu(shellEntry,shellSizeLimit,mBool[o].bPreSysDisDone, mBool[o].bDoFindHiddenCalls, mBool[o].bDoEnableComments, mBool[o].bDoShowAscii, mBool[o].bDoFindStrings, mBool[o].ignoreDisDiscovery, mBool[o].maxOpDisplay, mBool[o].btsV, mBool[o].bDoShowOffsets, mBool[o].bDoshowOpcodes,mBool[o].bShowLabels) 
				# disassembleUiMenu(shellEntry)
				disassembleSubMenu()
			elif userIN[0:1] == "s":	# "find assembly instrucitons associated with shellcode"
				uiDiscover()

			elif userIN[0:1] == "l":
				emulatorUI(emuObj)
				emulationSubmenu()
			elif(re.match("^b$", userIN)):
				decryptUI()

			elif userIN[0:1] == "U":                  
				toggleDecodedModule()

			elif userIN[0:1] == "a":	# "change architecture, 32-bit or 64-bit"
				uiBits()
				initSysCallSelect()
				# print("\nReturning to main menu.\n")

			elif(re.match("^c$", userIN)):   # "save configuration"
				# print(configOptions)
				# if configOptions:
				modConf()
				saveConf(con)
					# configData = ",".join(configOptions)
					# print(configData)
			elif userIN[0:1] == "z":
				startupPrint()
			elif userIN[0:1] == "u":
				Text2Json(m[o].rawData2)
			elif userIN[0:1] == "p":	#We want to print
				uiPrint()
				# print("\nReturning to main menu.\n")
			elif userIN[0:1] == "i":
				if(rawHex):
					info = showBasicInfo()
					print (info)
					hashShellcodeTestShow(sample)
					# print("No PE file selected.\n")
				else:
					info = showBasicInfoSections()
					print(info)
			elif userIN[0:1] == "k":
				uiFindStrings()
				# print("\nReturning to main menu.\n")
			elif userIN[0:2] == "j!":
				uiShellcodeStrings()  ### deprecated
				# print("\nReturning to main menu.\n")
			elif userIN[0:1] == "e":  # "find imports"
				uiFindImports()
			elif userIN[0:1] == "q":  # "quick find all"
				findAll()
			elif userIN[0:1] == "o":
				saveBinAscii()   # "output bins and ascii"
			elif userIN[0:1] == "m":	# "find modules in the iat and beyond"
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
def discoverEmulation(maxLen=None):
	global shellBit
	if maxLen==None:
		maxLen=42
	
	start = time.time()
	curLen = len("  Emulation of shellcode...")
	print(cya + " Starting emulation of shellcode..."+res, end="", flush=True)
	

	emuArch = emuObj.cpuArch										# temporary way of invoking emulator - may change later
	startEmu(emuArch, m[o].rawData2, emuObj.verbose)
	mBool[o].bEmulationFound=True									# if we run it, it is done - if we have not objective way of quantifying how successful it issues
																	# depending on shellcode, could miss some, a lot, or be perfect. We just run it.

	print(cya + " Emulation of shellcode..."+res, end="", flush=True)

	if(mBool[o].bEmulationFound):
		print("{:>{x}}[{}]".format("", gre + "COMPLETED" + res, x=15+(maxLen-curLen)))
	else:
		print("{:>{x}}[{}]".format("", red + "NOT COMPLETED" + res, x=15+(maxLen-curLen)))
	end = time.time()
	# elapsed_time += end - start
	return end-start

def discoverPEB(maxLen=None):
		
	global shellBit
	if maxLen==None:
		maxLen=42
	
	start = time.time()
	curLen = len("Searching for PEB walking instructions")
	print(cya + " Searching for PEB walking instructions..."+res, end="", flush=True)
	if (rawHex):
		# findAllPebSequences_old(m[o].rawData2, 'noSec')
		findAllPebSequences("normal", m[o].rawData2, 'noSec')
		# findAllPebSequences(m[o].rawData2, 0, "decrypt")
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
			mBool[o].bPEBFound = True
	if rawHex:
		if len(m[o].save_PEB_info) > 0:
			mBool[o].bPEBFound = True
	if(mBool[o].bPEBFound):
		print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
	else:
		print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
	end = time.time()
	# elapsed_time += end - start
	return end-start

def discoverSyscal(maxLen=None):
	
	if maxLen==None:
		maxLen=42
	start = time.time()
	curLen = len("Searching for windows syscall instructions")
	print(cya + " Searching for windows syscall instructions..."+res, end="", flush=True)
	if (rawHex):
		# getSyscallPE(20, 20, match, 'noSec', m[o].rawData2)
		getSyscallRawHex(0, linesBack, 'noSec', m[o].rawData2)

	else:
		for secNum in range(len(s)):
				data2 = s[secNum].data2
				for match in EGGHUNT.values():
					optimized_find(20, match, secNum, data2, "disHereSyscall")
					# getSyscallPE(20, 20, match, secNum, data2)
	for i in s:
		if (len(i.save_Egg_info) > 0):
			mBool[o].bSyscallFound = True

	if  rawHex:
		if len(m[o].save_Egg_info) > 0:
			mBool[o].bSyscallFound = True
	if(mBool[o].bSyscallFound):
		print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
	else:
		print("{:>{x}}[{}]".format("", red + "Not Found"+ res, x=15+(maxLen-curLen)))
	end = time.time()
	# elapsed_time += end - start
	return end-start
	
def discoverDisassembly(maxLen=None):
		
	global gDisassemblyText
	global bit32
	global rawHex

	if maxLen==None:
		maxLen=42
	curLen = len("Searching for disassembly")
	print(cya + " Searching for disassembly..." + res, end="", flush=True)
	start = time.time()
	
	if rawHex:
		if bit32:
			# dontPrint()
			shellDisassemblyInit(m[o].rawData2, "silent")
			# allowPrint()
			colorama.init()
			# elapsed_time += end - start
	if gDisassemblyText != "":
		print("{:>{x}}[{}]".format("", gre + "Found"+res, x=15+(maxLen-curLen)))
		mBool[o].bDisassemblyFound = True
	else:
		print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
	# elapsed_time += end - start
	end = time.time()

	return end-start

def discoverHeaven(maxLen=None):
	
	if maxLen==None:
		maxLen=42

	start = time.time()
	curLen = len("Searching for heaven's gate instructions")
	print(cya + " Searching for heaven's gate instructions..."+ res, end="", flush=True)
	if (rawHex):
		getHeavenRawHex(0, linesBack, 'noSec', m[o].rawData2)

	else:
		for secNum in range(len(s)):
				data2 = s[secNum].data2
				findAllHeaven(data2, secNum)
	for i in s:
		if (len(i.save_Heaven_info) > 0):
			mBool[o].bHeavenFound = True
	if  rawHex:
		if len(m[o].save_Heaven_info) > 0:
			mBool[o].bHeavenFound = True
	if(mBool[o].bHeavenFound):
		print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
	else:
		print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
	end = time.time()
	# elapsed_time += end - start
	return end-start
	
def discoverCallPop(maxLen=None):
	
	if maxLen==None:
		maxLen=42
	start = time.time()
	curLen = len("Searching for call pop instructions")
	print(cya + " Searching for call pop instructions..."+res, end="", flush=True)
	if (rawHex):
		if bit32:
			findAllCallpop(m[o].rawData2, 'noSec')
		else: 
			findAllCallpop64(m[o].rawData2, 'noSec')
	else:
		for secNum in range(len(s)):
			data2 = s[secNum].data2
			if bit32:
				findAllCallpop(data2, secNum)
			else:
				findAllCallpop64(data2, secNum)
	for i in s:
		if (len(i.save_Callpop_info) > 0):
			mBool[o].bCallPopFound = True
	if  rawHex:
		if len(m[o].save_Callpop_info) > 0:
			mBool[o].bCallPopFound = True
	if(mBool[o].bCallPopFound):
		print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
	else:
		print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
	end = time.time()
	return end-start
def discoverFstenv(maxLen=None):
		

	# pass ### until fixed

	###### CURRENTLY DISABLED!!!

	if maxLen==None:
		maxLen=42
	curLen = len("Searching for fstenv instructions")
	print(cya + " Searching for fstenv instructions..."+res, end="", flush=True)
	start = time.time()
	# print("Objects ----> ", len(s))
	# input()
	# print("Size -- > ", s[5].data2)
	if (rawHex):
		findAllFSTENV(m[o].rawData2, 'noSec')

	else:
		for secNum in range(len(s)):
		# secNum = 0
			data2 = s[secNum].data2

			findAllFSTENV(data2, secNum)
			# secNum += 1
	for i in s:
		if (len(i.save_FSTENV_info) > 0):
			mBool[o].bFstenvFound = True

	if rawHex:
		if len(m[o].save_FSTENV_info) > 0:
			mBool[o].bFstenvFound = True
	if(mBool[o].bFstenvFound):
		print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
		#print("{:>{x}}".format("[Found]    ", x=15+(maxlen-curLen)))
	else:
		print("{:>{x}}[{}]".format("", red + "Not Found"+ res, x=15+(maxLen-curLen)))
		#print("{:>{x}}".format("[Not Found]", x=15+(maxLen-curLen)))
	end = time.time()
	# print("After fstenv search", m[o].rawData2.hex())
	return end-start

def discoverPushRet(maxLen=None):
	

	if maxLen==None:
		maxLen=42
	# ("uiDiscoverpush")
	start = time.time()
	curLen = len("Searching for push ret instructions")
	print(cya + " Searching for push ret instructions..." + res, end="", flush=True)
	if (rawHex):
		if bit32:
			findAllPushRet(m[o].rawData2, 'noSec')
		else: 
			findAllPushRet64(m[o].rawData2, 'noSec')
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
			mBool[o].bPushRetFound = True

	if rawHex:
		if len(m[o].save_PushRet_info) > 0:
			mBool[o].bPushRetFound = True

	if(mBool[o].bPushRetFound):
		print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
	else:
		print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
	end = time.time()
	return end - start



def uiDiscover(): 	#Discover shellcode instructions
	global bPushRet
	global bFstenv
	global bSyscall
	global bHeaven
	global bPEB
	global bCallPop
	global bShellcodeAll
	
	global bDisassembly
	
	# clearConsole()
	
	
	
	
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
		if(re.match("^t$", listIN, re.IGNORECASE)):
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
			print(displayCurrentInstructions(bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, bShellcodeAll))
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
			print(displayCurrentInstructions(bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, bShellcodeAll))
		elif(re.match("^r$", listIN)):
			clearInstructions()
			print("Found shellcode instructions cleared.\n")
		

			# test
		elif(re.match("^z$", listIN, re.IGNORECASE)):

			list_of_labels = ["Searching for disassembly", "Searching for fstenv instructions", "Searching for push ret instructions", "Searching for call pop instructions", "Searching for heaven's gate instructions", "Searching for windows syscall instructions", "Searching for PEB walking instructions"]
			maxLen = get_max_length(list_of_labels)
		#For each boolean set, we execute the finding functions

			if bFstenv and not mBool[o].bFstenvFound:
				newTime= discoverFstenv(maxLen)
				elapsed_time += newTime
						
			if bPushRet and not mBool[o].bPushRetFound:
				newTime= discoverPushRet(maxLen)
				elapsed_time += newTime
				
			if bCallPop and not mBool[o].bCallPopFound:
				newTime=discoverCallPop(maxLen)
				elapsed_time += newTime
				

			if bHeaven and not mBool[o].bHeavenFound:
				newTime= discoverHeaven(maxLen)
				elapsed_time += newTime


				# start = time.time()
				# curLen = len("Searching for heaven's gate instructions")
				# print(cya + " Searching for heaven's gate instructions..."+ res, end="", flush=True)
				# if (rawHex):
				# 	getHeavenRawHex(0, linesBack, 'noSec', m[o].rawData2)

				# else:
				# 	for secNum in range(len(s)):
				# 			data2 = s[secNum].data2
				# 			findAllHeaven(data2, secNum)
				# for i in s:
				# 	if (len(i.save_Heaven_info) > 0):
				# 		mBool[o].bHeavenFound = True
				# if  rawHex:
				# 	if len(m[o].save_Heaven_info) > 0:
				# 		mBool[o].bHeavenFound = True
				# if(mBool[o].bHeavenFound):
				# 	print("{:>{x}}[{}]".format("", gre + "Found" + res, x=15+(maxLen-curLen)))
				# else:
				# 	print("{:>{x}}[{}]".format("", red + "Not Found" + res, x=15+(maxLen-curLen)))
				# end = time.time()
				# elapsed_time += end - start

			if bSyscall and not mBool[o].bSyscallFound:
				newTime	= discoverSyscal(maxLen)
				elapsed_time += newTime

			if bPEB and not mBool[o].bPEBFound:
				newTime	= discoverPEB(maxLen)
				elapsed_time += newTime
			
			if bDisassembly and not mBool[o].bDisassemblyFound:
				newTime= discoverDisassembly(maxLen)
				

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
					print(displayCurrentInstructions(bPushRet, bCallPop, bFstenv, bSyscall, bHeaven, bPEB, bDisassembly, bShellcodeAll))
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
	global rawHex
	x=""
	print("\n ..................\n Technical Settings\n ..................\n")
	techSettingsMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex)
	
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
			uiStringTechMenu()
		elif(techIN[0:1] == "h"):
			techSettingsMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex)
		else:
			print("Invalid input")
		# print("\n..................\nTechnical Settings\n..................\n")
		# techIN = input("> ")

def uiGlobalTechMenu(): 	
	global bytesForward
	global bytesBack
	global linesForward
	global linesBack
	global rawHex
	x = ""
	# print("\n............................\nGlobal settings for PE files\n............................\n")
	globalTechMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex)
	while True:
		print(yel+ " Sharem>" + cya + "Shell>" + res+ red + "Tech>" + res + whi + "Global> " + res, end="")
		gtIN = input()
		if(gtIN == "x"):
			break
		elif gtIN == "":
			continue
		elif(gtIN == "fb"):
			val = input("\tBelow enter the number of bytes to disassemble forward.\n\n")
			try:
				bytesForward = int(val)
				print ("\tMax bytes to dissassemble forward:" + yel + str(bytesForward)+res)
			except:
				print("Invalid input. Enter input as decimal.")
		elif(gtIN == "bb"):
			val = input("\tBelow enter the number of bytes to disassemble backwards.\n\n")
			try:
				bytesBack =int(val)
				print ("\tMax bytes to dissassemble backward:" + yel + str(bytesBack)+res)
			except:
				print("Invalid input. Enter input as decimal.")
		elif(gtIN == "fi"):
			val = input("\tBelow enter value for number of lines to check forward.\n\n")
			try:
				linesForward = int(val)
				print ("\tMax lines to check forward: " + yel + str(linesForward) + res)
			except:
				print("Invalid input. Enter input as decimal.")
		elif(gtIN == "bi"):
			val = input("\tBelow enter value for number of lines to check backward.\n\n")
			try:
				linesBack = int(val)
				print ("\tMax lines to check forward: " + yel + str(linesBack) + res)
			except:
				print("Invalid input. Enter input as decimal.")
		else:
			print("Invalid input. Type x to exit.")
		# print("\n............................\nGlobal settings for PE files\n............................\n")

def uiCPTechMenu(): 	#Tech settings for callpop
	global maxDistance
	cpTechMenu(maxDistance)
	x = ""
	while x != "e":
		print (yel+ " Sharem>" + cya + "Shell>" + res+ red + "Tech>" + res + whi + "CallPop> " + res, end="")
		# cptIN = input("> ")
		cptIN = input()

		if(re.match("^[0-9]*$", cptIN, re.IGNORECASE)):
			try:
				maxDistance = int(cptIN)
			except:
				maxDistance = int(cptIN,16)

			print ("\tMax call distance changed: " + yel + str(maxDistance)+res+"\n")
			break
		elif(cptIN == "x"):
			break
		else:
			print("\nInput invalid; please enter a decimal number or x to exit: ")


def changeStrLen():
	global minStrLen
	print("\n Current string length: "  +yel+ str(minStrLen) +res+"\n")
	
	strLen = input(" Enter minimum string length: ")
	try:
		minStrLen = int(strLen)
		print("\n Minimum string length changed to " +  yel+str(minStrLen) +res+ ".\n")
	except:
		print (" Sorry, input not recognized.")


def uiStringTechMenu():
	global minStrLen
	print("\n Current string length: "  +yel+ str(minStrLen) +res+"\n")
	
	print("\n Enter minimum string length below.\n")
	x=""
	while x!='e':
		print(yel+ " Sharem>" + cya + "Shell>" + res+ red + "Tech>" + res+ "Strings> ", end="")
		stLenIn = input()
		if(re.match("^x$", stLenIn, re.IGNORECASE)):
			break
		elif not (re.match("^[0-9]*$", stLenIn, re.IGNORECASE)):
			print(" Input not recognized. Please enter a decimal.\n")
		elif(stLenIn == "x"):
			break
		else:
			try:
				minStrLen = int(stLenIn)
				print("\n Minimum string length changed to " +  yel+str(minStrLen) +res+ ".\n")
				break
			except:
				print (" Sorry, input not recognized.")
	
def uiPebTechMenu(): 
	#Tech settings for peb
	global pebPoints
	# global pointsLimit
	pebTechMenu(pebPoints)
	x = ""
	print("Enter number of PEB features below.\n")
	while True:
		print (yel+ " Sharem>" + cya + "Shell>" + res+ red + "Tech>" + res + whi + "PEB> " + res, end="")

		pebtIN = input("")
		if(pebtIN.isnumeric()):
			try:
				pebPoints = int(pebtIN)
				if pebPoints > 4:
					pebPoints=4
					print ("\tPEB points may not exceed 4.")
					print ("\tNumber of PEB features changed: " + yel + str(pebPoints)+res+"\n")
					break
			except:
				pass
		elif pebtIN == "x":
			break
		else:
			print("\nInput invalid; please enter a decimal number or x to exit: ")

def pebTechMenu(pointsLimit):
	pebTMenu = gre+"\nPEB Points Settings\n\n"+res
	pebTMenu += "Current minimum number of likely features: " + yel + str(pointsLimit) + res + "\n"	
	pebTMenu += cya + "\tThese unique features to identify PEB wakling.\n"
	pebTMenu += "\tLess than 3 generally is not recommended, due to excess of false positives.\n" + res
	
	print (pebTMenu)

def changePrintGlobals(mode):
	global bpPushRet
	global bpFstenv
	global bpCallPop
	global bpSyscall
	global bpPEB
	global bpHeaven
	global bpModules
	global bpEvilImports
	global bpStrings
	global bpPushStrings
	global bpAll
	global bDisassembly
	global bPrintEmulation

	if mode == "reset":
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
		bPrintEmulation = False
	if mode == "all":
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
		bPrintEmulation=True

def uiPrintPushStrings(bPushStringsFound):
	if mBool[o].bPushStringsFound:
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

def uiPrintStrings(bStringsFound):
	if mBool[o].bStringsFound:	
		print("\n***********\nStrings\n***********\n")
		t=0

		try:
			if not rawHex:
				# if (len(s[t].Strings)) or (len(s[t].wideStrings)) or (len(s[t].pushStrings)):
				if mBool[o].bStringsFound or mBool[o].bWideStringFound or mBool[o].bPushStringsFound:
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
	global bpEvilImports
	global bDisassembly
	global syscallSelection
	global shellbit
	global bpAll
	global bExportAll
	global stringsTempWide
	global pushStringsTemp
	global stringsTemp
	global p2screen
	global bPrintEmulation
	global sharem_out_dir
	global emulation_verbose
	global emulation_multiline


	if sharem_out_dir == "current_dir":
		sh_out_dir = os.getcwd()
	else:
		sh_out_dir = sharem_out_dir


	# clearConsole()
	print(yel + "\n ..........\n Print Menu\n ..........\n" + res)

	printMenu(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bExportAll, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly, bpAll, sh_out_dir,emulation_verbose, emulation_multiline, bPrintEmulation, p2screen)
	if (not mBool[o].bPushRetFound) and (not mBool[o].bFstenvFound) and (not mBool[o].bSyscallFound) and (not mBool[o].bHeavenFound) and (not mBool[o].bPEBFound) and (not mBool[o].bCallPopFound) and (not mBool[o].bStringsFound) and (not mBool[o].bPushStringsFound) and (not mBool[o].bModulesFound) and (not mBool[o].bDisassemblyFound):
		print(red+" Warning: "+res+ "No selections have been discovered yet. Search first.\n")

	x=""
	while True:
		print(yel + " Sharem>" + gre + "Print> " + res, end="")
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
		elif(re.match("^d$", listIN, re.IGNORECASE)):
			sharem_out_dir = input(" Enter output path: ")
			sh_out_dir = sharem_out_dir
			print(" Output path has been changed.")
		elif(re.match("^z$", listIN, re.IGNORECASE)):
			

			if bDisassembly and p2screen:
				if mBool[o].bDisassemblyFound:
					print(cya + "\n***********\nDisassembly\n***********" + res)
					print(gDisassemblyText)
				else:
					print("\nNo disassembly found.\n")
			if bpEvilImports and mBool[o].bEvilImportsFound and p2screen:
				# print(showImports())
				print(yel + "Imports are saved to file." + res)
			if bpPushRet and p2screen:
				if mBool[o].bPushRetFound:
					print(cya + "\n***********\nPush ret\n***********\n" + res)
					printSavedPushRet(shellBit)
				else:
					print("\nNo push ret instructions found.\n")
			if bpModules and mBool[o].bModulesFound and p2screen:
				print(cya + "\n\n*******\nModules\n*******\n\n" + res)
				print(giveLoadedModules("save"))
			# print ("bpstrings",bpStrings)
			# print ("p2screen", p2screen)
			if bpStrings and p2screen:
				uiPrintStrings(mBool[o].bStringsFound)
			if bpPushStrings and p2screen:
				uiPrintPushStrings(mBool[o].bPushStringsFound)
			if bpFstenv and p2screen:
				if mBool[o].bFstenvFound:
					print(cya + "\n***********\nFstenv\n***********\n" + res)
					printSavedFSTENV(shellBit)
				else:
					print("\nNo fstenv instructions found.\n")
			if bpCallPop and p2screen:
				if mBool[o].bCallPopFound:
					print(cya + "\n***********\nCall Pop\n***********\n" + res)
					printSavedCallPop(shellBit)
				else:
					print("\nNo call pop instructions found.\n")
			if bpSyscall and p2screen:
				if mBool[o].bSyscallFound:
					print(cya + "\n***************\nWindows Syscall\n***************\n" + res)
					printSavedSyscall(shellBit)
				else:
					print("\nNo syscall instructions found.\n")
			if bpPEB and p2screen:
				if mBool[o].bPEBFound:
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
				if mBool[o].bHeavenFound:
					print(cya + "\n***************\nHeaven's Gate\n***************\n" + res)
					printSavedHeaven(shellBit)
				else:
					print("No heaven's gate instructions found.\n")
			if bPrintEmulation and p2screen:
				emulation_txt_out(loggedList)

			outputData = generateOutputData()

			printToJson(bpAll, outputData)
			printToText(outputData)
			if not p2screen:
				print("Data saved.")
		elif(re.match("^h$", listIN, re.IGNORECASE)):
			print("\n.......\n")
			printMenu(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bExportAll, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly, bpAll, sh_out_dir,emulation_verbose, emulation_multiline, bPrintEmulation,p2screen)
		elif(re.match("^s$", listIN, re.IGNORECASE)):
			uiPrintSyscallSubMenu()

		elif(re.match("^e$", listIN, re.IGNORECASE)):
			if emulation_verbose: 
				emulation_verbose = False
				print(cya + " Emulation verbose mode disabled.\n" + res)
			else:
				emulation_verbose = True
				print(cya + " Emulation verbose mode enabled.\n" + res)

		elif(re.match("^m$", listIN, re.IGNORECASE)):
			if emulation_multiline: 
				emulation_multiline = False
				print(cya + " Emulation multiline format disabled.\n" + res)
			else:
				emulation_multiline = True
				print(cya + " Emulation multiline format enabled.\n" + res)

		elif(re.match("^j$", listIN, re.IGNORECASE)):
			if(bExportAll):
				bExportAll = False
				print("\nJSON export all disabled\n")
			else:
				bExportAll = True
				print("\nJSON export all enabled\n")
		elif(re.match("^c$", listIN, re.IGNORECASE)):
			changePrintGlobals("reset")
			print("Selections changed.\n")
			print(displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly,bPrintEmulation, bpAll))
		elif(re.match("^all$", listIN, re.IGNORECASE)):
			changePrintGlobals("all")
			print("Selections changed.\n")
			print(displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly, bPrintEmulation, bpAll))


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
				bPM = re.search("( |,|^)EM( |,|$)", printSelectIn, re.IGNORECASE)

				print("\n")
				if bFD:
					bDisassembly = False if bDisassembly else True

				if bPM:
					bPrintEmulation = False if bPrintEmulation else True

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
					changePrintGlobals("all")
				if bNone:
					changePrintGlobals("reset")
				if bpPushRet and bpFstenv and bpCallPop and bpSyscall and bpPEB and bDisassembly and bpHeaven and bpStrings and bpEvilImports and bpModules and bpPushStrings:
					bpAll = True
				if bPR or bFE or bCP or bSy or bPB or bHG or bST or bPS or bIM or bLM or bFD or bPM:
					print("Selections changed.\n")
					print(displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisassembly,bPrintEmulation, bpAll))
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
			printSavedSyscall(syscallPrintBit, showDisassembly)
		elif(re.match("^c$", syscallIN, re.IGNORECASE)):
			for osv in syscallSelection:
				osv.toggle = False
			print("\nChanges applied: ")
			syscallPrintSubMenu(syscallSelection, showDisassembly, syscallPrintBit, False)

		elif(re.match("^b$", syscallIN, re.IGNORECASE)):
			print(red+"Warning: "+res+"64-bit is standard for all syscalls.\n\tDeviate with extreme care.\nChange architecture:\n\n\t"+cya+"1"+res+" - 32-bit\n\t"+cya+"2"+res+" - 64-bit\n")
			syscallBitIN = input("> ")
			if(syscallBitIN[0:1] == "1" ):
				syscallPrintBit = 32
			elif(syscallBitIN[0:1] == "2"): 
				syscallPrintBit = 64
			print("\tArchitecture changed.")
			# print("Returning to syscall selection submenu.\n")

			

		elif(re.match("^d$", syscallIN, re.IGNORECASE)):
			showDisassembly = False if showDisassembly else True
			print("\tShow disassembly set to " + str(showDisassembly)+".")
		# print("\n................\nSyscall Settings\n................\n")

def uiModulesSubMenu():		#Find and display loaded modules
	global bpModules
	
	global modulesMode		#1-3, whichever option we want
	# global gMS_API_MIN_skip
	print("\n"+yel+"............................\nFind Modules Beyond the IAT\n............................\n"+res)
	print("This feature will statically discover modules used in the PE file.\n")
	if(rawHex):
		print(red+"Warning: "+res+"No PE file selected.\n")
	printModulesMenu(modulesMode)
	x = 'i'
	while x != 'e':
		print(yel+" .......\n Modules\n .......\n"+res)
		print(yel + " Sharem>" + res + cya + "Modules> "+res,end="")
		modIn = input("")
		if(re.match("^x$", modIn, re.IGNORECASE)):
			break
		elif(re.match("^[1-3]$", modIn, re.IGNORECASE)):
			modulesMode = int(modIn)
			if (modulesMode == 1):
				print("Selection changed to: "+gre+"Find only DLLs in IAT\n"+res)
			if (modulesMode == 2):
				print("Selection changed to: "+gre+"Find DLLs in IAT and beyond\n"+res)
			if (modulesMode == 3):
				print("Selection changed to: "+gre+"Find DLLs in IAT, beyond, and more\n"+res)
		# elif(re.match("^e$", modIn, re.IGNORECASE)):
		# 	changeMSAPIMIN()
		elif(re.match("^h$", modIn, re.IGNORECASE)):
			printModulesMenu(modulesMode)
		elif(re.match("^p$", modIn, re.IGNORECASE)):
			print(giveLoadedModules("save"))
		elif(re.match("^r$", modIn, re.IGNORECASE)):
			clearMods()
			print("Loaded modules cleared.\n")
		elif(re.match("^z$|^m$", modIn, re.IGNORECASE)):
			if(rawHex):
				print("\nNo PE file selected\n")
			else:
				runInMem()
				print(giveLoadedModules())
				giveLoadedModules("save")

		else:
			print("Input not recognized.\n")
		
	return



def runInMem():
	global modulesMode
	

	clearMods()
	print("\nFinding DLLs in IAT\n")
	getDLLs()
	if(modulesMode > 1):
		print("Finding DLLs beyond the IAT\n")
		digDeeper(PE_DLLS)
	if(modulesMode > 2):
		print("Finding even more DLLs\n")
		# dontPrint()
		digDeeper2()
	# allowPrint()
	InMem2()
	colorama.init()

	if(len(IATs.foundDll) > 0):
		mBool[o].bModulesFound = True

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
	

#Jan102022  #December
def uiFindStrings():
	
	
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
	
	global useStringsFile
	global chMode
	
	# 


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
		#jan102022
		# print ("hello!")
		elif(re.match("^e$", stringIN, re.IGNORECASE)):
			chMode = True
			print("\nEmulation enabled\n")
		elif (re.match("^s$", stringIN, re.IGNORECASE)):
			pushStringsOutput(5)	# Testing only
			# getPushStrings(5)
		elif (re.match("^k$", stringIN, re.IGNORECASE)):
			changeStrLen()
		elif(re.match("^n$", stringIN, re.IGNORECASE)):

			changeRegsFile()
			useStringsFile = True
		elif(re.match("^z$", stringIN, re.IGNORECASE)):

			if bAsciiStrings and not mBool[o].bStringsFound:
				discoverAsciiStrings()
			elif mBool[o].bStringsFound:
				print (red+"\tAscii strings already found; reset if need be."+res)
			# print ("discoverui", mBool[o].bWideStringFound)
			if bWideCharStrings and not mBool[o].bWideStringFound:
				discoverUnicodeStrings()
			elif mBool[o].bWideStringFound:
				print (red+"\tUnicode strings already found; reset if need be."+res)
			if bPushStackStrings and not mBool[o].bPushStringsFound:
				discoverStackStrings()
			elif mBool[o].bPushStringsFound:
				print (red+"\tStack strings already found; reset if need be."+res)
	
		elif(re.match("^p$", stringIN, re.IGNORECASE)):
			printStrings()
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

		else:
			print("\nInput not recognized.\n")

def uiShellcodeStrings():
	global minStrLen
	global stringReadability
	global checkGoodStrings
	global sBy
	
	
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
	print(red+"\nThis function is deprecated!"+res+"\n............\nFind Shellcode Strings\n............\n")
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
				if(goodString(m[o].rawData2, x, minStrLen)):
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
						if(goodString(m[o].rawData2, x, minStrLen)):
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
	print("\n ............\n Find Imports\n ............\n")
	
	if(rawHex):
		print(red+"Warning: "+res+"No PE file selected.\n")
	importsMenu()
	x=""
	while x != "e":
		print("\n ............\n Find Imports\n ............\n")
		print(yel + " Sharem>" + cya + "Imports> "+ res, end="")
		importsIN = input()
		if(re.match("^x$", importsIN, re.IGNORECASE)):
			break
		elif(re.match("^h$", importsIN, re.IGNORECASE)):
			importsMenu()
		elif(re.match("^r$", importsIN, re.IGNORECASE)):
			clearImports()
		elif(re.match("^z$", importsIN, re.IGNORECASE)):
			if not rawHex:
				if not mBool[o].bEvilImportsFound:
					findEvilImports()
				if(len(FoundApisName) > 0):

					mBool[o].bEvilImportsFound = True
					print(showImports())
			else:
				print("No PE file selected.\n")
		elif(re.match("^p$", importsIN, re.IGNORECASE)):
			print(showImports())
		else:
			print("Input not recognized.\n")

def renameFilename():
	global fileName

def hashShellcode(shell=None, mode=None):
	global rawHex
	# print("hash:")
	# print(hashlib.md5(open('shellcode4.bin','rb').read()).hexdigest())
	# print(hashlib.md5(shell).hexdigest())
	# print(hashlib.sha256(open('shellcode4.bin','rb').read()).hexdigest())
	# print(hashlib.sha256(shell).hexdigest())

	# hash2 = ssdeep.hash('Also called fuzzy hashes, Ctph can match inputs that have homologies.')
	# print ("ssdeep tester", hash2)
	# ssdeepHash1 = ssdeep.hash(open('shellcode4.bin','rb').read())
	if not rawHex:
		return
	if shell != None:
		ssdeepHash = ssdeep.hash(shell)
		md5sum=(hashlib.md5(shell).hexdigest())
		sha256=(hashlib.sha256(shell).hexdigest())
	# if shell ==None:
	# 	ssdeepHash = ssdeep.hash(m[o].rawData2)
	# 	md5sum=(hashlib.md5(m[o].rawData2).hexdigest())
	# 	sha256=(hashlib.sha256(m[o].rawData2).hexdigest())
	if mode == sample:	
		shHash.setMd5(md5sum)
		shHash.setSha256(sha256)
		shHash.setSsdeep(ssdeepHash)
	if mode == unencryptedShell:
		shHash.setMd5(md5sum, unencryptedShell)
		shHash.setSha256(sha256, unencryptedShell)
		shHash.setSsdeep(ssdeepHash, unencryptedShell)
	if mode == decoderShell:
		shHash.setSha256(sha256, decoderShell)
		shHash.setSsdeep(ssdeepHash, decoderShell)
		shHash.setMd5(md5sum, decoderShell)
	if mode == unencryptedBodyShell:
		shHash.setMd5(md5sum, unencryptedBodyShell)
		shHash.setSha256(sha256, unencryptedBodyShell)
		shHash.setSsdeep(ssdeepHash, unencryptedBodyShell)
	if shell == None and (mode == allObject or mode == None ):		
		ssdeepHash = ssdeep.hash(m[o].rawData2)
		md5sum=(hashlib.md5(m[o].rawData2).hexdigest())
		sha256=(hashlib.sha256(m[o].rawData2).hexdigest())
		shHash.setMd5(md5sum)
		shHash.setSha256(sha256)
		shHash.setSsdeep(ssdeepHash)

		ssdeepHash = ssdeep.hash(sh.unencrypted)
		md5sum=(hashlib.md5(sh.unencrypted).hexdigest())
		sha256=(hashlib.sha256(sh.unencrypted).hexdigest())
		shHash.setMd5(md5sum, unencryptedShell)
		shHash.setSha256(sha256, unencryptedShell)
		shHash.setSsdeep(ssdeepHash, unencryptedShell)

		ssdeepHash = ssdeep.hash(sh.decoderStub)
		md5sum=(hashlib.md5(sh.decoderStub).hexdigest())
		sha256=(hashlib.sha256(sh.decoderStub).hexdigest())
		shHash.setSha256(sha256, decoderShell)
		shHash.setSsdeep(ssdeepHash, decoderShell)
		shHash.setMd5(md5sum, decoderShell)

		ssdeepHash = ssdeep.hash(sh.decodedBody)
		md5sum=(hashlib.md5(sh.decodedBody).hexdigest())
		sha256=(hashlib.sha256(sh.decodedBody).hexdigest())
		shHash.setMd5(md5sum, unencryptedBodyShell)
		shHash.setSha256(sha256, unencryptedBodyShell)
		shHash.setSsdeep(ssdeepHash, unencryptedBodyShell)

def hashShellcodeTestShow(mode=None):
	if mode==sample:
		print(shHash.show())
	if mode == unencryptedShell:
		print(shHash.show(unencryptedShell))
	if mode == decoderShell:
		print(shHash.show(decoderShell))
	if mode == unencryptedBodyShell:
		print(shHash.show(unencryptedBodyShell))
	if mode == None:		
		print(shHash.show())
		print(shHash.show(unencryptedShell))
		print(shHash.show(decoderShell))
		print(shHash.show(unencryptedBodyShell))

def hashShellcodeTestShow2(mode=None):
	if mode==sample:
		print(shHash.show())
	if mode == unencryptedShell:
		print(shHash.show(unencryptedShell))
	if mode == decoderShell:
		print(shHash.show(decoderShell))
	if mode == unencryptedBodyShell:
		print(shHash.show(unencryptedBodyShell))
	if mode == None:	
		try:	
			print(shHash.show())
		except Exception as e:
			print(e)
			pass

		try:	
			print(shHash.show(unencryptedShell))
		except Exception as e:
			print(e)
		pass

		try:	
			print(shHash.show(decoderShell))
		except Exception as e:
			print(e)
		pass

		try:	
			print(shHash.show(unencryptedBodyShell))
		except Exception as e:
			print(e)
		pass
		


def useMd5asFilename():
	global useHash
	global filename2
	useHash=True
	if useHash:
		filename2=shHash.md5
	print ("\tMd5 hash will be used to save output.")
		


def findAll():  #Find everything
	global peName
	
	
	
	global bDisassembly
	
	
	
	
	
	
	
	
	global modulesMode
	global minStrLen
	global elapsed_time

	mBool[o].bWideStringFound = False

	list_of_labels = ["Searching for push stack strings","Searching for unicode strings", "Searching for strings", "Searching for disassembly", "Searching for fstenv instructions", "Searching for push ret instructions", "Searching for call pop instructions", "Searching for heaven's gate instructions", "Searching for windows syscall instructions", "Searching for PEB walking instructions"]
	max_len = get_max_length(list_of_labels)
	if not rawHex:
		print("Finding imports.\n")
		if not mBool[o].bEvilImportsFound:
			findEvilImports()
		if(len(FoundApisName) > 0):
			mBool[o].bEvilImportsFound = True

	if(rawHex):
		pass
	else:
		runInMem()
	if not mBool[o].bStringsFound:
		print("Finding strings.\n")

		discoverAsciiStrings(max_len)
	if not mBool[o].bWideStringFound:
		discoverUnicodeStrings(max_len)
	if not mBool[o].bPushStringsFound:
		discoverStackStrings(max_len)

	print("\n\n")

	if bFstenv and not mBool[o].bFstenvFound:
		newTime= discoverFstenv(max_len)
		elapsed_time += newTime
		
	if bPushRet and not mBool[o].bPushRetFound:
		newTime= discoverPushRet(max_len)
		elapsed_time += newTime
		
	if bCallPop and not mBool[o].bCallPopFound:
		newTime=discoverCallPop(max_len)
		elapsed_time += newTime

	if bHeaven and not mBool[o].bHeavenFound:
		newTime= discoverHeaven(max_len)
		elapsed_time += newTime

	if bSyscall and not mBool[o].bSyscallFound:
		newTime	= discoverSyscal(max_len)
		elapsed_time += newTime

	if bPEB and not mBool[o].bPEBFound:
		newTime	= discoverPEB(max_len)
		elapsed_time += newTime
	
	if bDisassembly and not mBool[o].bDisassemblyFound:
		newTime= discoverDisassembly(max_len)

	

	print("\n")
	# print(".........................\n")
	print(" Search completed.\n")

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

	# print("S --> before clear", s)

	global rawHex
	for secNum in s:
		secNum.save_PEB_info.clear()
		secNum.save_FSTENV_info.clear()
		secNum.save_Egg_info.clear()
		secNum.save_Heaven_info.clear()
		secNum.save_Callpop_info.clear()
		secNum.save_PushRet_info.clear()

	# o = 0
	for o in m:
		m[o].save_PEB_info.clear()
		m[o].save_FSTENV_info.clear()
		m[o].save_Egg_info.clear()
		m[o].save_Heaven_info.clear()
		m[o].save_Callpop_info.clear()
		m[o].save_PushRet_info.clear()
		# o+= 1
	# s.clear()
	# print("S --> after clear", s)
	# m.clear()
	# sections.clear()

	clearFoundBooleans()


def clearMods():			#Clears our module list
	
	IATs.foundDll = []
	FoundApisName = []
	IATs.found = []
	IATs.path = []
	IATs.originate = []
	mBool[o].bModulesFound = False

def clearFoundBooleans(): 	#Clears bools saying we've found data
	
	
	
	
	
	
	
	
	
	

	mBool[o].bPushRetFound = False
	mBool[o].bFstenvFound = False
	mBool[o].bSyscallFound = False
	mBool[o].bHeavenFound = False
	mBool[o].bPEBFound = False
	mBool[o].bCallPopFound = False
	mBool[o].bStringsFound = False
	mBool[o].bEvilImportsFound = False
	mBool[o].bModulesFound = False
	mBool[o].bWideStringFound = False
	mBool[o].bPushStringsFound = False



def clearAll():		#Clears all found data and booleans
	clearInstructions()
	clearMods()
	clearFoundBooleans()
	clearStrings()
	clearImports()

def clearStrings():
	
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp
	
	

	mBool[o].bStringsFound = False
	mBool[o].bWideStringFound=False
	mBool[o].bPushStringsFound=False
	try:
		t = 0
		for sec in s:
			sec.Strings.clear()
			sec.wideStrings.clear()
			sec.pushStrings.clear()

	except Exception as e:
		print("Clear strings Here", e)
		pass
	stringsTempWide.clear()
	pushStringsTemp.clear()
	stringsTemp.clear()

def clearImports():
	
	FoundApisName.clear()
	mBool[o].bEvilImportsFound = False



def emulation_json_out(apiList):


	# api1 = {"api_name": "winexec",
	# 	"parameters":[{
	# 	"type":"LPCSTR lpCmdLine",
	# 	"value":"cmd.exe /c ping google.com > c:\\result.txt",

	# 	}, {

	# 	"type":"UINT uCmdShow",
	# 	"Value":"0x5"
	# 	}],
	# 	"return_value":"INT 0x5"

	# }
	artifacts, net_artifacts, file_artifacts, exec_artifacts = findArtifacts()



	# emu_dlls = ["kernel32", "advapi32", "user32"]
	# artifacts = ["c:\\result.txt", "cmd.exe", "google.com", "result.txt", "user32.dll", "calc.exe", "notepad.exe", "www.msn.com", "http://c2.net", "c:\\windows\system32\mstsc.exe"]

	
	r = "(http|ftp|https):\/\/?|(www\.)?[a-zA-Z]+\.(com|eg|net|org)"
	rfile = ".*(\\.*)$"
	for i in artifacts:
		result = re.search(r, i)

		if result:
			web_artifacts.append(i)
		if i[-4:] == ".exe":
			exec_artifacts.append(i)

		result = re.search(rfile,i)
		if result:
			file_artifacts.append(i)

	# sample = [('WinExec', '0x123123', '0x20', 'INT', ['cmd.exe /c ping google.com > C:\\result.txt', '0x5'], ['LPCSTR', 'UINT'], ['lpCmdLine', 'uCmdShow'], False), ('EncyptFileA', '0x321321', '0x20', 'INT', ['C:\\result.txt'], ['LPCSTR'], ['lpFileName'], False),
# ('LoadLibraryA', '0x1337c0de', '0x45664c88', 'HINSTANCE', ['user32.dll'], ['LPCTSTR'], ['lpLibFileName'], False),('MessageBoxA', '0xdeadc0de', '0x20', 'INT', ['0x987987', 'You have been hacked by an elite haxor. Your IP address is now stored in C:\\result.txt but it is encrypted :)cmd.exe /c ping google.com > C:\\result.txt', 'You have been hacked by an elite haxor. Your IP address is now stored in C:\\result.txt but it is encrypted :)cmd.exe /c ping google.com > C:\\result.txt', '0x0'], ['HWND', 'LPCSTR', 'LPCSTR', 'UINT'], ['hWnd', 'lpText', 'lpCaption', 'uType'], False)]

	# api_names = []
	api_params_values = []
	api_params_types = []
	api_params_names = []
	# api_address = []
	# ret_values = []
	# ret_type = []

	list_of_apis = []



	emulation_dict = {"api_calls":[],
					  "dlls":[],
					  "artifacts":[],
					  "web_artifacts":[],
					  "file_artifacts":[],
					  "executable_artifacts":[]
	}

	for i in apiList:
		api_dict = {}
		api_name = i[0]
		api_address = i[1]
		ret_value = i[2]
		ret_type = i[3]
		api_dict["api_name"] = api_name
		api_dict["return_value"]= ret_value
		api_dict["address"] = api_address
		api_dict['parameters'] = []

		api_params_values = i[4]
		api_params_types = i[5]
		api_params_names = i[6]
		for pTyp, pName, pVal in zip(api_params_types, api_params_names, api_params_values):
			api_dict['parameters'].append({"type":pTyp + " " + pName,
												"value":pVal})
		# list_of_apis.append(api_dict)
		emulation_dict["api_calls"].append(api_dict)


	emulation_dict["dlls"].extend(logged_dlls)
	emulation_dict["artifacts"].extend(artifacts)
	emulation_dict["executable_artifacts"].extend(exec_artifacts)	
	emulation_dict["web_artifacts"].extend(net_artifacts)
	emulation_dict["file_artifacts"].extend(file_artifacts)
	# print(emulation_dict)
	# for api in list_of_apis:
	# 	t = 0
	# 	for x in api_params_types:
	# 		pTyp = api_params_types[t]
	# 		pName = api_params_names[t]
	# 		pVal = api_params_values[t] 
	# 		print("---> ", pTyp, pName, pVal)
			# t += 1
			# api['parameters'].append({"type":pTyp + " " + pName,
									  # "value":pVal

			# })
	# print(list_of_apis)
	# sys.exit()

	# "api_calls": [
 #      {
 #         "api_name": "winexec",
 #         "parameters": [
 #            {
 #               "type": "LPCSTR lpCmdLine",
 #               "value": "cmd.exe /c ping google.com > c:\\result.txt"
 #            },
 #            {
 #               "type": "UINT uCmdShow",
 #               "Value": "0x5"
 #            }
 #         ],
 #         "return_value": "INT 0x5"
 #      }
 #   ],
	

	

	return emulation_dict













	
def emulation_txt_out(apiList):
	
	# for each in apiList:
		# print (type(each), each, "\n\n")
	sample = [('WinExec', '0x123123', '0x20', 'INT', ['cmd.exe /c ping google.com > C:\\result.txt', '0x5'], ['LPCSTR', 'UINT'], ['lpCmdLine', 'uCmdShow'], False), ('EncyptFileA', '0x321321', '0x20', 'INT', ['C:\\result.txt'], ['LPCSTR'], ['lpFileName'], False),
('LoadLibraryA', '0x1337c0de', '0x45664c88', 'HINSTANCE', ['user32.dll'], ['LPCTSTR'], ['lpLibFileName'], False),('MessageBoxA', '0xdeadc0de', '0x20', 'INT', ['0x987987', 'You have been hacked by an elite haxor. Your IP address is now stored in C:\\result.txt but it is encrypted :)cmd.exe /c ping google.com > C:\\result.txt', 'You have been hacked by an elite haxor. Your IP address is now stored in C:\\result.txt but it is encrypted :)cmd.exe /c ping google.com > C:\\result.txt', '0x0'], ['HWND', 'LPCSTR', 'LPCSTR', 'UINT'], ['hWnd', 'lpText', 'lpCaption', 'uType'], True)]
	

	artifacts, net_artifacts, file_artifacts, exec_artifacts = findArtifacts()

	api_names = []
	api_params_values = []
	api_params_types = []
	api_params_names = []
	api_address = []
	ret_values = []
	ret_type = []
	api_bruteforce = False

	for i in apiList:
		api_names.append(i[0])
		api_address.append(i[1])
		ret_values.append(i[2])	
		ret_type.append(i[3])
		api_params_values.append(i[4])
		api_params_types.append(i[5])
		api_params_names.append(i[6])
		api_bruteforce = i[7]

	api_par_bundle = []
	# for v, t in zip(api_params_types[0], api_params_types[0]):
	# 	api_par_bundle.append(v + " " + t)

	# artifacts = ["c:\\result.txt", "cmd.exe", "google.com", "result.txt", "user32.dll", "www.msn.com", "http://74.32.123.2:8080", "c:\\windows\\system32\\ipconfig.exe"]


	# web_artifacts = ["www.msn.com", "http://74.32.123.2:8080", "google.com"]
	# file_artifacts = ["c:\\result.txt", "cmd.exe", "result.txt"]
	# executables = ["c:\\windows\\system32\\ipconfig.exe", "cmd.exe"]

	txt_output = ""
	no_colors_out = ""

	txt_output += "\n**************************\n"
	txt_output += "     Emulation\n"
	txt_output += "**************************\n\n"

	no_colors_out += txt_output


	txt_output += mag + "\n************* APIs *************\n\n" + res
	no_colors_out += "\n************* APIs *************\n\n"
	

	verbose_mode = emulation_verbose
	t = 0
	for eachApi in api_names:
		
		apName = api_names[t]
		offset = api_address[t]
		pType = api_params_types[t]
		pName = api_params_names[t]
		TypeBundle = []
		retVal = ret_values[t]
		retType = ret_type[t]
		paramVal = api_params_values[t]
		# bundle = [list(zipped) for zipped in zip(pType, pName)]
		for v, typ in zip(pType, pName):
			TypeBundle.append(v + " " + typ)
		joinedBund = ', '.join(TypeBundle)
		joinedBundclr = joinedBund.replace(",", cya + ","+res)
		# print(type(joinedBundclr), type(apName), type(offset), "---->", offset)

		# try: 
		# 	offset= int((str(offset)),16 )
		retBundle = retType + " " + retVal
		if verbose_mode:
			
			txt_output += '{} {}{}\n'.format(gre + offset + res, yel + apName+ res, cya + "("+res + joinedBundclr + cya +")"+res) # Example: WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
			no_colors_out += '{} {}({})\n'.format(offset , apName, joinedBund)
		else:
			txt_output += '{} {}{} {}{}\n'.format(gre + offset + res, yel + apName+ res, cya + "("+res + joinedBundclr +cya +")"+res , cya + "Ret: "+res,red + retBundle + res) # Example: WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
			no_colors_out += '{} {}({}): {}\n'.format(offset , apName, joinedBund, retBundle)


		t += 1
		if verbose_mode:
			for ptyp, pname, pval in zip(pType, pName, paramVal):
				txt_output += '\t{} {} {}\n'.format(cya + ptyp , pname + ":"+res, pval)
				no_colors_out += '\t{} {}: {}\n'.format(ptyp, pname, pval)

			# 	txt_output += '\t{}: {}\n'.format(cya + p + res, val)
			# 	no_colors_out += '\t{}: {}\n'.format(p, val)
			# txt_output += "\n"
			# no_colors_out += "\n"
			txt_output += "\t{} {}\n".format( red + "Return:"+res, retBundle)
			if api_bruteforce:
				txt_output += "\t{}\n\n".format( whi + "Brute-forced"+res,)
			else:
				txt_output+= "\n"

			no_colors_out += "\t{} {}\n\n".format( "Return:", retVal)

	if emulation_multiline:
		emu_dll_list = "\n"
		emu_dll_list += '\n'.join(logged_dlls)

		emu_artifacts_list = "\n"
		emu_artifacts_list += "\n".join(artifacts)
		emu_artifacts_list += "\n"

		emu_webartifacts_list = "\n"
		emu_webartifacts_list += "\n".join(net_artifacts)
		emu_webartifacts_list += "\n"


		emu_fileartifacts_list = "\n"
		emu_fileartifacts_list += "\n".join(file_artifacts)
		emu_fileartifacts_list += "\n"


		# emu_execartifacts_list = "\n"
		# emu_execartifacts_list += "\n".join(executables)
		# emu_execartifacts_list += "\n"

	else:
		emu_dll_list= ', '.join(logged_dlls)
		emu_artifacts_list= ', '.join(artifacts)
		emu_webartifacts_list = ", ".join(net_artifacts)
		emu_fileartifacts_list = ", ".join(file_artifacts)
		# emu_execartifacts_list = ", ".join(executables)


	txt_output += mag + "\n************* DLLs *************\n" + res
	no_colors_out += "\n************* DLLs *************\n"

	txt_output += "{}{:<18} {}\n".format(cya + "DLLs" + res, "",emu_dll_list)
	no_colors_out += "{}{:<18} {}\n".format("DLLs", "",','.join(logged_dlls))

	txt_output += mag + "\n************* Artifacts *************\n" + res
	no_colors_out += "\n************* Artifacts *************\n"

	txt_output += "{}{:<13} {}\n".format(cya + "Artifacts" + res,"", emu_artifacts_list)
	txt_output += "{}{:<9} {}\n".format(cya + "Web artifacts" + res,"", emu_webartifacts_list)
	txt_output += "{}{:<8} {}\n".format(cya + "File artifacts" + res,"", emu_fileartifacts_list)
	# txt_output += "{}{:<2} {}\n\n".format(cya + "Executable artifacts" + res,"", emu_execartifacts_list)

	no_colors_out += "{}{:<13} {}\n".format("Artifacts","", emu_artifacts_list)
	no_colors_out += "{}{:<9} {}\n".format("Web artifacts","", emu_webartifacts_list)
	no_colors_out += "{}{:<8} {}\n".format("File artifacts","", emu_fileartifacts_list)
	# no_colors_out += "{}{:<2} {}\n\n".format("Executable artifacts","", emu_execartifacts_list)

	# print(txt_output)
	# sys.exit()

	if bPrintEmulation:
		print(txt_output)
	else:
		return no_colors_out

	# for api, data in eachApi.items():
			
		# 	if api == "api_name":

		# 		apName = data
		# 		# apitxtTmp = apitxtTmp.replace("<ap>", yel + apName + res)
		# 	elif api == "offset":
		# 		offset = data
		# 	elif api == "parameters":
		# 		paramsList = data
		# 		for p in paramsList:
		# 			for t, val in p.items():
						

		# 				if t == "type":
		# 					pType = val

		# 					pTemp = pTemp.replace("<type>", gre + pType + res)
		# 					# print("Type ---> ", pType)
		# 					typeList.append(str(pType))

		# 				elif t == "value":
		# 					pValue = val
		# 					pTemp = pTemp.replace("<value>",gre + pValue + res)
		# 					typevalList.append(pValue)

		# 		# pTemp += endParams

		# 	elif api == "return_value":
		# 		retVal = data
		# 		apitxtTmp = apitxtTmp.replace("<ret>", gre + retVal + res)
	# print("Apis ", api_names)
	# print("Apis params names ", api_params_names)
	# print("Api params", api_params)


	# api1 = [{"api_name": "winexec",
	# 		"offset":"0x1234",
	# 		"parameters":[{
	# 		"type":"LPCSTR lpCmdLine",
	# 		"value":"cmd.exe /c ping google.com > c:\\result.txt",
	# 		}, 
	# 		{"type":"UINT uCmdShow",
	# 		"value":"0x5"
	# 		}],

	# 	"return_value":"INT 0x5"

	# },
	# {"api_name": "EncryptFileA",
	# 		"offset":"0x2222",
	# 		"parameters":[{
	# 		"type":"LPCSTR lpFileName",
	# 		"value":"c:\\result.txt",

	# 	}, 
	# 	{"type":"UINT uCmdShow",
	# 	"Value":"0x5"
	# 	}],

	# 	"return_value":"INT 0x20"

	# }]
	"""
	0x2345 WinExec(LPCSTR lpCmdLine, UINT uCmdShow)
	LPCSTR lpCmdLine: cmd.exe /c ping google.com > c:\result.txt
	UINT uCmdShow: 0x5

	Return: Int 0x5

	Artifacts --> ["c:\\result.txt", "cmd.exe", "google.com", "result.txt", "user32.dll"]
	Web Artifacts --> [...]
	"""


	# apiText = """
	# |---------[ Api name: <ap> ]---------
	# |
	# |     {}: <ret>	
	# |
	# |
	# |     ++++++ {} ++++++
	# |
	# """.format(red + "Return Value" + res, mag + "Parameters" + res)
	# paramsText = """|
	# |      {} : <type>
	# |      {}: <value>
	# |
	# """.format(cya + "Type" + res, cya + "Value" + res)
	# endParams = """|
	# |
	# |     ++++++ {} ++++++
	# """.format(mag + "End of Parameters" + res)
	# separator = """|
	# |
	# |
	# |"""

	# dllTxt = ', '.join(emu_dlls)
	# artifactsTxt = ', '.join(artifacts)
	# dllList = """|
	# |
	# |     ++++++ {} ++++++
	# |
	# |      {}
	# """.format(mag + "DLLS" + res, cya+dllTxt+res)

	# artifactsList = """|
	# |
	# |     ++++++ {} ++++++
	# |
	# |      {}
	# """.format(mag + "Artifacts" + res, cya+artifactsTxt+res)

	
	"""
	|=========[ Api name: EncryptFileA ]=========
	|
	|	****** Return Value: 0x20 ******
	|
	|	++++++ Parameters ++++++
	|
	|		Type : LPCSTR lpFileName
	|		Value: c:\\result.txt
	|
	|
	|=========[ Api name: EncryptFileA ]=========
	|
	|	****** Return Value: 0x20 ******
	|
	|	++++++ Parameters ++++++
	|
	|		Type : LPCSTR lpFileName
	|		Value: c:\\result.txt
	"""

	# "Api_calls":[

# 		{"api_name":"WinExec",
# 		 "parameters":[{"Name":"lpCmdLine",
# 		 				"Type":"LPCSTR",
# 		 				"Value":"cmd.exe /c ping google.com > c:\\result.txt"},

# 		 				{"Name":"uCmdShow",
# 		 				"Type":"UINT",
# 		 				"Value":"0x5"}

# 		 ]
# 		}

# 	],

# 	"DLLS":["kernel32", "advapi32", "user32"],

# 	"artifacts":["c:\\result.txt", "cmd.exe", "google.com", "result.txt", "user32.dll"]


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
	
	
	
	
	
	
	
	global shellBit
	global rawHex
	global filename
	global sharem_out_dir
	global FoundApisName

	time = datetime.datetime.now()
	filetime = time.strftime("%Y%m%d_%H%M%S")
	time = time.strftime("%Y-%m-%d %H:%M:%S")
	t = 0
	for char in peName:
		if(char == '.'):
			break
		t += 1

	filename = filename.split("\\")[-1]
	noExtension = peName[0:t]
	if filename == "":
		outfile = peName.split(".")[0]
		outfileName = peName
		chkExt = peName[-4]
	else:	
		outfile = filename.split(".")[0]
		outfileName = filename
		chkExt = filename[-4]

	output_dir = os.getcwd()

	if sharem_out_dir == "current_dir":
		output_dir = os.getcwd()
	else:
		output_dir = sharem_out_dir


	filler = ""
	if chkExt == ".":
		filler = ""
	else:
		filler = "-output"


	
	# importsOut = showImports(out2File=True)

	importsDict = {"imports":[]}
	# print("length: ", len(FoundApisName), FoundApisName)
	for dll, api, offset in FoundApisName:
		dll = dll.decode()
		api = api.decode()
		offset = str(offset)

		importsDict["imports"].append({"dll":dll,
								  "offset":offset,
								  "api":api})



# 	emulation_dict = {
# 	"Api_calls":[

# 		{"api_name":"WinExec",
# 		 "parameters":[{"Name":"lpCmdLine",
# 		 				"Type":"LPCSTR",
# 		 				"Value":"cmd.exe /c ping google.com > c:\\result.txt"},

# 		 				{"Name":"uCmdShow",
# 		 				"Type":"UINT",
# 		 				"Value":"0x5"}

# 		 ]
# 		}

# 	],

# 	"DLLS":["kernel32", "advapi32", "user32"],

# 	"artifacts":["c:\\result.txt", "cmd.exe", "google.com", "result.txt", "user32.dll"]

# }
	# emulationOut = output_dir + "\\" + outfile+filler + "\\"  + "Test" +"-32"  + ".json"
	#jsonFileName =  os.getcwd() + "\\" + noExtension + "\\output_" + peName + "_" + filetime + ".json"
	if useDirectory and not known_arch:
		if current_arch == 32:
			jsonFileName =  output_dir + "\\" + outfile+filler + "\\"  + outfileName +"-32" + "_" + filetime + ".json"

		elif current_arch == 64:
			jsonFileName =  output_dir + "\\" + outfile +filler+ "\\"  + outfileName + "-64"+ "_" + filetime + ".json"

	else:
		if shellBit == 32:

			jsonFileName =  output_dir + "\\" + outfile +filler+ "\\" + outfileName + "-32"+"_" + filetime + ".json"
		else:
			jsonFileName =  output_dir + "\\" + outfile +filler+ "\\" + outfileName + "-64"+"_" + filetime + ".json"



	jsonImports =  output_dir + "\\" + outfile+filler + "\\"  + outfileName + "-imports"  + ".json"

	# jsonFileName =  os.getcwd() + "\\" + outfile + "\\" + outfileName + "_" + filetime + ".json"
	# print("outfile: ", outfile, "outfileName", outfileName)
	# input()
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
	outimports = open(jsonImports, "w")
	js_imports = json.dumps(importsDict, indent=3)
	outimports.write(js_imports)
	# emufile = open(emulationOut, "w")
	# emu_ob = json.dumps(emulation_dict, indent=3)
	js_ob = json.dumps(outputData, indent = 3)

	outfile.write(js_ob)
	# emufile.write(emu_ob)


def formatPrint(i, add4, addb, pe=False, syscall=False):
	#print('{1:>{0}}'.format(length, string))
	# print("---------> ", len(i.op_str))


	if print_style == "right":
		length = 35

		if not pe:
			if not syscall:

				val =('{0:<6s} {1:<{2}s} {3:<8s}'.format(i.mnemonic, i.op_str, length, add4))
				return val
			else:
				monic = i.split("|")[0]
				op_str = ''.join(i.split("|")[1])

				val =('{0:<6s} {1:<{2}s} {3:<8s}'.format(monic, op_str, length, add4))
				return val

		else:
			val =('{0:<6s} {1:<{2}s} {3:<12s} {4:<10}'.format(i.mnemonic, i.op_str, length, add4, "(offset " + addb + ")"))
			return val
	elif print_style == "left":
		length = 30
		if not pe:
			if not syscall:
				val =('{0:<10s} {1:<4s} {2} '.format(add4, i.mnemonic, i.op_str ))
				return val
			else:
				monic = i.split("|")[0]
				op_str = i.split("|")[1]
				# print(op_str)
				# input()

				val =('{0:<6s} {1:<{2}s} {3:<8s}'.format(monic, op_str, length, add4))
				return val

		else:
			val =('{0:<10s} {1:<4s} {2:<{3}s} {4}'.format(add4, i.mnemonic, i.op_str , length, "(offset " + addb + ")"))

			# val =('{0:<6s} {1:<{2}s} {3:<12s} {4:<10}'.format(i.mnemonic, i.op_str, length, add4, "(offset " + addb + ")"))
			return val
	else:
		print("Error: format style is not correct, it should be either right, or left.")
		sys.exit()

def generateOutputData(): #Generate the dictionary for json out
	
	global shellBit
	global rawHex
	global brawHex
	global bstrLit


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
	if rawHex:
		jsonData['decoded_stub'] = ''

	jsonData['emulation'] = emulation_json_out(loggedList)

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
	if (mBool[o].bStringsFound):
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
	if (mBool[o].bPushRetFound):
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
				CODED2 = m[o].rawData2[address:(printEnd)]
				# print ("1",binaryToStr(CODED2))
				# print ("\n2",binaryToStr(m[o].rawData2[pushAdd:(printEnd)]))

			

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

						if retOffset == addb:
							val5.append(val)
							break
						else:
							val5.append(val)
						# if "ret" in val:
						# 	val5.append(val)
						# 	break
						# else:
						# 	val5.append(val)
						# if checkRet:
						# 	if not stopRet:
						# 		val5.append(val)
						# 		stopRet = True
						# 	else:
						# 		pass
						# if not stopRet:
						# 	val5.append(val)
						# val5.append(val)
					# pOut=""
					# pSize=len(pushOffset)-1
					# t=0
					
					
					# for p in pushOffset:
						

					# 	if t<pSize:
					# 		pOut+=p + ", "
					# 	else:
					# 		pOut+=p
					# 	t+=1
					# pushOffset=pOut
					jsonData['pushret'].append({'address': hex(address),'pushOffset':pushOffset, 'retOffset': retOffset, "modSecName": modSecName, "disassembly":val5, "internalData" : {'secNum': secNum, 'NumOpsDis': NumOpsDis,'points': points}})

	if (mBool[o].bCallPopFound):
		if(rawHex):
			for item in m[o].save_Callpop_info:
				address = item[0]
				NumOpsDis = item[1]
				modSecName = item[2]
				secNum = item[3]
				distance = item[4]
				pop_offset = item[5]
				CODED2 = m[o].rawData2[(address):int(pop_offset, 16) + 1]
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

	if (mBool[o].bFstenvFound):
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
				CODED2 = m[o].rawData2[int(FPU_offset, 16):(int(printEnd, 16))]
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
	if (mBool[o].bHeavenFound):
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
	if (mBool[o].bPEBFound):
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
				CODED2 = m[o].rawData2[address:(address+NumOpsDis)]
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
	if (mBool[o].bSyscallFound):
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
				# CODED2 = m[o].rawData2[address:(printEnd)]

				# print(NumOpsDis)
				CODED2 = m[o].rawData2[address:(address+20)]
				converted = [string.replace("\t", "") for string in converted]
				if(eax != "unknown"):
					# syscalls = returnSyscalls(int(eax, 0))
					# print(syscalls)
					# input()
					syscalls = getSyscallRecent(int(eax, 0), 64, "print2Json")

				# CODED3 = CODED2
				# val5 = []
				# for i in callCS.disasm(CODED3, address):

				# 	add4 = hex(int(i.address))
				# 	addb = hex(int(i.address))
				# 	val = formatPrint(i, add4, addb)
				# 	val5.append(val)
					# print(i.mnemonic, i.op_str, add4, addb)
					# val = formatPrint(i, add4, addb, pe=True)

					# val =('{:<6s} {:<32s} {:<8s} {:<10}'.format(i.mnemonic, i.op_str, add4, "(offset " + addb + ")"))
					# val2.append(val)
					# val3.append(add2)
					# val5.append(val)

					# if c0_offset == addb:
					# 	break
				# print(val5)
				# input()

				# for idx, val in enumerate(converted):
				# 	if val.find("(offset") != -1:
						
				# 		converted[idx] = val[:val.find("offset")-18]
				val5 = []
				for i in converted:
				# print(converted, type(converted))
					if i != "":
						allInstr = i.split(" ")
						# print("Everything ---> ", allInstr)
						mnemonic = allInstr[0]
						add4 = allInstr[-3]
						addb = allInstr[-2:]
						op_str = ' '.join(allInstr[1:-3])

						# print("----> mnemonic" , mnemonic, type(mnemonic))
						# print("-----> op_str", op_str, type(op_str))
						# input()
						convOut = formatPrint(mnemonic + "|" + op_str, add4, addb, syscall=True)
						val5.append(convOut)

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
	if(mBool[o].bModulesFound):
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
	if(mBool[o].bEvilImportsFound):
		for dll, api, offset in FoundApisName:
			jsonData['imports'].append({'dll':dll.decode(), 'api':api.decode(), 'address':str(offset)})

	return jsonData


def dontPrint():
	sys.stdout = open(os.devnull, 'w')
	# sys.stdout = open('nul', 'w')

def allowPrint():
	sys.stdout = sys.__stdout__

def printToTextPushRet(bPushRetFound,data):
	# print (mBool[o].bPushRetFound,"found")
	if mBool[o].bPushRetFound:
		outString="\n\n***********\nPush ret\n***********\n\n"
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
		outString="\nNo push ret instructions found.\n"
	return outString
def printToTextStrings(bStringsFound):
	if mBool[o].bStringsFound:
		outString="\n\n***********\nStrings\n***********\n\n"
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
							# outString += ("**unicode strings**\n")
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
		outString="\nNo strings found.\n"
	return outString

def printToText(outputData):	#Output data to text doc
	#output data from generateoutputdata
	
	
	global bDisassembly
	
	
	
	
	
	
	
	global bpModules
	global bpEvilImports
	global shellBit
	global stringsTemp
	global stringsTempWide
	global pushStringsTemp
	global syscallString
	global gDisassemblyText
	global save_bin_file
	global filename
	global sharem_out_dir
	global bEvilImportsFound
	global bPrintEmulation

	data = outputData
	#Used for section info
	if (rawHex):
		info = showBasicInfo()
	else:
		info = showBasicInfoSections()
	info=cleanColors(info)

	time = datetime.datetime.now()
	epoch = time.timestamp()
	filetime = time.strftime("%Y%m%d_%H%M%S")
	time = time.strftime("%Y-%m-%d %H:%M:%S")
	# t = 0
	# for char in peName:
	# 	if(char == '.'):
	# 		break
	# 	t += 1
	# noExtension = peName[0:t]s
		

	# print("File name in printtotext", filename)
	#print("********************************** ", peName, " **********************")
	filename = filename.split("\\")[-1]
	if filename == "":
		outfile = peName.split(".")[0]
		outfileName = peName
		chkExt = peName[-4]
	else:	
		outfile = filename.split(".")[0]
		outfileName = filename
		chkExt = filename[-4]

	filler = ""
	if chkExt == ".":
		filler = ""
	else:
		filler = "-output"
	output_dir = os.getcwd()

	if sharem_out_dir == "current_dir":
		output_dir = os.getcwd()
	else:
		output_dir = sharem_out_dir
		


	# txtFileName =  os.getcwd() + "\\" + outfile + "\\output_" + outfileName + "_" + filetime + ".txt"
	if useDirectory and not known_arch:
		if current_arch == 32:
			txtFileName =  output_dir + "\\" + outfile + filler+"\\" + "\\" + outfileName+"-32" + "_" + filetime + ".txt"
		elif current_arch == 64:
			txtFileName =  output_dir + "\\" + outfile + filler+"\\" + "\\" + outfileName + "-64"+ "_" + filetime + ".txt"

	else:
		if shellBit == 32:
			txtFileName =  output_dir + "\\" + outfile +filler+ "\\" + outfileName + "-32"+"_" + filetime + ".txt"
		else:
			txtFileName =  output_dir + "\\" + outfile +filler+ "\\" + outfileName + "-64"+"_" + filetime + ".txt"


	# print("Saving location: ", outfile, outfileName)
	# print("Saving location: ", txtFileName)

	# txtDis = open(directory+"disassembly\\"+filename[:-4]+"-disassembly.txt", "w")

# 	red ='\u001b[31;1m'
# gre = '\u001b[32;1m'
# yel = '\u001b[33;1m'
# blu = '\u001b[34;1m'
# mag = '\u001b[35;1m'
# cya = '\u001b[36;1m'
# whi = '\u001b[37m'
# res = '\u001b[0m'
	os.makedirs(os.path.dirname(txtFileName), exist_ok=True)
	text = open(txtFileName, "w")


	disFileName = output_dir + "\\" + outfile + filler+"\\" + outfileName + "-disassembly.txt"
	binFileName = output_dir + "\\" + outfile + filler+"\\" + outfileName + "-disassembly.bin"

	if mBool[o].bEvilImportsFound:
		importsName =  output_dir + "\\" + outfile + filler+"\\" + outfileName + "-imports.txt"
		importData = showImports(out2File=True)
		importFp = open(importsName, "w")
		importFp.write(importData)
		importFp.close()

	disasm = open(disFileName, "w")
	disasm.write(gDisassemblyText)
	disasm.close()

	# print("Type --> ", type(m[o].rawData2), m[o].rawData2)
	if save_bin_file and rawHex:
		binasm = open(binFileName, "wb")
		binasm.write(m[o].rawData2)
		binasm.close()


	outString =  'Filename: ' + outfileName + "\n"
	outString += 'File Type: ' + outputData['fileType'] + "\n"
	outString += 'Architecture: ' + str(shellBit) +"-bit\n"
	outString += 'Date Analyzed: ' + time + "\n"
	outString += "Seconds since last epoch: " + str(epoch) + "\n"
	outString += info


	#If we've found and are printing a category, then do so
	if bpModules and mBool[o].bModulesFound:
		outString+="\n\n*******\nModules\n*******\n\n"
		outString+=giveLoadedModules("save")
	if bpEvilImports and mBool[o].bEvilImportsFound:
		outString+="\n\n*****************\nImports\n*****************\n"
		# outString+= showImports()
		for api, dll, offset in FoundApisName:
			try:
				outString += (' {:<14s} {:<32s} {:<0}'.format(api.decode(), dll.decode(), str(offset))) + "\n"
			except:
				pass

	if bpStrings:
		outString+=printToTextStrings(mBool[o].bStringsFound)
		
	if bpPushRet:
		outString+=printToTextPushRet(mBool[o].bStringsFound,data)

	if bpFstenv:
		if mBool[o].bFstenvFound:
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
		if mBool[o].bCallPopFound:
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
		if mBool[o].bSyscallFound:
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
		if mBool[o].bPEBFound:
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
		if mBool[o].bHeavenFound:
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
		if mBool[o].bDisassemblyFound:
			outString += "\n\n****************\nDisassembly\n****************\n\n"
			outString += gDisassemblyText
	else:
		outString += "\nNo Disassembly found.\n"
	#disassembly = shellDisassemblyStart(filename, "txt")
	#dontPrint()
	#disassembly = takeBytes(m[o].rawData2, 0)
	#printAgain()
	
	#disassembly = disassembly.split("Raw Hex:")[0]
	#print(disassembly)
	#outString += "\n\n\n-------------------------- Disassembly --------------------------------\n\n"
	#outString += disassembly
	bPrintEmulation = False
	emulation_txt = emulation_txt_out(loggedList)
	bPrintEmulation = True
	text.write (outString)
	text.write(emulation_txt)
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

	# emu_test()
	# emulation_txt_out()
	# sys.exit()	
	# emulation_json_out()	
	CliParser()
	init2(filename)

	if rawHex:
		newModule(o,rawData2, gName)
	else:
		newModule(peName,rawData2, gName)
		Extraction()

	shHash=shellHash()
	sh=shellcode(rawData2)
	IATs = FoundIATs()
	sBy=DisassemblyBytes()
	emuObj = emulationOptons()
	if rawHex:
		hashShellcode(m[o].rawData2, sample)  # if comes after args parser
		if useHash:
			filename2=shHash.md5sum

	bramwell=False
	austin=False
	viewBool=False
	tarek=False
	jacob=False
	BramwellID=0
	AustinID=1
	view=2
	JacobID=3

	#user=BramwellID       #comment out, so only one user shows, or is the last one shown.
	# user=view      #comment out, so only one user shows, or is the last one shown.

	# user = AustinID
	user=view
	# user=BramwellID

	
	if user==AustinID:
		austin=True
		bramwell=False
		viewBool = False
	elif user==BramwellID:

		bramwell=True
		austin=False
		viewBool=False
	elif user==view:
		bramwell=False
		austin=False
		viewBool=True
		# debugging=False
	elif user==JacobID:
		jacob=True
		bramwell=False
		austin=False
		viewBool=False
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

		# yes =559
		yes=2
		# yes=4452

		if yes ==4452:

			print ("start InMemoryOrderModuleList getDLLs")
			getDLLs()
			# InMem2()
			
			digDeeper(PE_DLLS)
			print ("start digDeeper2")
			# InMem2()
			
			digDeeper2()

			print ("again")
			digDeeper2()

			print ("start InMem2")
			InMem2()
			print ("end InMem2")
			print(giveLoadedModules())
		if yes == 53:
			# # print (binaryToStr(m[o].rawData2))
			# if not os.path.exists(directory+'bins'):
			# 	os.makedirs(directory+'bins')
			# assembly=binaryToText(m[o].rawData2)
			# newBin = open(directory+"bins\\"+filename[:-4]+".bin", "wb")
			# newBin.write(m[o].rawData2)
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

			print (len(m[o].rawData2))
			# input()
			if mBool[o].bDoFindStrings:
		# import sharem
				print ("finding strings")
				findStrings(m[o].rawData2,3)
				findStringsWide(m[o].rawData2,3)
				findPushAsciiMixed(m[o].rawData2,3)
				print ("found strings")
			shellDisassemblyInit(m[o].rawData2)
			# bramwellStart2()

		if yes ==559:


			print ("results")
			hashShellcode(m[o].rawData2, unencryptedBodyShell)   ## options (None, unencryptedBodyShell,unencryptedShell, decoderShell )

			hashShellcodeTestShow(unencryptedBodyShell)  ## options (None, unencryptedBodyShell,unencryptedShell, decoderShell )

			X86_CODE32_LOOP = b"\x41\x4a\xeb\xfe"
			X86_CODE32 = b"\x41\x4a\x66\x0f\xef\xc1" # INC ecx; DEC edx; PXOR xmm0, xmm1
			random = b"\x5F\x5F\x01\xFF\xBF\x05\x00\x00\x00" 
			X86_CODE32_JUMP = b"\xeb\x02\x90\x90\x90\x90\x90\x90" # jmp 4; nop; nop; nop; nop; nop; nop
			#shellcode object
			sh.setRawData2(X86_CODE32_LOOP)
			# sh.setRawData2(X86_CODE32_LOOP)

			print (binaryToStr(m[o].rawData2))
			sh.setDecoderStub(X86_CODE32)
			print (binaryToStr(sh.decoderStub))
			sh.setDecodedBody(random)
			print (binaryToStr(sh.decodedBody))			
			sh.setDecoded(X86_CODE32_JUMP)
			print (binaryToStr(sh.unencrypted))

			hashShellcode()   ## options (sample, unencryptedBodyShell,unencryptedShell, decoderShell )

			hashShellcodeTestShow(sample)  ## options (sample, unencryptedBodyShell,unencryptedShell, decoderShell )
			print ("\n\n")
			hashShellcodeTestShow(unencryptedBodyShell)  ## options (sample, unencryptedBodyShell,unencryptedShell, decoderShell )
			print ("\n\n")
			hashShellcodeTestShow(unencryptedShell)  ## options (sample, unencryptedBodyShell,unencryptedShell, decoderShell )
			print ("\n\n")
			hashShellcodeTestShow(decoderShell)  ## options (sample, unencryptedBodyShell,unencryptedShell, decoderShell )
			print ("\n\n")
			hashShellcodeTestShow()  ## options (sample, unencryptedBodyShell,unencryptedShell, decoderShell )

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
	################################ viewBool'S WORK AREA
	if viewBool:
		if useDirectory:

			work_from_directory()
			print("**************** Completed ******************")
			sys.exit()
		# if workDir:
		# 	work_from_directory()
		# 	sys.exit()
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
			# 			m[o].rawData2 = f.read()

			# 		filename = i
			# 		init2(filename)
			# 		startupPrint()
			# 		# print("peb: ", mBool[o].bPEBFound)

			# 		clearAll()

				# 	f = open(file2Check, "rb")
				# filename = file2Check
				# m[o].rawData2 = f.read()
				# f.close()
				# rawHex = True
				# rawBin = True


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