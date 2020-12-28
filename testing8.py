
from capstone import *
import re, string
import binascii
from lists import *
import os
from sharem import findStrings
# from sharem import *

# end classs 

FindStringsStatus=True
GoodStrings=["cmd", "CMD", "NET", "net","add","ADD", "Win", "WIN", "http"]

#####SAME AS FROM SHAREM
filename=""


def testme():
	print("it works")

numArgs = len(sys.argv)
if numArgs > 1:			# to get full functionality, need to put file location for binary that is installed (may need to find some DLLs in that directory)
	txtDoc= re.search( r'\.txt', sys.argv[1], re.M|re.I)
	if txtDoc:
		filename= sys.argv[1]

if len(filename) > 1:
	testing=filename

stringsTemp=[]
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
	print (wordSize, "size")
	print ((letters+numbers+spaces)/wordSize, "num")

	print ("size", len(data), len(word))
	# if len(data) == len(word):
	if len(word) >= 0.85*len(data):
		print ("badsize")
		return False
	print (letters, (letters+numbers+spaces)/wordSize, len(word), size)
	if (letters >= 2) and ((letters+numbers+spaces)/wordSize > .65) and (len(word) >=size):
		print ("yes, goodString")
		return True

	if word in GoodStrings:
		return True
	return False


def removeLastLine(strLine):  #removes last line of disasembly that starts with \n0x
	array = strLine.split("\n0x")
	new = ""
	array.pop()
	for word in array:
		new +=  word+"\n"
	return new

def findStrings(binary,Num):#,t):
	dprint2("findstrings ", Num)
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
rawHex ="31C9B9ADDE6564C1E9105168776F726B686F697420684578706C89E2B9CAADDE29C1E91851686E73203A687574746F687365206268206D6F756870696E67685377617089E331C951525351FFD0"
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
	# print ("bytes\n\n")
	# print (type(bytesStr))
	# for val in bytesStr:
	# 	print(hex(val),' ', end='')
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
	dprint ("checkForLabel " + addb)
	for label in labels:
		if label==addb:
			val="     label_"+addb+":\n"
			dprint (val)
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


def disHereMakeDB2(data,offset, end, mode, CheckingForDB):
	print("dis: disHereMakeDB2 - range " + str(hex(offset)) + " " + str(hex(end)) )
	num_bytes=end-offset
	print (num_bytes)
	printAllShByRange(offset,offset+num_bytes)

	global labels
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
	for x in range (length):
		bytesRes= (binaryToStr(data[offset:stop]))
		instr="db 0"+bytesRes[1:]+" (!)"
		Ascii2=makeAsciiforDB(bytesRes)
		val +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
		# sVal +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
		if shBy.strings[offset]==True:
			dbFlag=True
			stringInProgress=True
			stringval=val
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
				print ("beforeS", sVal, beforeS)
				sVal=""
				startAddString=str(hex(offset))
				stringVala=shBy.stringsValue[offset]+" ; string"
				dbOut+=(binaryToStr(data[t:t+1]))
				print (stringVala)
				
			if offset>stringStart:
				print (stringVala)
				print ("dbout ", hex(t))
				dbOut+=(binaryToStr(data[t:t+1]))
		if (shBy.strings[offset]==False):
			print("FoundNOTSTRING", hex(stringStart), hex(offset),"off")

			stringInProgress=False
			if dbFlag==False:
				print ("dbflag=False")
				truth,res=checkForLabel(str(hex(offset)),labels)
				if truth:
					val=val+res
					stringVal=stringVal+res
				stringVal +=('a {:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				print ("y offset", hex(t))
		
				# stringVal= beforeS + stringVal
				skip=True
			if dbFlag==True:

				print ("sV, offset: ", hex(offset), "value ", shBy.stringsValue[offset])
				nada=""
				truth,res=checkForLabel(str(hex(offset)),labels)
				if truth:
					val=val+res
					stringVal=stringVal+res
				stringVal+=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(startAddString, stringVala,dbOut,nada ))
				stringVal +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				if len(beforeS) > 0:
					stringVal= beforeS +"\n"+ stringVal
				print ("stringVal", stringVal)
				dbOut=""
				print (stringVal)
				dbFlag=False
				skip=True
			if not skip:
				stringVal+=('3 {:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
			skip=False
		offset +=1
		stop += 1
		t+=1
		w+=1
		# print ("t-eof", hex(w), hex(length))
		if w==(length):
			if dbFlag==True:
				nada=""
				# stringVal +=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
				stringVal+=('{:<10s} {:<35s}{:<26s}{:<10s}\n'.format(startAddString, stringVala,dbOut,nada ))
				# stringVal= beforeS + stringVal
				dbOut=""
				dbFlag=False
				if len(dbOut)>0:
					stringVal+=('c {:<10s} {:<35s}{:<26s}{:<10s}\n'.format(str(hex(offset)), instr, bytesRes, Ascii2))
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
			removeBadOffsets(addy)
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
	add = hex(int(i.address))
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
		if CantSkip:
			val2.append(val)
			val3.append(add2)
			val5.append(val)
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
class DisassByt:
	def _init_(self): #, name):
		"""Initializes the data."""
		self.offsets = []   # starting offsets of bytes - may not always be 0 or 1
		self.values = [] # the hex value
		self.instructions =[]  # t/f - is it instructions--intinialized as instructions first
		self.data =[] # t/f is data bytes
		self.ranges=[] # does it identify ranges?
		self.bytesType=[]
		self.strings=[] # TRUE if strings, false if not
		self.stringsStart=[] #offset the strings starts @
		self.stringsValue=[]



shBy=DisassByt()
shBy._init_()


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

def takeBytes(shellBytes,startingAddress):
	global shBy
	global FindStringsStatus
	print ("take bytes")

	i=startingAddress
	for x in shellBytes:
		shBy.offsets.append(i)
		shBy.values.append(x)
		shBy.instructions.append(True)
		shBy.data.append(False)
		shBy.bytesType.append(True) # True = instructions
		shBy.strings.append(False)
		shBy.stringsStart.append(0xffffffff)
		shBy.stringsValue.append("")
		i+=1

	# modifyShByRange(data, 0x14, 0x19, "d")
	print ("FindStringsStatus", FindStringsStatus)
	if FindStringsStatus:
		findStrings(shellBytes,3)
	anaFindFF(shellBytes)

	out=findRange(shellBytes, startingAddress)  #1st time helps do corrections
	out=findRange(shellBytes, startingAddress) # makes sure all corrections fully implemented
	# printAllShBy()
	return out
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
	print("anaFindStrings")
	print (stringsTemp)
	OP_FF=b"\xff"

	for word,offset,distance  in stringsTemp:
		print ("\t"+ str(word) + "\t" + str(hex(offset)) + "\t" + str(hex(distance))) 
		# print (word, offset, distance, "before modify range")
		# modifyStringsRange(offset, offset+distance, "s", word)
		# print (goodString(data,word,6),"goodstring", word)
		if goodString(data,word,5):
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
	###   end
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
	print (stringsTemp)
	OP_FF=b"\xff"
	offset=0
	maxV=len(data)
	escape=False
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
		while (test == OP_FF):
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
			print (total, "ffTotal2")
			modifyShByRange(data, offset, offset+distance+total, "d")
			# modifyStringsRange(offset, offset+distance+total, "s", word)
		if escape:
			# print ("inc offset", escape, hex(offset))
			if total >1:
				offset+=total
			else:
				offset+=1
		if not escape:
			# print ("inc offset, not", escape, hex(offset))
			offset+=1
######
# printFromArrayLiteralToHex(ArrayLiteral)

# printFromhexToBytes(rawHex)
# printFromStringLiteralToBytes(stringLiteral)


# ans=fromArrayLiteralToHex(ArrayLiteral)

# ans2=fromhexToBytes(rawHex)

def splitDirectory(filename):
	
	array = filename.split("\\")
	new = ""
	if len(array) >1:
		relFilename=array[len(array)-1]
		array.pop()
		for word in array:
			new +=  word
		return new+"\\", relFilename
	else:
		filename="shellcode.txt"
		return "", filename

def testing8Start(shellArg):
	global filename
	ans3=fromStringLiteralToBytes(stringLiteral)
	# printBytes(ans)
	# printBytes(ans2)

	printBytes(ans3)
	ans4=readShellcode(shellArg) 
	ansTiny=readShellcode(shellcode6)  #4
	# ans4=readShellcode(shellcode7) 

	printBytes(ans4)
	# print (disHereShell(ans4, False, False, "ascii", True))
	# disHereMakeDB
	out= (disHereMakeDB(ans4, 0x04, 0x05, "ascii", True))

	print ("final!")
	print (out)
	disassembly=takeBytes(ans4,0)
	printAllShBy()
	printAllShByStrings()

	ans, valb_1, valb_2, num_bytes= disHereTiny(ansTiny)
	print(ans)
	print(valb_1)
	print(valb_2)


	### Saving disassembly and .bin

	# print (filename)
	directory, filename= (splitDirectory(filename))
	print (directory)
	print (filename)
	directory=""

	if not os.path.exists(directory+'outputs'):
		print ("No exist")
		os.makedirs(directory+'outputs')
	print (directory+"outputs\\"+filename[:-4]+".bin")
	newBin = open(directory+"outputs\\"+filename[:-4]+".bin", "wb")
	newBin.write(ans4)
	newBin.close()
	newDis = open(directory+"outputs\\"+filename[:-4]+"-disassembly.txt", "w")
	newDis.write(disassembly)
	newDis.close()
	ans=signedNegHexTo(int(valb_2,16))

	print(hex(ans))
	print((ans))
	
	print (filename)


# fromShellTxt= readShellcode()
# print(fromShellTxt)
# printFromStringLiteralToBytes(fromShellTxt)
# ans4=fromStringLiteralToBytes(fromShellTxt)
# printBytes(fromShellTxt)

testing="shellcodes\\testing.txt"
testing2="shellcodes\Add Admin User Shellcode (194 bytes) - Any Windows Version.txt"


# testing8Start(testing)
testing8Start(shellcode4)
