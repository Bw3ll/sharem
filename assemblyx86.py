import re
realEAX =[] # tuple 
realEAX2=0
realEAX.append(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realEAX2 = (tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realEBX=[]
realEBX.append(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realEBX2=(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realECX=[]
realECX.append(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realECX2=(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realEDX=[]
realEDX.append(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realEDX2=(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realESI=[]
realESI.append(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realESI2=(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realEDI=[]
realEDI.append(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realEDI2=(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realESP=[]
realESP.append(tuple((0x00, 0x00, 0x00, 0x01, "0x00BB0001")))
realESP2=(tuple((0x00, 0x00, 0x00, 0x00, "0x00BB0001")))
realEBP=[]
realEBP.append(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))
realEBP2=(tuple((0x00, 0x00, 0x00, 0x00, "0x00000000")))

regsTemp=[]

strHex="0x0040aabb"

def splitWords2(strInput):
	array = strInput.split(" ")
	reg=""
	regValueStr=""
	reg=array[0]
	regValueStr=array[1].strip()
	return reg, regValueStr

def readRegs():
	global regsTemp
	regsTemp [:] =[]
	file1 = open('regs.txt', 'r') 
	Lines = file1.readlines() 
	for line in Lines: 
		reg, regValueStr=splitWords2(line)
		regsTemp.append(tuple((reg, regValueStr)))

	for each in regsTemp:
		print(each)
	setAll()





def setReg(strHex, timeless, reg):
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
	# strHex=strHex[2 :  :]
	r1=strHex[2:4]
	r2=strHex[4:6]
	r3=strHex[6:8]
	r4=strHex[8:10]
	reg = reg.lower()
	# reg="ecx"
	if reg == "eax":
		if timeless:
			realEAX.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEAX2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "ebx":
		if timeless:
			realEBX.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEBX2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "ecx":
		if timeless:
			realECX.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realECX2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "edx":
		if timeless:
			realEDX.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEDX2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "esi":
		if timeless:
			realESI.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realESI2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "edi":
		if timeless:
			realEDI.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEDI2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "ebp":
		if timeless:
			realEBP.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEBP2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "esp":
		if timeless:
			realESP.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realESP2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "ebx":
		if timeless:
			realEBX.appfend(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEBX2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))

def setReg16(strHex, timeless, reg):
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
	r1="00"
	r2="00"
	r3=strHex[2:4]
	r4=strHex[4:6]

	if reg == "ax":
		if timeless:
			realEAX.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEAX2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "bx":
		if timeless:
			realEBX.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEBX2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "cx":
		if timeless:
			realECX.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realECX2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "dx":
		if timeless:
			realEDX.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEDX2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "si":
		if timeless:
			realESI.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realESI2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "di":
		if timeless:
			realEDI.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEDI2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "bp":
		if timeless:
			realEBP.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realEBP2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	elif reg == "sp":
		if timeless:
			realESP.append(tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex )))
		else:
			realESP2=tuple((int(r1, 16),int(r2, 16),int(r3, 16),int(r4, 16),strHex ))
	
def hxRStr(strHex):
	ch = re.match( r'0x', strHex, re.M|re.I)
	if ch:
		strHex=strHex[2:]
	if len(strHex)<2:
		strHex="0"+strHex
	return strHex
def hxR(intHex):
	strHex=str(hex(intHex))
	ch = re.match( r'0x', strHex, re.M|re.I)
	if ch:
		strHex=strHex[2:]
	if len(strHex)<2:
		strHex="0"+strHex
	return strHex

def retR32(reg, mode):
	reg=reg.lower()
	printReg =[]
	if reg == "eax":
		printReg= realEAX2
	if reg == "ebx":
		printReg= realEBX2
	if reg == "ecx":
		printReg= realECX2
	if reg == "edx":
		printReg= realEDX2
	if reg == "esi":
		printReg= realESI2
	if reg == "edi":
		printReg= realEDI2
	if reg == "ebp":
		printReg= realEBP2
	if reg == "esp":
		printReg= realESP2
	res=""
	# print (printReg)
	r1,r2,r3,r4,s= printReg
	res= hxR(r1)+hxR(r2)+hxR(r3)+hxR(r4)
	if (mode =="x"):
		res= "0x"+res
	return res

def retR32Int(reg):
	global realESP2
	global realEBP2
	printReg=""
	if reg == "eax":
		printReg= realEAX2
	if reg == "ebx":
		printReg= realEBX2
	if reg == "ecx":
		printReg= realECX2
	if reg == "edx":
		printReg= realEDX2
	if reg == "esi":
		printReg= realESI2
	if reg == "edi":
		printReg= realEDI2
	if reg == "ebp":
		print ("hi")
		printReg= realEBP2
	if reg == "esp":
		printReg= realESP2
	print (printReg)
	r1,r2,r3,r4,s= printReg
	return int(s,16)

def showAllRegs():
	strEAX=retR32("eax", "x")
	strEBX=retR32("ebx", "x")
	strECX=retR32("ecx", "x")
	strEDX=retR32("edx", "x")
	strESI=retR32("esi", "x")
	strEDI=retR32("edi", "x")
	strEBP=retR32("ebp", "x")
	strESP=retR32("esp", "x")
	output="EAX: " + strEAX+"\n"
	output+="EBX: " + strEBX+"\n"
	output+="ECX: " + strECX+"\n"
	output+="EDX: " + strEDX+"\n"
	output+="ESI: " + strESI+"\n"
	output+="EDI: " + strEDI+"\n"
	output+="EBP: " + strEBP+"\n"
	output+="ESP: " + strESP+"\n"
	print(output)





	print (strEAX)
def helperadd16b(r1, r2,r3,r4,s,strHex, regBit):
	val=int(strHex,16)
	if regBit=="16b":
		r16=int(s[6:10],16)
		r16+=val
		val2=str(hex(r16))
		if len(val2)==6:
			r3 = val2[2:4]
			r4 = val2[4:6]
		elif len(val2)==4:
			r4 = val2[2:4]
			r3="00"
		test = hxR(r1)
		res= "0x"+hxR(r1)+hxR(r2)+r3+r4
		return r1,r2,int(r3,16),int(r4,16),res
	elif regBit=="32":
		r32=int(s, 16)
		r32+=val
		val2=str(hex(r32))
		if len(val2)==11:
			val2=val2[0:10]
		if len(val2)==10:
			r1 = val2[2:4]
			r2 = val2[4:6]
			r3 = val2[6:8]
			r4 = val2[8:10]
		elif len(val2)==8:
			r1 = "0x00"
			r2 = val2[4:6]
			r3 = val2[6:8]
			r4 = val2[8:10]
		elif len(val2)==6:
			r1 = "0x00"
			r2 = "0x00"
			r3 = val2[6:8]
			r4 = val2[8:10]
		elif len(val2)==4:
			r1 ="0x00"
			r2 = "0x00"
			r3 = "0x00"
			r4 = val2[8:10]
		res= "0x"+r1+r2+r3+r4
		print ("res " + res)
		return int(r1,16),int(r2,16),int(r3,16),int(r4,16),res
def addReg16b(strHex, timeless, reg, regBit):
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
	strHex=strHex[2 :  :]
	val=int(strHex,16)
	reg=reg.lower()

	# regBit=16
	if reg == "eax":
		if timeless:
			r1, r2, r3, r4,s= realEAX[len(realEAX)-1]
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEAX.append(tuple((r1, r2,r3, r4,res )))
		else:
			r1, r2, r3, r4,s= realEAX2
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEAX2=tuple((r1, r2,r3, r4,res ))
	elif reg == "ebx":
		if timeless:
			r1, r2, r3, r4,s= realEBX[len(realEBX)-1]
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEBX.append(tuple((r1, r2,r3, r4,res )))
		else:
			r1, r2, r3, r4,s= realEBX2
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEBX2=tuple((r1, r2,r3, r4,res ))
	elif reg == "ecx":
		if timeless:
			r1, r2, r3, r4,s= realECX[len(realECX)-1]
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realECX.append(tuple((r1, r2,r3, r4,res )))
		else:
			r1, r2, r3, r4,s= realECX2
			r1b, r2b, r3b, r4b, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realECX2=tuple((r1b, r2b,r3b, r4b,res ))
	elif reg == "edx":
		if timeless:
			r1, r2, r3, r4,s= realEDX[len(realEDX)-1]
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEDX.append(tuple((r1, r2,r3, r4,res )))
		else:
			r1, r2, r3, r4,s= realEDX2
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEDX2=tuple((r1, r2,r3, r4,res ))
	elif reg == "esi":
		if timeless:
			r1, r2, r3, r4,s= realESI[len(realESI)-1]
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realESI.append(tuple((r1, r2,r3, r4,res )))
		else:
			r1, r2, r3, r4,s= realESI2
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realESI2=tuple((r1, r2,r3, r4,res ))
	elif reg == "edi":
		if timeless:
			r1, r2, r3, r4,s= realEDI[len(realEDI)-1]
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEDI.append(tuple((r1, r2,r3, r4,res )))
		else:
			r1, r2, r3, r4,s= realEDI2
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEDI2=tuple((r1, r2,r3, r4,res ))
	elif reg == "ebp":
		if timeless:
			r1, r2, r3, r4,s= realEBP[len(realEBP)-1]
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEBP.append(tuple((r1, r2,r3, r4,res )))
		else:
			r1, r2, r3, r4,s= realEBP2
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realEBP2=tuple((r1, r2,r3, r4,res ))
	elif reg == "esp":
		if timeless:
			r1, r2, r3, r4,s= realESP[len(realESP)-1]
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realESP.append(tuple((r1, r2,r3, r4,res )))
		else:
			r1, r2, r3, r4,s= realESP2
			r1, r2, r3, r4, res = helperadd16b(r1,r2,r3,r4,s, strHex, regBit)
			realESP2=tuple((r1, r2,r3, r4,res ))

def FindReg(reg):
	reg=reg.lower()
	global regsTemp
	regValueStr=""
	for x, y  in regsTemp:
		x=x.lower()
		if (x==reg):
			ch = re.match( r'0x', y, re.M|re.I)
			if ch:
				return y
			else:
				return "0x"+y
	return "0x00000000"

def setAll():
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
	global regsTemp

	eaxVal=FindReg("eax")	
	ebxVal=FindReg("ebx")
	print (ebxVal)	
	ecxVal=FindReg("ecx")
	edxVal=FindReg("edx")	
	esiVal=FindReg("esi")	
	ediVal=FindReg("edi")
	espVal=FindReg("esp")	
	ebpVal=FindReg("ebp")	
	print (eaxVal)
	setReg(eaxVal, False, "eax")
	setReg(ebxVal, False, "ebx")
	print ("ok")
	setReg(ecxVal, False, "ecx")
	setReg(edxVal, False, "edx")
	setReg(esiVal, False, "esi")
	setReg(ediVal, False, "edi")
	setReg(ebpVal, False, "ebp")
	setReg(espVal, False, "esp")



setReg(strHex, True, "eax")

setReg(strHex, False, "eax")

# test="0xaa"
# test2="0x2"
# print (hxRStr(test2))

print ("\nresults:")
for r1,r2,r3,r4,s in realEAX:
	print (hxRStr(str(hex(r2))))

print ("\nHexresults:")
for r1,r2,r3,r4,s in realEAX:
	res= hxR(r1)+hxR(r2)+hxR(r3)+hxR(r4)
	print( res+"\n")


print ("print ret432 eax:")
print( retR32("eax", "x")+"\n")

print (realEAX)

r1, r2, r3, r4,s= realEAX[len(realEAX)-1]
print( r1,r2,r3,r4)

print ("ebx")
print (realEBX)
print (realEBX2)

print ("eCx")
print (realECX)
print (realECX2)
print (hex(retR32Int("ebx")))

print( "before ebp")
print (hex(retR32Int("ebp")))
print ("\n***")
addReg16b("0x0044", False, "ebp","16b")

print ("\nafter1 ebp")
print (hex(retR32Int("ebp")))

print ("\nadd")

print ("\nafter2")
print (hex(retR32Int("ebp")))
print (realESI2)



print (realEAX)
addReg16b("0x0099", True, "eax","16b")
print (realEAX)

print ("***")

addReg16b("0x0099", True, "eSP","16b")
print (realESP)


print ("set reg***")
setReg16("0x0022", False, "ebx")
print (realEBX2)


print ("\nnew testing")
setReg("0x0040aabb", False, "ecx")
print (hex(retR32Int("ecx")))
addReg16b("0xdd000000", False,"ecx", "32")
print (hex(retR32Int("ecx")))

readRegs()

setAll()
# print ("show")
showAllRegs()
