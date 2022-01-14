
import re
import itertools
from math import factorial
import timeit
import numpy as np
import multiprocessing 
import time
import math
import dispy
import traceback
import lists
# from capstone import *
# from selfModify import findAllPebSequences_decode	

pebPoints = 3

def get_PEB_walk_start_decodeDistr(mode, NumOpsDis ,bytesToMatch, secNum, data2): 
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
			# print("hit a found")
			# input("enter..")
			ans = disHerePEB_decodeDistr(mode, t, numOps, secNum, data2)
			if mode=="decrypt" and ans is not None:
				# print ("got disherepeb", ans)
				return ans

			

		t=t+1

def disHerePEB_decodeDistr(mode, address, NumOpsDis, secNum, data): ############ AUSTIN ##############
	import capstone
	# print ("disHerePEB", mode)
	global o
	global pebPoints
	w=0

	start = timeit.default_timer()
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
	# print(binaryToStrDistr(CODED3))
	cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
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



		loadLDR = re.match("^((mov)|(add)|(xor)|(or)|(adc)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?(0xc)\])", val, re.IGNORECASE)

		# if(movLoadLDR or addLoadLDR or adcLoadLDR or xorLoadLDR or orLoadLDR or xchgLoadLDR):
		if(loadLDR):
			loadLDR_offset = addb
			points += 1



		loadInMemOrder = re.match("^((mov)|(add)|(adc)|(xor)|(or)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x14))\])", val, re.IGNORECASE)

		# if(movLoadInMemOrder or addLoadInMemOrder or adcLoadInMemOrder or xorLoadInMemOrder or orLoadInMemOrder or xchgLoadInMemOrder):
		if(loadInMemOrder):
			loadModList_offset = addb
			points += 1




		loadInInitOrder = re.match("^((mov)|(add)|(adc)|(xor)|(or)|(xchg)) (e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))), ?(d?word ptr ?(ds:)?\[(e?((ax)|(bx)|(cx)|(dx)|(di)|(si)|(bp))|((a|b|c|d)(h|l))) ?\+ ?((0x1c))\])", val, re.IGNORECASE)

		if(loadInInitOrder):
		# if(movLoadInInitOrder or addLoadInInitOrder or adcLoadInInitOrder or xorLoadInInitOrder or orLoadInInitOrder or xchgLoadInInitOrder):
			loadModList_offset = addb
			points += 1




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
			points += 1

		val5.append(val)
		# print (val)
	#return val5
	# stop = timeit.default_timer()
	# total2 += (stop - start)
	# print("Time 2 PEB: " + str(stop - start))


	
	disString = val5
	# print("dishere disString: ", disString)

	stop = timeit.default_timer()
	# print("Time PEB: " + str(stop - start))

	if(points >= pebPoints):

		modSecName = "shellcode"


		if mode=="decrypt":
			# print ("decrypt returning")
			# print (address, NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, loadModList_offset, advanceDLL_Offset)
			return address , NumOpsDis, modSecName, secNum, points, loadTIB_offset, loadLDR_offset, loadModList_offset, advanceDLL_Offset



def findAllPebSequences_decodeDistr(mode, inputBytes): ################## AUSTIN ######################

	# global rawHex
	# print ("findAllPebSequences", mode, binaryToStrDistr(rawData2),)
	mode = "decrypt"
	for match in lists.PEB_WALK.values(): #iterate through all opcodes representing combinations of registers
		ans=get_PEB_walk_start_decodeDistr(mode, 19, match, "noSec", inputBytes) #19 hardcoded for now, seems like good value for peb walking sequence
		# print ("ans", ans)
		if mode=="decrypt" and ans is not None:
			# print ("good, get pet walk")
			# print (ans)
			return (ans)



def p2EncodeDistr(low, high, encodeBytes4, sample, rank, queue, version, endFlag, findAll = False, successPoints = 3):
	global pebPoints
	pebPoints = successPoints

	outs = []
	# if(version == 3):
	for i in range(low,high):
		if(endFlag.value >= 1):
			# print("ending early, someone found a match")
			queue.put(outs)
			return

		elif(version == 1):
			output = doStuffP21Distr(encodeBytes4[i], sample, rank)
		elif(version == 2):
			output = doStuffP22Distr(encodeBytes4[i], sample, rank)
		elif(version == 3):
			output = doStuffP2Distr(encodeBytes4[i], sample, rank)
		elif(version == 4):
			output = doStuffP24Distr(encodeBytes4[i], sample, rank)
		elif(version == 5):
			output = doStuffP25Distr(encodeBytes4[i], sample, rank)
		# if(findAll):
		# 	outs.append(output)

		# print("checking bytes, endFlag = ", endFlag.value, "rank = ", rank, " findall = ", findAll)
		# print("P2OUTPUTVAR = ", output)
		ans = findAllPebSequences_decodeDistr("decrypt", output[0])
		# print("checking bytes, endFlag = ", endFlag.value, "rank = ", rank, " findall = ", findAll, " ans = ", ans)

		if ans is not None:
			if(not findAll):
				endFlag.value = 1
			outs.append(output)
			# print("FOUND IN P2ENCODEDISTR BY RANK = ", rank, "FINDALL = ", str(findAll))
			#print(output)
	# elif(version == 4):
	# 	for i in range(low,high):
	# 		outs.append(doStuffP24Distr(encodeBytes4[i], sample, rank))
	# elif(version == 5):
	# 	for i in range(low,high):
	# 		outs.append(doStuffP25Distr(encodeBytes4[i], sample, rank))

	queue.put(outs)



def doStuffP21Distr(inputs, sample, rank):
	newString = ""
	a=inputs[0]
	each=inputs[1]
	# print("PROCESS " + str(rank) + " REPORTING")
	# print("len sample:" )
	# print(len(sample))
	# print("index:")
	# print((len(sample)//2))
	# print("type each")
	# print(type(each))
	# print(each)
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
					# encode="encodeBytes.append(new)"
	# print (newString, "\n", "a",a, "")
	bytesStr = bytes(encodeBytes)
	out = newString + "\n" + "a" + str(a)
	# print ("\nencoder5 new", binaryToStrDistr(bytesStr),"\n\n\n")
	return (bytesStr, out, list((a,)), each)
	# return out
	# return "ok"


def doStuffP22Distr(inputs, sample, rank):
	newString = ""
	a=inputs[0]
	b=inputs[1]
	each=inputs[2]
	# print("PROCESS " + str(rank) + " REPORTING")
	# print("len sample:" )
	# print(len(sample))
	# print("index:")
	# print((len(sample)//2))
	# print("type each")
	# print(type(each))
	# print(each)
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
					# encode="encodeBytes.append(new)"
	# print (newString, "\n", "a",a, "b",b, "")
	bytesStr = bytes(encodeBytes)
	out = newString + "\n" + "a" + str(a) + "b" + str(b)
	# print ("\nencoder5 new", binaryToStrDistr(bytesStr),"\n\n\n")
	return (bytesStr, out, list((a,b)), each)
	# return out
	# return "ok"



def doStuffP2Distr(inputs, sample, rank):
	newString = ""
	# print("IN dostuffp2")
	a=inputs[0]
	b=inputs[1]
	c=inputs[2]
	each=inputs[3]
	# print("PROCESS " + str(rank) + " REPORTING")
	# print("len sample:" )
	# print(len(sample))
	# print("index:")
	# print((len(sample)//2))
	# print("type each")
	# print(type(each))
	# print(each)
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
		
					# encode="encodeBytes.append(new)"
	# print (newString, "\n", "a",a, "b",b, "c",c ,"")
	bytesStr = bytes(encodeBytes)
	out = newString + "\n" + "a" + str(a) + "b" + str(b) + "c" + str(c)
	# print ("\nencoder5 new", binaryToStrDistr(bytesStr),"\n\n\n")
	# return out
	return (bytesStr, out, list((a,b,c)), each)
	# return "ok"

def doStuffP24Distr(inputs, sample, rank):
	newString = ""
	a=inputs[0]
	b=inputs[1]
	c=inputs[2]
	d=inputs[3]
	each=inputs[4]
	# print("PROCESS " + str(rank) + " REPORTING")
	# print("len sample:" )
	# print(len(sample))
	# print("index:")
	# print((len(sample)//2))
	# print("type each")
	# print(type(each))
	# print(each)
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
					# encode="encodeBytes.append(new)"
	# print (newString, "\n", "a",a, "b",b, "c",c ,"d",d, "")
	bytesStr = bytes(encodeBytes)
	out = newString + "\n" + "a" + str(a) + "b" + str(b) + "c" + str(c) + "d" + str(d)
	# print ("\nencoder5 new", binaryToStrDistr(bytesStr),"\n\n\n")
	return (bytesStr, out, list((a,b,c,d)), each)
	# return out
	# return "ok"

def doStuffP25Distr(inputs, sample, rank):
	newString = ""
	a=inputs[0]
	b=inputs[1]
	c=inputs[2]
	d=inputs[3]
	e=inputs[4]
	each=inputs[5]
	# print("PROCESS " + str(rank) + " REPORTING")
	# print("len sample:" )
	# print(len(sample))
	# print("index:")
	# print((len(sample)//2))
	# print("type each")
	# print(type(each))
	# print(each)
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
		
					# encode="encodeBytes.append(new)"
	# print (newString, "\n", "a",a, "b",b, "c",c ,"d",d, "e",e, "")
	bytesStr = bytes(encodeBytes)
	out = newString + "\n" + "a" + str(a) + "b" + str(b) + "c" + str(c) + "d" + str(d) + "e" + str(e)
	# print ("\nencoder5 new", binaryToStrDistr(bytesStr),"\n\n\n")
	return (bytesStr, out, list((a,b,c,d,e)), each)
	# return out
	# return "ok"

def binaryToStrDistr(binary):
	newop=""
	try:
		for v in binary:
			# i = ord2(v) 
			i = v
			# newop += "\\x"+show1(i)
			newop += "\\x" + "{0:02x}".format(i)
			# newAscii += "\\x"+chr(i)
		# print newop
		# print newAscii
		return newop
	except Exception as e:
		print ("*Not valid format")
		print(e)

# def ord2(x):
# 	return x

# def show1(int):
# 	show = "{0:02x}".format(int) #
# 	return show
