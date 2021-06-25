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
import distrFunc

def show1(int):
		show = "{0:02x}".format(int) #
		return show

def binaryToStr(binary):
	# OP_SPECIAL = b"\x8d\x4c\xff\xe2\x01\xd8\x81\xc6\x34\x12\x00\x00"
	newop=""
	# newAscii=""
	try:
		for v in binary:
			i = (v) 
			newop += "\\x"+show1(i)
			# newAscii += "\\x"+chr(i)
		# print newop
		# print newAscii
		return newop
	except Exception as e:
		print ("*Not valid format")
		print(e)



def nPr(n, r):
    from math import factorial
    return int(factorial(n)/factorial(n-r))


def XOR(val):
	print("t:  I am xor", val)
def ADD(val):
	print("u:  I am add",val)
def SUB(val):
	print("w:  I am sub",val)
def ROT(val):
	print("r:  I am ROT",val)
def LSH(val):
	print("v:  I am LSH",val)


code="XOR(9)\nADD(7)\nSUB(7)"




def foo(): 
	print("original foo")

if __name__ == '__main__':
	foo()


	rewrite_txt="def foo(): print('I am new foo')"
	newcode=compile(rewrite_txt,"",'exec')
	eval(newcode)
	foo()

	t=99
	newcode=compile(code,"",'exec')
	eval(newcode)


	XORstr="XOR(t)\n"
	ADDstr="ADD(u)\n"
	SUBstr="SUB(w)\n"
	ROTstr="ROT(rr)\n"
	LSHstr="LSH(v)\n"

	mylist=[]
	mylist.append(XORstr)
	mylist.append(ADDstr)
	mylist.append(SUBstr)
	# mylist.append(ADDstr)
	# mylist.append(SUBstr)
	me="Hi"
	code2=("print(me)\n")
	newcode=compile(code2,"",'exec')
	eval(newcode)

	t=0
	u=0
	w=0 
	rr=0
	v=0
	# for x in range (24):
	# 	for each in (list(itertools.permutations(mylist))):
	# 		# print ("first", each)
	# 		temp=""
	# 		# for e in each:
	# 		# 	temp+=e
	# 		# 	print ("\t",temp)
	# 		newString="".join(each)
	# 		print (newString, "\n\n\n")
	# 		newcode=compile(newString,"",'exec')
	# 		eval(newcode)
	# 	t+=1



	strSub="new=tohex((new -(x)),8)" 
	strAdd="new=tohex((new +(w)),8)" 
	strXor="new=tohex((new ^ (z)),8)"



def specialEncoder(*args):   #args = variable # of inputs
	print("specialEncoder")
	u=0
	t=0

	Max=20
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4

	mylist2=[]
	for x in args:
		mylist2.append(x)   # puts all args into a list
	z=0

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=maxValuT*maxValuW*maxValuU * (nPr(numItems,numItems-1))
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	for x in range (maxValuT):
	# while t <maxValuT:
		for each in (list(itertools.permutations(mylist2))):
			# print ("first", each)
			temp=""
			# for e in each:
			# 	temp+=e
			# 	print ("\t",temp)
			w=0
			while w < maxValuW:
				u=0
				while (u < maxValuU):
					newString="".join(each)
					print (newString, "\n\n\n")
					newcode=compile(newString,"",'exec')
					eval(newcode) 
					z+=1 #total counter
					if z == permPercent:
						print (str(int(100*permPercent/totalPerm))+"% completed")
						permPercent+=0.1*totalPerm
					u+=1
				w+=1

		t+=1
	stop = timeit.default_timer()
	print("Total time: " + str(stop - start))

	cores=240
	print (z, "total")
	print (totalPerm, "Perm")
	numSeconds=0.00001
	print (totalPerm*numSeconds, "seconds")
	print ((totalPerm*numSeconds)/60, "minutes")
	print (((totalPerm*numSeconds)/60)/60, "hours")
	print ((((totalPerm*numSeconds)/60)/60)/24, "days")
	print ("spread across " + str(cores) + " cores: ", ((((totalPerm*numSeconds)/60)/60)/24)/cores, "days")


def specialEncoder3(*args):
	print("specialEncoder3")
	u=0
	t=0

	maxTrue=5
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4

	mylist2=[]
	for x in args:
		mylist2.append(x)
	z=0

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=maxValuT*maxValuW*maxValuU * (nPr(numItems,numItems-1))
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	encodeBytes=bytearray()
	
	for x in range (maxTrue):
	# while t <maxValuT:
		for each in (list(itertools.permutations(mylist2))):
			temp=""
			w=0
			while w < maxValuW:
				u=0
				while (u < maxValuU):
					for each2 in sample:
						new=each2
						newString="".join(each)
						newString+="encodeBytes.append(new)"
						newcode=compile(newString,"",'exec')
						eval(newcode) 
						
						# encode="encodeBytes.append(new)"
					print (newString, "\n", "u",u, "w",w, "x",x ,"")
					bytesStr = bytes(encodeBytes)
					print ("\nencoder3 new", binaryToStr(bytesStr),"\n\n\n")
					encodeBytes.clear()
					z+=1 #total counter
					if z == permPercent:
						print (str(int(100*permPercent/totalPerm))+"% completed")
						permPercent+=0.1*totalPerm
					u+=1
				w+=1

		# t+=1
		

	stop = timeit.default_timer()
	print("Total time: " + str(stop - start))

	finTime=stop-start
	cores=240
	print (z, "total")
	print (totalPerm, "Perm")
	numSeconds=0.00001
	print (totalPerm*numSeconds, "seconds")
	print ((totalPerm*numSeconds)/60, "minutes")
	print (((totalPerm*numSeconds)/60)/60, "hours")
	print ((((totalPerm*numSeconds)/60)/60)/24, "days")
	print ("spread across " + str(cores) + " cores: ", ((((totalPerm*numSeconds)/60)/60)/24)/cores, "days")


	print ("end time: ", z/finTime )
	print ("finTime", finTime)



def specialEncoder4(*args):
	print("specialEncoder4")
	u=0
	t=0

	maxTrue=5
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4

	mylist2=[]
	for x in args:
		mylist2.append(x)
	z=0

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=maxValuT*maxValuW*maxValuU * (nPr(numItems,numItems-1))
	permPercent=0.1*totalPerm
	start = timeit.default_timer()

	encodeBytes=bytearray()
	zz=0
	for x in range (maxTrue):
	# while t <maxValuT:
		for each in (list(itertools.permutations(mylist2))):
			temp=""
			w=0
			while w < maxValuW:
				u=0
				while (u < maxValuU):
					t=0
					newString="\nnew=sample[t]\nt+=1\n"
					# newString="\nnew=5\n"
					newString+="".join(each)
					# newString+="encodeBytes.append(new)"

					increment=("\nencodeBytes.append(new)\nz+=1\n")
					newString+=increment
					n2=newString*len(sample)
					newcode=compile(n2,"",'exec')
					# print (n2)
					eval(newcode) 
					# print (newcode)
						
						# encode="encodeBytes.append(new)"
					# print (newString, "\n\n\n", u, w, x ,"\n")
					bytesStr = bytes(encodeBytes)
					print ("\nencoder4 new", binaryToStr(bytesStr))
					encodeBytes.clear()
					zz+=1 #total counter
					if z == permPercent:
						print (str(int(100*permPercent/totalPerm))+"% completed")
						permPercent+=0.1*totalPerm
					u+=1
				w+=1

		# t+=1
		

	stop = timeit.default_timer()
	print("4 Total time: " + str(stop - start))

	finTime=stop-start
	cores=240
	print (zz, "total")
	print (totalPerm, "Perm")
	numSeconds=0.00001
	print (totalPerm*numSeconds, "seconds")
	print ((totalPerm*numSeconds)/60, "minutes")
	print (((totalPerm*numSeconds)/60)/60, "hours")
	print ((((totalPerm*numSeconds)/60)/60)/24, "days")
	print ("spread across " + str(cores) + " cores: ", ((((totalPerm*numSeconds)/60)/60)/24)/cores, "days")


	print ("end time: ", z/finTime )
	print ("finTime", finTime)



def specialEncoder44(*args):
	print("specialEncoder44")
	u=0
	t=0

	Max=5
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4

	mylist2=[]
	for x in args:
		mylist2.append(x)
	z=0

	

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=maxValuT*maxValuW*maxValuU * (nPr(numItems,numItems-1))
	permPercent=0.1*totalPerm
	start = timeit.default_timer()

	encodeBytes=bytearray()
	zz=0
	entryRange=range(0,5)
	for x in entryRange:
	# while t <maxValuT:
		for each in (list(itertools.permutations(mylist2))):
			temp=""
			w=0
			while w < maxValuW:
				u=0
				while (u < maxValuU):
					t=0
					newString="\nnew=sample[t]\nt+=1\n"
					newString+="".join(each)
					increment=("\nencodeBytes.append(new)\nz+=1\n")
					newString+=increment
					n2=newString*len(sample)
					newcode=compile(n2,"",'exec')
					# print (n2)
					eval(newcode) 
					# print (newcode)
					# eval(exec"print (1);"*9)
						# encode="encodeBytes.append(new)"
					# print (newString, "\n\n\n", u, w, x ,"\n")
					bytesStr = bytes(encodeBytes)
					print ("\nencoder44 new", binaryToStr(bytesStr))
					encodeBytes.clear()
					zz+=1 #total counter
					if z == permPercent:
						print (str(int(100*permPercent/totalPerm))+"% completed")
						permPercent+=0.1*totalPerm
					u+=1
				w+=1

		# t+=1
		

	stop = timeit.default_timer()
	print("Total time: " + str(stop - start))

	finTime=stop-start
	cores=240
	print (zz, "total")
	print (totalPerm, "Perm")
	numSeconds=0.00001
	print (totalPerm*numSeconds, "seconds")
	print ((totalPerm*numSeconds)/60, "minutes")
	print (((totalPerm*numSeconds)/60)/60, "hours")
	print ((((totalPerm*numSeconds)/60)/60)/24, "days")
	print ("spread across " + str(cores) + " cores: ", ((((totalPerm*numSeconds)/60)/60)/24)/cores, "days")


	print ("end time: ", z/finTime )
	print ("finTime", finTime)

if __name__ == '__main__':
	encodeBytes2=bytearray()
	
def sayHi(item, each, x, w,u):
	# newcode=compile(item,"",'exec')
	# 				# print (n2)
	# eval(newcode) 
	global encodeBytes2

	new=item
	newString="".join(each)
	newString+="encodeBytes2.append(new)"
	newcode=compile(newString,"",'exec')
	eval(newcode) 
	return 
def specialEncoder4ListComprehension(*args):
	print("specialEncoder4ListComprehension")
	u=0
	t=0
	global encodeBytes2
	Max=5
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4
	mylist2=[]
	for x in args:
		mylist2.append(x)
	z=0

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=maxValuT*maxValuW*maxValuU * (nPr(numItems,numItems-1))
	permPercent=0.1*totalPerm
	start = timeit.default_timer()

	encodeBytes=bytearray()
	zz=0
	entryRange=range(0,3)
	for x in entryRange:
	# while t <maxValuT:
		for each in (list(itertools.permutations(mylist2))):
			temp=""
			w=0
			while w < maxValuW:
				u=0
				while (u < maxValuU):
					newString="\nnew=sample[t]\nt+=1\n"
					# newString="\nnew=5\n"
					newString+="".join(each)
					results = [sayHi(item, each, x, w, u) for item in sample]
				
					bytesStr = bytes(encodeBytes2)          ####  USE this global to get results from function
					print ("\nencoder44LC", binaryToStr(bytesStr))
					encodeBytes2.clear()
					zz+=1 #total counter
					if z == permPercent:
						print (str(int(100*permPercent/totalPerm))+"% completed")
						permPercent+=0.1*totalPerm
					u+=1
				w+=1

		# t+=1
		

	stop = timeit.default_timer()
	print("Total time: " + str(stop - start))

	finTime=stop-start
	cores=240
	print (zz, "total")
	print (totalPerm, "Perm")
	numSeconds=0.00001
	print (totalPerm*numSeconds, "seconds")
	print ((totalPerm*numSeconds)/60, "minutes")
	print (((totalPerm*numSeconds)/60)/60, "hours")
	print ((((totalPerm*numSeconds)/60)/60)/24, "days")
	print ("spread across " + str(cores) + " cores: ", ((((totalPerm*numSeconds)/60)/60)/24)/cores, "days")


	print ("end time: ", z/finTime )
	print ("finTime", finTime)

def specialEncoderExperimental(*args):
	print("specialEncoderExperimental")
	u=0
	t=0

	Max=5
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4

	mylist2=[]
	for x in args:
		mylist2.append(x)
	z=0

	sample=b"\x31\xc9\x64"#\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=maxValuT*maxValuW*maxValuU * (nPr(numItems,numItems-1))
	permPercent=0.1*totalPerm
	start = timeit.default_timer()

	encodeBytes=bytearray()
	zz=0
	for x in range (1):
		for each in (list(itertools.permutations(mylist2))):
			temp=""
			w=0
			while w < maxValuW:
				u=0
				while (u < maxValuU):
					# print ("hello")
					strInner="t=0\nnew=sample[t]\n"
					# print (strInner)
					strInner+="newString="
					strInner+="\"new=sample[t]\\n\"\n"
					strInner+="print (\"hello55\", sample[t])\n"
					strInner+="t+=1\n"
					strInner+="newString+=\"\'\'.join(each)\\n\"\n"
					# print (strInner)
					strInner+="print (\"hello\", \'\'.join(each))\n"

					strInner+="print (\"hello6\", strInner)\n"
					strInner2="newString+=\"encodeBytes.append("
					strInner3="new)\\n\"\n"
					strInner+=strInner2
					strInner+=strInner3
					strInner+="print (\"hello4\", len(encodeBytes))\n"
			


					strInner+="newString=\"z+=1\\n\"\n"
					# strInner+="newString+=increment\n"
					strInner+="newString=bytesStr = bytes(encodeBytes)\n"
					strInner+="newString=print (\"\\nencoder4 new\", len(encodeBytes), binaryToStr(bytesStr))\n"
					print (strInner)
					strInner+="n2=newString*len(sample)\n"
					strInner+="newcode=compile(n2,\"\",'exec')\n"
					
	
					# strInner+="encodeBytes.clear()\n"
					strInner+="zz+=1\n"#total counter
					strInner+="eval(newcode)\n"

					# strInner="print(\"Gotcha\")"
					# print (strInner)
					print ("trying compile")
					newcode=compile(strInner,"",'exec')
					eval(newcode)
				
					u+=1
				w+=1

		# t+=1
		

	stop = timeit.default_timer()
	print("Total time: " + str(stop - start))

	finTime=stop-start
	cores=240
	print (zz, "total")
	print (totalPerm, "Perm")
	numSeconds=0.00001
	print (totalPerm*numSeconds, "seconds")
	print ((totalPerm*numSeconds)/60, "minutes")
	print (((totalPerm*numSeconds)/60)/60, "hours")
	print ((((totalPerm*numSeconds)/60)/60)/24, "days")
	print ("spread across " + str(cores) + " cores: ", ((((totalPerm*numSeconds)/60)/60)/24)/cores, "days")


	print ("end time: ", z/finTime )
	print ("finTime", finTime)


def tohex(num, bits):
	v= hex((num + (1 << bits)) % (1 << bits))
	return int(v,16)

ROTATE_BITMASK = {
    8  : 0xff,
    16 : 0xffff,
    32 : 0xffffffff,
    64 : 0xffffffffffffffff,
}



def ror(inVal, numShifts, dataSize=32):
    '''rotate right instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
        raise ValueError('Bad dataSize')
    bitMask = ROTATE_BITMASK[dataSize]
    return bitMask & ((inVal >> numShifts) | (inVal << (dataSize-numShifts)))


def rol(inVal, numShifts, dataSize=32):
    '''rotate left instruction emulation'''
    if numShifts == 0:
        return inVal
    if (numShifts < 0) or (numShifts > dataSize):
        raise ValueError('Bad numShifts')
    if (dataSize != 8) and (dataSize != 16) and (dataSize != 32) and (dataSize != 64):
        raise ValueError('Bad dataSize')
    bitMask = ROTATE_BITMASK[dataSize]
    currVal = inVal
    return bitMask & ((inVal << numShifts) | (inVal >> (dataSize-numShifts)))





def specialEncoder2(Max, *args):
	print("specialEncoder")
	u=0
	t=0
	z=0

	mylist2=[]
	for x in args:
		mylist2.append(x)
	
	maxValuU=Max
	maxValuW=Max
	maxValuT=Max
	maxValuR=Max
	maxValuV=Max
	rangeStart=0

	if len(mylist2)<4:
		maxValuR=1

	if len(mylist2)<5:
		maxValuV=1

	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=maxValuT*maxValuW*maxValuU *maxValuR * maxValuV * (nPr(numItems,numItems-1))
	totalPerm2=maxValuT*maxValuW*maxValuU *maxValuR * maxValuV *  len(list(itertools.permutations(mylist2)))

	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	# while t <maxValuT:
	for x in range (maxValuT):
	# for x in range (0):
		for each in (list(itertools.permutations(mylist2))):
			# print ("first", each)
			temp=""
			# for e in each:
			# 	temp+=e
			# 	print ("\t",temp)
			rr=rangeStart
			while rr < maxValuR:
				w=rangeStart
				while w < maxValuW:
					u=rangeStart
					while (u < maxValuU):# and (u >= rangeStart):
						newString="".join(each)
						print (newString, "\n\n\n")
						newcode=compile(newString,"",'exec')
						eval(newcode) 
						z+=1 #total counter
						# if z == permPercent:
						# 	print (str(int(100*permPercent/totalPerm))+"% completed")
						# 	permPercent+=0.1*totalPerm
						u+=1
					w+=1
				rr+=1

		t+=1

	stop = timeit.default_timer()

	total1 = (stop - start)
	print("Total time: " + str(stop - start))
	cores=1000
	print (z, "total")
	print (totalPerm, "Perm")
	print (totalPerm2, "Perm2")

	numSeconds=0.001
	print (totalPerm*numSeconds, "seconds")
	print ((totalPerm*numSeconds)/60, "minutes")
	print (((totalPerm*numSeconds)/60)/60, "hours")
	print ((((totalPerm*numSeconds)/60)/60)/24, "days")
	print ("spread across " + str(cores) + " cores: ", ((((totalPerm*numSeconds)/60)/60)/24)/cores, "days")


def doStuff(each, a, b, c, sample ):
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
	out = newString + str(a) + str(b) + str(c) + binaryToStr(bytesStr)
	# print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
	return out
	# return "ok"


def doStuffParallel(each, a, b, c, sample ):
	# print("len sample:" )
	# print(len(sample))
	# print("index:")
	# print((len(sample)//2))
	# print("testType each")
	# print(type(each))
	# print(each)
	each = each[0]
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
		
					# encode="encodeBytes.append(new)"
	# print (newString, "\n", "a",a, "b",b, "c",c ,"")
	# bytesStr = bytes(encodeBytes)
	# print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
	return (newString, encodeBytes, a, b, c)
	# return "ok"


def doStuff_testP(each, a, b, c, sample ):
	# print("len sample:" )
	# print(len(sample))
	# print("index:")
	# print((len(sample)//2))
	# print("testType each")
	# print(type(each))
	# print(each)
	each = each[0]
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
		
					# encode="encodeBytes.append(new)"
	# print (newString, "\n", "a",a, "b",b, "c",c ,"")
	# bytesStr = bytes(encodeBytes)
	# print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
	return (newString, encodeBytes, a, b, c)
	# return "ok"

def doStuff_test(each, a, b, c, sample ):

	index = len(sample)//2

	if __name__ == "__main__":
		processList = []
		manager = multiprocessing.Manager()
		return_dict = manager.dict()
		procnum = 1
		processList.append(multiprocessing.Process(target=doStuff_threads, args = (procnum, return_dict, each,a,b,c,sample[0:index])))
		procnum = 2
		processList.append(multiprocessing.Process(target=doStuff_threads, args = (procnum, return_dict, each,a,b,c,sample[index:])))

		for proc in processList:
			proc.start()

		for proc in processList:
			proc.join()

		print("THREADS DONE HERE")
		print(return_dict.values())

def doStuff_testQ(each, a, b, c, sample ):


	if __name__ == "__main__":
		numThreads = 8
		r = len(sample) % numThreads
		startChunk = 0
		rSize = math.ceil(len(sample)/numThreads)
		p_rSize = len(sample)//numThreads
		processList = []
		rets = []
		queue = multiprocessing.Queue()

		for procnum in range(r):
			processList.append(multiprocessing.Process(target=doStuff_threadsQ, args = (procnum, queue, each,a,b,c,sample[startChunk:startChunk + rSize])))
			startChunk += rSize
		for procnum in range(numThreads - r):
			processList.append(multiprocessing.Process(target=doStuff_threadsQ, args = (procnum, queue, each,a,b,c,sample[startChunk:startChunk + p_rSize])))
			startChunk += p_rSize

		for proc in processList:
			proc.start()

		for proc in processList:
			ret = queue.get()
			rets.append(ret)

		for proc in processList:
			proc.join()

		for proc in processList:
			proc.terminate()

		#print("THREADS DONE HERE")
		#print(rets)

		ordered = []
		for i in range(len(processList)):
			for item in rets:
				if(item[0] == i):
					ordered.append(item)

		bytesStr = ordered[0][5]
		for i in range(1,len(ordered)):
			bytesStr += ordered[i][5]

		newString = ordered[0][1]
		print (newString, "\n", "a",a, "b",b, "c",c ,"")
		bytesStr = bytes(bytesStr)
		print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")

		#input()

	#encodeBytes=bytearray()
	#result = [pool.apply(doStuff_threads, args=(each,a,b,c,sample,each2)) for each2 in sample]
		
		
					# encode="encodeBytes.append(new)"
	#print (newString, "\n", "a",a, "b",b, "c",c ,"")
	#bytesStr = bytes(encodeBytes)
	#print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
	# return "ok"

def doStuff4_testQ(each, a, b, c,d, sample ):
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
		
					# encode="encodeBytes.append(new)"
	print (newString, "\n", "a",a, "b",b, "c",c ,"","d", d)
	bytesStr = bytes(encodeBytes)
	print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")

def doStuff_pool(procnum, return_dict, each, a, b, c, sample, each2):
	new=each2
	newString="".join(each)
	newString+="encodeBytes.append(new)"
	newcode=compile(newString,"",'exec')
	eval(newcode) 
	return(newString, a,b,c)


def doStuff_threads(procnum, return_dict, each, a, b, c, sample):
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 

	bytesStr = bytes(encodeBytes)
	return_dict[procnum] = (newString, a,b,c, bytesStr)

def doStuff_threadsQ(procnum, queue, each, a, b, c, sample):
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 

	bytesStr = bytes(encodeBytes)
	ret = (procnum, newString, a,b,c, bytesStr)
	queue.put(ret)

def doStuffTup(myTup):
	each, a, b, c, sample
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
		
					# encode="encodeBytes.append(new)"
	print (newString, "\n", "a",a, "b",b, "c",c ,"")
	bytesStr = bytes(encodeBytes)
	print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
	# return "ok"

def doStuff4(each, a, b, c,d, sample ):
	encodeBytes=bytearray()
	for each2 in sample:
		new=each2
		newString="".join(each)
		newString+="encodeBytes.append(new)"
		newcode=compile(newString,"",'exec')
		eval(newcode) 
		
					# encode="encodeBytes.append(new)"
	print (newString, "\n", "a",a, "b",b, "c",c ,"","d", d)
	bytesStr = bytes(encodeBytes)
	out = newString + str(a) + str(b) + str(c) + str(d) + str(bytesStr)
	print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
	return out
		# return newString

limitXOR_8=256
limitADD_8=256
limitSUB_8=256
limitNOT_8=1
limitROR_8=8
limitROL_8=8
limit_LSHIFT_8=3

aLimit=0
bLimit=0
cLimit=0
dLimit=0
eLimit=0
fLimit=0
gLimit=0
hLimit=0
iLimit=0

aValue="NULL"
bValue="NULL"
cValue="NULL"
dValue="NULL"
eValue="NULL"
fValue="NULL"
gValue="NULL"
hValue="NULL"
iValue="NULL"


def findObfusMethod(val):
	XORtest = re.search( r'\^', val, re.M|re.I)
	ADDtest = re.search( r'\+', val, re.M|re.I)
	SUBtest = re.search( r'-', val, re.M|re.I)
	NOTtest = re.search( r'~', val, re.M|re.I)
	RORtest = re.search( r'ror', val, re.M|re.I)
	ROLtest = re.search( r'rol', val, re.M|re.I)
	LSHtest = re.search( r'>>', val, re.M|re.I)
	if XORtest:
		return 256, "XOR"
	if ADDtest:
		return 256, "ADD"
	if SUBtest:
		return 256, "SUB"
	if NOTtest:
		return 1, "NOT"
	if RORtest:
		return 8, "ROR"
	if ROLtest:
		return 8, "ROL"
	if LSHtest:
		return 2, "LEFT SHIFT"


def tempMax(newMaxA, newMaxB, newMaxC, newMax):
	global aLimit
	global bLimit
	global cLimit
	global dLimit
	global eLimit
	global fLimit
	global gLimit
	global hLimit
	global iLimit

	aLimit = newMaxA
	bLimit = newMaxB
	cLimit = newMaxC
	dLimit = newMax
	eLimit = newMax
	fLimit = newMax
	gLimit = newMax
	hLimit = newMax
	iLimit = newMax

def specialEncoder5(*args):
	global aLimit
	global bLimit
	global cLimit
	global dLimit
	global eLimit
	global fLimit
	global gLimit
	global hLimit
	global iLimit
	global aValue
	global bValue
	global cValue
	global dValue
	global eValue
	global fValue
	global gValue
	global hValue
	global iValue

	print("specialEncoder5")
	u=0
	t=0

	alphaList=[]
	alpha = 'a'
	for i in range(0, 26): 
		alphaList.append(alpha) 
		alpha = chr(ord(alpha) + 1)  

	for val in args:
		lim, res=findObfusMethod(val)
		if t==0:
			aLimit, aValue=lim, res
		elif t==1:
			bLimit, bValue=lim, res
		elif t==2:
			cLimit, cValue=lim, res
		elif t==3:
			dLimit, dValue=lim, res
		elif t==4:
			eLimit, eValue=lim, res
		elif t==5:
			fLimit, fValue=lim, res
		elif t==6:
			gLimit, gValue=lim, res
		elif t==7:
			hLimit, hValue=lim, res
		elif t==8:
			iLimit, iValue=lim, res
		t+=1

	tempMax(10, 10,7, 10)

	print ("aLimit", aLimit, aValue)
	print ("bLimit", bLimit, bValue)
	print ("cLimit", cLimit, cValue)
	maxTrue=3
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4


	mylist2=[]
	# for x in args:
	# 	mylist2.append(x)
	z=0

	#### TODO --build it out so it only populates with natural max--
	###populate the maxes for the range func as well with regular expressions. :-)
	t=0
	for each in args:
		x = each.replace("VALUE", alphaList[t] )
		mylist2.append(x)
		t+=1
		print (x)


		

		

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	# sample=b"\x31\xc9"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
	if len(mylist2)==4:
		totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))

	print ("total permutations: ", totalPerm)
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	encodeBytes=bytearray()
	
	# encodeBytes4=bytearray()

	# print("mylist2")
	# print(mylist2)
	# print("sample")
	# print(sample)
	# input("break")
	if len(mylist2)==3:

		# 1-6, 0-3, 0-3, 0-3
		# permutations = list(itertools.permutations(mylist2))
		
		# doStuff(permutations[1] ,22, 35, 1)

		# for each in (list(itertools.permutations(mylist2))):
		encodeBytes4 = [doStuff(each, a, b, c, sample)
						for a in range (aLimit)
						for each in (list(itertools.permutations(mylist2)))
						for b in range (bLimit)
						for c in range (cLimit)
						]
		
	elif len(mylist2)==4:
		encodeBytes4 = [doStuff4(each, a, b, c, d, sample)
						for a in range (aLimit)
						for each in (list(itertools.permutations(mylist2)))
						for b in range (bLimit)
						for c in range (cLimit)
						for d in range (dLimit)
						]
	sortOut = sorted(encodeBytes4)
		# print(sortOut)
	print("LEN SORT SEQ", str(len(sortOut)))
	#print("Encodebytes here")
	#print(encodeBytes4)
	stop = timeit.default_timer()
	print("Total time SEQ: " + str(stop - start))


	# print ("Total number of iterations:", len(encodeBytes4))
	# for xx in encodeBytes4:
		
	# 	print (xx)
	# 	print ("\n\n")
	


	finTime=stop-start
	cores=240
	print (totalPerm, "Perm")
	numSeconds=0.00001

	print ("end time: ", z/finTime )
	print ("finTime", finTime)
	return sortOut


def block_low(id, p, n):
	return (id*n)//(p)

def block_high(id, p, n):
	return int(block_low(id+1, p, n))

def block_size(id, p, n):
	return int(block_high(id, p, n) - block_low(id, p, n) + 1)



def austinDecode(decodeOps, sample, mode = "default", starts = [], order = []):
# def austinDecode(*args):
	global aLimit
	global bLimit
	global cLimit
	global dLimit
	global eLimit
	global fLimit
	global gLimit
	global hLimit
	global iLimit
	global aValue
	global bValue
	global cValue
	global dValue
	global eValue
	global fValue
	global gValue
	global hValue
	global iValue


	print("austinDecode")
	u=0
	t=0

	# starts = []
	single = False
	# args = list(args)
	# sample = args.pop()
	
	# if(mode == "continue"):
		# starts = args.pop()
		# sample = args.pop()
	if(mode == "single"):
		# order = args.pop()
		# starts = args.pop()
		# sample = args.pop()
		single = True
	# starts = args.pop()

	# else:
	# 	for val in args:
	# 		starts.append(0)
	alphaList=[]
	alpha = 'a'
	for i in range(0, 26): 
		alphaList.append(alpha) 
		alpha = chr(ord(alpha) + 1)  

	args = list(decodeOps)
	for val in args:
		lim, res=findObfusMethod(val)
		if t==0:
			aLimit, aValue=lim, res
		elif t==1:
			bLimit, bValue=lim, res
		elif t==2:
			cLimit, cValue=lim, res
		elif t==3:
			dLimit, dValue=lim, res
		elif t==4:
			eLimit, eValue=lim, res
		elif t==5:
			fLimit, fValue=lim, res
		elif t==6:
			gLimit, gValue=lim, res
		elif t==7:
			hLimit, hValue=lim, res
		elif t==8:
			iLimit, iValue=lim, res
		t+=1

	tempMax(10, 10,10, 3)

	print ("aLimit", aLimit, aValue)
	print ("bLimit", bLimit, bValue)
	print ("cLimit", cLimit, cValue)
	maxTrue=3
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4


	mylist2=[]
	# for x in args:
	# 	mylist2.append(x)
	z=0

	#### TODO --build it out so it only populates with natural max--
	###populate the maxes for the range func as well with regular expressions. :-)
	t=0

	for each in args:
		x = each.replace("VALUE", alphaList[t] )
		mylist2.append(x)
		t+=1
		# print (x)


		

		

	sample2=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"

	# sample=b"\x31\xc9"
	numItems=len(mylist2)
	totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
	if len(mylist2)==4:
		totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))
	if len(mylist2)==5:
		totalPerm=aLimit*bLimit*cLimit * dLimit * eLimit*(nPr(numItems,numItems-1))

	print ("total permutations: ", totalPerm)
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	encodeBytes=bytearray()
	
	# encodeBytes4=bytearray()

	# print("mylist2")
	# print(mylist2)
	# print("sample")
	# print(sample)
	# input("break")

	# 1-6, 0-3, 0-3, 0-3
	permutations = list(itertools.permutations(mylist2))
	# print("PERMS")
	# print(len(permutations))
	# doStuff(permutations[1] ,22, 35, 1)

	# for each in (list(itertools.permutations(mylist2))):


	tupleStart = timeit.default_timer()
	### LIST COMPREHENSION ###
	# 6000 perm time = 0.0019388999999999934
	# encodeBytes4 = [ (a,b,c,each)
	# 				for a in range (aLimit)
	# 				for b in range (bLimit)
	# 				for c in range (cLimit)
	# 				for each in (list(itertools.permutations(mylist2)))
	# 				]
	### WHILE LOOPS ###
	# 6000 perm time = 0.001719499999999985
	encodeBytes4 = []
	eachLen = len(permutations)

	# print("STARTS HERE")
	# print(starts)
	a=0
	b=0
	c=0
	d=0
	e=0
	if(len(starts) >= 3):
			a = starts[0]
			b = starts[1]
			c = starts[2]
	if(len(starts) >= 4):
		d = starts[3]
	if(len(starts) >= 5):
		e = starts[4]
	eachInd = 0

	curPerm = 0
	listLimit = 1000000
	totalRuns = 0
	# print("CPU COUNT")
	# print(multiprocessing.cpu_count())
	numThreads = multiprocessing.cpu_count()
	out = []
	startVals = []
	early = False

	if(single):
		version = len(mylist2)
		if(version == 3):
			encodeBytes4.append((a,b,c,order))
		elif(version == 4):
			encodeBytes4.append((a,b,c,d,order))
		elif(version == 5):
			encodeBytes4.append((a,b,c,d,e,order))
		out = runProcs(encodeBytes4, sample, numThreads,version)
		return out,early,startVals
	
	if(len(mylist2) == 3):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(eachInd < eachLen):
						encodeBytes4.append((a,b,c,permutations[eachInd]))
						eachInd += 1
						curPerm += 1
						if(curPerm > listLimit):
							early = True
							print("RUNNING PROCS")
							out = out + runProcs(encodeBytes4, sample, numThreads)
							totalRuns += numThreads
							curPerm = 0
							encodeBytes4 = []
							hitLimit = True
							startVals.append(a)
							startVals.append(b)
							startVals.append(c)
							return out,early,startVals
					c += 1
					eachInd = 0
				b += 1
				c = 0
			a += 1
			b = 0

		if(totalRuns != totalPerm):
			out = out + runProcs(encodeBytes4, sample, numThreads)
	
	elif(len(mylist2) == 4):
		print("in loop a=", a, "b=", b, "c=", c, "d=", d, "eachInd=", eachInd, "eachLen=", eachLen)
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(d < dLimit):
						while(eachInd < eachLen):
							encodeBytes4.append((a,b,c,d,permutations[eachInd]))
							eachInd += 1
							curPerm += 1
							if(curPerm > listLimit):
								print("RUNNING PROCS")
								out = out + runProcs(encodeBytes4, sample, numThreads, 4)
								totalRuns += numThreads
								curPerm = 0
								encodeBytes4 = []
								hitLimit = True
								startVals.append(a)
								startVals.append(b)
								startVals.append(c)
								startVals.append(d)
								return out,early,startVals
						d += 1
						eachInd = 0
					c += 1
					d = 0
				b += 1
				c = 0
			a += 1
			b = 0
		if(totalRuns != totalPerm):
			out = out + runProcs(encodeBytes4, sample, numThreads, 4)

	elif(len(mylist2) == 5):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(d < dLimit):
						while(e < eLimit):
							while(eachInd < eachLen):
								encodeBytes4.append((a,b,c,d,e,permutations[eachInd]))
								eachInd += 1
								curPerm += 1
								if(curPerm > listLimit):
									print("RUNNING PROCS")
									out = out + runProcs(encodeBytes4, sample, numThreads, 5)
									totalRuns += numThreads
									curPerm = 0
									encodeBytes4 = []
									hitLimit = True
									startVals.append(a)
									startVals.append(b)
									startVals.append(c)
									startVals.append(d)
									startVals.append(e)
									return out,early,startVals
							e += 1
							eachInd = 0
						d += 1
						e = 0
					c += 1
					d = 0
				b += 1
				c = 0
			a += 1
			b = 0
		if(totalRuns != totalPerm):
			out = out + runProcs(encodeBytes4, sample, numThreads, 5)

	tupleStop = timeit.default_timer()
	print("Tuple time: " + str(tupleStop - tupleStart))

	print("LISTDONE")
	# print(encodeBytes4)
	print(len(encodeBytes4))
	sortOut = sorted(out)
	print("LEN SORT PAR", str(len(sortOut)))

	
	stop = timeit.default_timer()
	print("Total time PAR: " + str(stop - start))


	# print ("Total number of iterations:", len(encodeBytes4))
	# for xx in encodeBytes4:
		
	# 	print (xx)
	# 	print ("\n\n")
	


	finTime=stop-start
	cores=240
	print (totalPerm, "Perm")
	numSeconds=0.00001

	print ("end time: ", z/finTime )
	print ("finTime", finTime)
	return out, early, startVals


def doDistr(decodeOps, sample, nodes, mode = "default", starts = [], order = []):
    final = []
    finalOutput = []
    print("in distr")
    cluster = dispy.JobCluster(austinDecodeDistributed_new, nodes = ['172.25.14.87', '172.25.14.208'], depends = [nPr, findObfusMethod,tempMax,runProcsDistr,block_low,block_high,distrFunc], loglevel = dispy.logger.DEBUG)
    jobs = []
    for i in range(2):
        print('starting jobs')
        # schedule execution of 'compute' on a node (running 'dispynode')
        # with a parameter (random number in this case)
        job = cluster.submit(decodeOps, sample, nodes, i, mode, starts, order)
        jobs.append(job)
    # cluster.wait() # wait for all scheduled jobs to finish
    for job in jobs:
        print("waiting for jobs")
        outputs = job() # waits for job to finish and returns results
        print("outputs here")
        # print(outputs)
        final.append(outputs)
        finalOutput.append(outputs[0])
        print('(%s) executed job %s at %s' % (job.ip_addr, job.id,
                                                         job.start_time))
        # other fields of 'job' that may be useful:
        # print(job.stdout, job.stderr, job.exception, job.ip_addr, job.start_time, job.end_time)
    cluster.print_status()

    for item in finalOutput:
    	print("FINAL RETURNED2")
    	for x in item:
    		try:
	    		for y in x:
	    			print( y)
    		except:
	    		print(x)
    		print("\n\n")


    	print("\n\n")


#operations, sample, numNodes, <startValues, "continue"> OR <startValues, order, "single"> 


def austinDecodeDistributed_old(*args):
	global aLimit
	global bLimit
	global cLimit
	global dLimit
	global eLimit
	global fLimit
	global gLimit
	global hLimit
	global iLimit
	global aValue
	global bValue
	global cValue
	global dValue
	global eValue
	global fValue
	global gValue
	global hValue
	global iValue


	print("austinDecode")
	u=0
	t=0

	starts = []
	single = False
	args = list(args)
	nodes = args.pop()
	sample = args.pop()
	
	if(sample == "continue"):
		starts = args.pop()
		nodes = args.pop()
		sample = args.pop()
	elif(sample == "single"):
		order = args.pop()
		starts = args.pop()
		nodes = args.pop()
		sample = args.pop()
		single = True
	# starts = args.pop()

	else:
		for val in args:
			starts.append(0)
	alphaList=[]
	alpha = 'a'

	
	for i in range(0, 26): 
		alphaList.append(alpha) 
		alpha = chr(ord(alpha) + 1)  
	
	for val in args:
		lim, res=findObfusMethod(val)
		if t==0:
			aLimit, aValue=lim, res
		elif t==1:
			bLimit, bValue=lim, res
		elif t==2:
			cLimit, cValue=lim, res
		elif t==3:
			dLimit, dValue=lim, res
		elif t==4:
			eLimit, eValue=lim, res
		elif t==5:
			fLimit, fValue=lim, res
		elif t==6:
			gLimit, gValue=lim, res
		elif t==7:
			hLimit, hValue=lim, res
		elif t==8:
			iLimit, iValue=lim, res
		t+=1

	tempMax(3, 3,3, 3)

	print ("aLimit", aLimit, aValue)
	print ("bLimit", bLimit, bValue)
	print ("cLimit", cLimit, cValue)
	maxTrue=3
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4


	mylist2=[]
	# for x in args:
	# 	mylist2.append(x)
	z=0

	#### TODO --build it out so it only populates with natural max--
	###populate the maxes for the range func as well with regular expressions. :-)
	t=0

	for each in args:
		x = each.replace("VALUE", alphaList[t] )
		mylist2.append(x)
		t+=1
		# print (x)

		

		

	sample2=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"

	# sample=b"\x31\xc9"
	numItems=len(mylist2)
	totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
	if len(mylist2)==4:
		totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))
	if len(mylist2)==5:
		totalPerm=aLimit*bLimit*cLimit * dLimit * eLimit*(nPr(numItems,numItems-1))

	print ("total permutations: ", totalPerm)
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	encodeBytes=bytearray()
	
	# encodeBytes4=bytearray()

	# print("mylist2")
	# print(mylist2)
	# print("sample")
	# print(sample)
	# input("break")

	# 1-6, 0-3, 0-3, 0-3
	permutations = list(itertools.permutations(mylist2))
	# print("PERMS")
	# print(len(permutations))
	# doStuff(permutations[1] ,22, 35, 1)

	# for each in (list(itertools.permutations(mylist2))):


	tupleStart = timeit.default_timer()
	### LIST COMPREHENSION ###
	# 6000 perm time = 0.0019388999999999934
	# encodeBytes4 = [ (a,b,c,each)
	# 				for a in range (aLimit)
	# 				for b in range (bLimit)
	# 				for c in range (cLimit)
	# 				for each in (list(itertools.permutations(mylist2)))
	# 				]
	### WHILE LOOPS ###
	# 6000 perm time = 0.001719499999999985
	encodeBytes4 = []
	eachLen = len(permutations)

	# print("STARTS HERE")
	# print(starts)
	a = starts[0]
	b = starts[1]
	c = starts[2]
	if(len(starts) >= 4):
		d = starts[3]
	if(len(starts) >= 5):
		e = starts[4]
	eachInd = 0

	curPerm = 0
	listLimit = 1000000
	totalRuns = 0
	# print("CPU COUNT")
	# print(multiprocessing.cpu_count())
	numThreads = multiprocessing.cpu_count()
	out = []
	startVals = []
	early = False	
	if(single):
		version = len(mylist2)
		if(version == 3):
			encodeBytes4.append((a,b,c,order))
		elif(version == 4):
			encodeBytes4.append((a,b,c,d,order))
		elif(version == 5):
			encodeBytes4.append((a,b,c,d,e,order))
		out = runProcs(encodeBytes4, sample, numThreads,version)
		return (out,early,startVals)
	# return("got here")
	
	if(len(mylist2) == 3):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(eachInd < eachLen):
						encodeBytes4.append((a,b,c,permutations[eachInd]))
						eachInd += 1
						curPerm += 1
						if(curPerm > listLimit):
							early = True
							print("RUNNING PROCS")
							out = out + runProcs(encodeBytes4, sample, numThreads)
							totalRuns += numThreads
							curPerm = 0
							encodeBytes4 = []
							hitLimit = True
							startVals.append(a)
							startVals.append(b)
							startVals.append(c)
							return (out,early,startVals)
					c += 1
					eachInd = 0
				b += 1
				c = 0
			a += 1
			b = 0

		if(totalRuns != totalPerm):
			for nodeID in range(nodes):
								print("BOTTOM RUNNING PROCS")
								print("BOTTOM ENCODEBYTES LEN = " + str(len(encodeBytes4)))
								print("BOTTOM NODE ID = " + str(nodeID))
								print("BOTTOM BLOCK LOW = " + str(block_low(nodeID, nodes, len(encodeBytes4))))
								print("BOTTOM BLOCK HIGH = " + str(block_high(nodeID, nodes, len(encodeBytes4))))
								out = out + runProcs(encodeBytes4[block_low(nodeID, nodes, len(encodeBytes4)): block_high(nodeID, nodes, len(encodeBytes4))], sample, numThreads)
			# out = out + runProcs(encodeBytes4, sample, numThreads)
	
	elif(len(mylist2) == 4):
		print("in loop a=", a, "b=", b, "c=", c, "d=", d, "eachInd=", eachInd, "eachLen=", eachLen)
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(d < dLimit):
						while(eachInd < eachLen):
							encodeBytes4.append((a,b,c,d,permutations[eachInd]))
							eachInd += 1
							curPerm += 1
							if(curPerm > listLimit):
								print("RUNNING PROCS")
								out = out + runProcs(encodeBytes4, sample, numThreads, 4)
								totalRuns += numThreads
								curPerm = 0
								encodeBytes4 = []
								hitLimit = True
								startVals.append(a)
								startVals.append(b)
								startVals.append(c)
								startVals.append(d)
								return (out,early,startVals)
						d += 1
						eachInd = 0
					c += 1
					d = 0
				b += 1
				c = 0
			a += 1
			b = 0
		if(totalRuns != totalPerm):
			for nodeID in range(nodes):
								print("BOTTOM RUNNING PROCS")
								print("BOTTOM ENCODEBYTES LEN = " + str(len(encodeBytes4)))
								print("BOTTOM NODE ID = " + str(nodeID))
								print("BOTTOM BLOCK LOW = " + str(block_low(nodeID, nodes, len(encodeBytes4))))
								print("BOTTOM BLOCK HIGH = " + str(block_high(nodeID, nodes, len(encodeBytes4))))
								out = out + runProcs(encodeBytes4[block_low(nodeID, nodes, len(encodeBytes4)): block_high(nodeID, nodes, len(encodeBytes4))], sample, numThreads, 4)
			# out = out + runProcs(encodeBytes4, sample, numThreads, 4)

	elif(len(mylist2) == 5):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(d < dLimit):
						while(e < eLimit):
							while(eachInd < eachLen):
								encodeBytes4.append((a,b,c,d,e,permutations[eachInd]))
								eachInd += 1
								curPerm += 1
								if(curPerm > listLimit):
									print("RUNNING PROCS")
									out = out + runProcs(encodeBytes4, sample, numThreads, 5)
									totalRuns += numThreads
									curPerm = 0
									encodeBytes4 = []
									hitLimit = True
									startVals.append(a)
									startVals.append(b)
									startVals.append(c)
									startVals.append(d)
									startVals.append(e)
									return (out,early,startVals)
							e += 1
							eachInd = 0
						d += 1
						e = 0
					c += 1
					d = 0
				b += 1
				c = 0
			a += 1
			b = 0
		if(totalRuns != totalPerm):
			for nodeID in range(nodes):
								print("BOTTOM RUNNING PROCS")
								print("BOTTOM ENCODEBYTES LEN = " + str(len(encodeBytes4)))
								print("BOTTOM NODE ID = " + str(nodeID))
								print("BOTTOM BLOCK LOW = " + str(block_low(nodeID, nodes, len(encodeBytes4))))
								print("BOTTOM BLOCK HIGH = " + str(block_high(nodeID, nodes, len(encodeBytes4))))
								out = out + runProcs(encodeBytes4[block_low(nodeID, nodes, len(encodeBytes4)): block_high(nodeID, nodes, len(encodeBytes4))], sample, numThreads, 5)
			# out = out + runProcs(encodeBytes4, sample, numThreads, 5)

	tupleStop = timeit.default_timer()
	print("Tuple time: " + str(tupleStop - tupleStart))

	print("LISTDONE")
	# print(encodeBytes4)
	print(len(encodeBytes4))
	sortOut = sorted(out)
	print("LEN SORT PAR", str(len(sortOut)))

	
	stop = timeit.default_timer()
	print("Total time PAR: " + str(stop - start))


	# print ("Total number of iterations:", len(encodeBytes4))
	# for xx in encodeBytes4:
		
	# 	print (xx)
	# 	print ("\n\n")
	


	finTime=stop-start
	cores=240
	print (totalPerm, "Perm")
	numSeconds=0.00001

	print ("end time: ", z/finTime )
	print ("finTime", finTime)
	return (out, early, startVals)


#def austinDecodeDistributed_new(list operations, 
def austinDecodeDistributed_new(decodeOps, sample, nodes, nodeID, mode = "default", starts = [], order = []):
	try:
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

			global aLimit
			global bLimit
			global cLimit
			global dLimit
			global eLimit
			global fLimit
			global gLimit
			global hLimit
			global iLimit
			global aValue
			global bValue
			global cValue
			global dValue
			global eValue
			global fValue
			global gValue
			global hValue
			global iValue

			# aLimit = 0
			# bLimit = 0
			# cLimit = 0
			# dLimit = 0
			# eLimit = 0
			# fLimit = 0
			# gLimit = 0
			# hLimit = 0
			# iLimit = 0
			# aValue = 0
			# bValue = 0
			# cValue = 0
			# dValue = 0
			# eValue = 0
			# fValue = 0
			# gValue = 0
			# hValue = 0
			# iValue = 0



			# return("limits done")
			# import re
			# import itertools
			# from math import factorial
			# import timeit
			# import numpy as np
			# import multiprocessing 
			# import time
			# import math
			# import dispy

			# return("entered")
			print("austinDecode")
			u=0
			t=0

			# starts = []
			single = False
			# args = list(args)
			# sample = args.pop()
			
			# if(mode == "continue"):
				# starts = args.pop()
				# sample = args.pop()
			if(mode == "single"):
				# order = args.pop()
				# starts = args.pop()
				# sample = args.pop()
				single = True
			# starts = args.pop()

			# else:
			# 	for val in args:
			# 		starts.append(0)
			alphaList=[]
			alpha = 'a'
			for i in range(0, 26): 
				alphaList.append(alpha) 
				alpha = chr(ord(alpha) + 1)  

			args = list(decodeOps)

			for val in args:
				lim, res=findObfusMethod(val)
				if t==0:
					aLimit, aValue=lim, res
				elif t==1:
					bLimit, bValue=lim, res
				elif t==2:
					cLimit, cValue=lim, res
				elif t==3:
					dLimit, dValue=lim, res
				elif t==4:
					eLimit, eValue=lim, res
				elif t==5:
					fLimit, fValue=lim, res
				elif t==6:
					gLimit, gValue=lim, res
				elif t==7:
					hLimit, hValue=lim, res
				elif t==8:
					iLimit, iValue=lim, res
				t+=1

			tempMax(3, 3,3, 3)

			print ("aLimit", aLimit, aValue)
			print ("bLimit", bLimit, bValue)
			print ("cLimit", cLimit, cValue)
			maxTrue=3
			Max=maxTrue
			maxValuU=Max#20
			maxValuW=Max#4
			maxValuT=Max#2
			maxValuR=Max#4


			mylist2=[]
			# for x in args:
			# 	mylist2.append(x)
			z=0

			#### TODO --build it out so it only populates with natural max--
			###populate the maxes for the range func as well with regular expressions. :-)
			t=0

			for each in args:
				x = each.replace("VALUE", alphaList[t] )
				mylist2.append(x)
				t+=1
				# print (x)


				

				

			sample2=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"

			# sample=b"\x31\xc9"	


			numItems=len(mylist2)

			totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
			if len(mylist2)==4:
				totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))
			if len(mylist2)==5:
				totalPerm=aLimit*bLimit*cLimit * dLimit * eLimit*(nPr(numItems,numItems-1))

			# return("got here")

			print ("total permutations: ", totalPerm)
			permPercent=0.1*totalPerm
			start = timeit.default_timer()
			encodeBytes=bytearray()
			
			# encodeBytes4=bytearray()

			# print("mylist2")
			# print(mylist2)
			# print("sample")
			# print(sample)
			# input("break")

			# 1-6, 0-3, 0-3, 0-3
			permutations = list(itertools.permutations(mylist2))
			# print("PERMS")
			# print(len(permutations))
			# doStuff(permutations[1] ,22, 35, 1)

			# for each in (list(itertools.permutations(mylist2))):


			tupleStart = timeit.default_timer()
			### LIST COMPREHENSION ###
			# 6000 perm time = 0.0019388999999999934
			# encodeBytes4 = [ (a,b,c,each)
			# 				for a in range (aLimit)
			# 				for b in range (bLimit)
			# 				for c in range (cLimit)
			# 				for each in (list(itertools.permutations(mylist2)))
			# 				]
			### WHILE LOOPS ###
			# 6000 perm time = 0.001719499999999985
			encodeBytes4 = []
			eachLen = len(permutations)

			# print("STARTS HERE")
			# print(starts)
			a=0
			b=0
			c=0
			d=0
			e=0
			if(len(starts) >= 3):
				a = starts[0]
				b = starts[1]
				c = starts[2]
			if(len(starts) >= 4):
				d = starts[3]
			if(len(starts) >= 5):
				e = starts[4]
			eachInd = 0

			curPerm = 0
			listLimit = 1000000
			totalRuns = 0
			# print("CPU COUNT")
			# print(multiprocessing.cpu_count())
			numThreads = multiprocessing.cpu_count()
			out = []
			startVals = []
			early = False

			
			if(single):
				version = len(mylist2)
				if(version == 3):
					encodeBytes4.append((a,b,c,order))
				elif(version == 4):
					encodeBytes4.append((a,b,c,d,order))
				elif(version == 5):
					encodeBytes4.append((a,b,c,d,e,order))
				out = runProcsDistr(encodeBytes4, sample, numThreads,version)
				return (out,early,startVals)
			
			if(len(mylist2) == 3):
				while(a < aLimit):
					while(b < bLimit):
						while(c < cLimit):
							while(eachInd < eachLen):
								encodeBytes4.append((a,b,c,permutations[eachInd]))
								eachInd += 1
								curPerm += 1
								if(curPerm > listLimit):
									early = True
									print("RUNNING PROCS")
									out = out + runProcsDistr(encodeBytes4, sample, numThreads)
									totalRuns += numThreads
									curPerm = 0
									encodeBytes4 = []
									hitLimit = True
									startVals.append(a)
									startVals.append(b)
									startVals.append(c)
									return (out,early,startVals)
							c += 1
							eachInd = 0
						b += 1
						c = 0
					a += 1
					b = 0

				if(totalRuns != totalPerm):
					for nodeID in range(nodes):
										print("BOTTOM RUNNING PROCS")
										print("BOTTOM ENCODEBYTES LEN = " + str(len(encodeBytes4)))
										print("BOTTOM NODE ID = " + str(nodeID))
										print("BOTTOM BLOCK LOW = " + str(block_low(nodeID, nodes, len(encodeBytes4))))
										print("BOTTOM BLOCK HIGH = " + str(block_high(nodeID, nodes, len(encodeBytes4))))
										out = out + runProcsDistr(encodeBytes4[block_low(nodeID, nodes, len(encodeBytes4)): block_high(nodeID, nodes, len(encodeBytes4))], sample, numThreads)
					# out = out + runProcs(encodeBytes4, sample, numThreads)
			
			elif(len(mylist2) == 4):
				print("in loop a=", a, "b=", b, "c=", c, "d=", d, "eachInd=", eachInd, "eachLen=", eachLen)
				while(a < aLimit):
					while(b < bLimit):
						while(c < cLimit):
							while(d < dLimit):
								while(eachInd < eachLen):
									encodeBytes4.append((a,b,c,d,permutations[eachInd]))
									eachInd += 1
									curPerm += 1
									if(curPerm > listLimit):
										print("RUNNING PROCS")
										out = out + runProcsDistr(encodeBytes4, sample, numThreads, 4)
										totalRuns += numThreads
										curPerm = 0
										encodeBytes4 = []
										hitLimit = True
										startVals.append(a)
										startVals.append(b)
										startVals.append(c)
										startVals.append(d)
										return (out,early,startVals)
								d += 1
								eachInd = 0
							c += 1
							d = 0
						b += 1
						c = 0
					a += 1
					b = 0
				if(totalRuns != totalPerm):
					for nodeID in range(nodes):
										print("BOTTOM RUNNING PROCS")
										print("BOTTOM ENCODEBYTES LEN = " + str(len(encodeBytes4)))
										print("BOTTOM NODE ID = " + str(nodeID))
										print("BOTTOM BLOCK LOW = " + str(block_low(nodeID, nodes, len(encodeBytes4))))
										print("BOTTOM BLOCK HIGH = " + str(block_high(nodeID, nodes, len(encodeBytes4))))
										out = out + runProcsDistr(encodeBytes4[block_low(nodeID, nodes, len(encodeBytes4)): block_high(nodeID, nodes, len(encodeBytes4))], sample, numThreads, 4)
					# out = out + runProcs(encodeBytes4, sample, numThreads, 4)

			elif(len(mylist2) == 5):
				while(a < aLimit):
					while(b < bLimit):
						while(c < cLimit):
							while(d < dLimit):
								while(e < eLimit):
									while(eachInd < eachLen):
										encodeBytes4.append((a,b,c,d,e,permutations[eachInd]))
										eachInd += 1
										curPerm += 1
										if(curPerm > listLimit):
											print("RUNNING PROCS")
											out = out + runProcsDistr(encodeBytes4, sample, numThreads, 5)
											totalRuns += numThreads
											curPerm = 0
											encodeBytes4 = []
											hitLimit = True
											startVals.append(a)
											startVals.append(b)
											startVals.append(c)
											startVals.append(d)
											startVals.append(e)
											return (out,early,startVals)
									e += 1
									eachInd = 0
								d += 1
								e = 0
							c += 1
							d = 0
						b += 1
						c = 0
					a += 1
					b = 0
				if(totalRuns != totalPerm):
					for nodeID in range(nodes):
										print("BOTTOM RUNNING PROCS")
										print("BOTTOM ENCODEBYTES LEN = " + str(len(encodeBytes4)))
										print("BOTTOM NODE ID = " + str(nodeID))
										print("BOTTOM BLOCK LOW = " + str(block_low(nodeID, nodes, len(encodeBytes4))))
										print("BOTTOM BLOCK HIGH = " + str(block_high(nodeID, nodes, len(encodeBytes4))))
										out = out + runProcsDistr(encodeBytes4[block_low(nodeID, nodes, len(encodeBytes4)): block_high(nodeID, nodes, len(encodeBytes4))], sample, numThreads, 5)
					# out = out + runProcs(encodeBytes4, sample, numThreads, 5)

			tupleStop = timeit.default_timer()
			print("Tuple time: " + str(tupleStop - tupleStart))

			print("LISTDONE")
			# print(encodeBytes4)
			print(len(encodeBytes4))
			sortOut = sorted(out)
			print("LEN SORT PAR", str(len(sortOut)))

			
			stop = timeit.default_timer()
			print("Total time PAR: " + str(stop - start))


			# print ("Total number of iterations:", len(encodeBytes4))
			# for xx in encodeBytes4:
				
			# 	print (xx)
			# 	print ("\n\n")
			


			finTime=stop-start
			cores=240
			print (totalPerm, "Perm")
			numSeconds=0.00001

			print ("end time: ", z/finTime )
			print ("finTime", finTime)
			return (out, early, startVals)
	except Exception as e:
		return(traceback.format_exc())
		# return(e)

def austinDecodeDistributed(*args):
	global aLimit
	global bLimit
	global cLimit
	global dLimit
	global eLimit
	global fLimit
	global gLimit
	global hLimit
	global iLimit
	global aValue
	global bValue
	global cValue
	global dValue
	global eValue
	global fValue
	global gValue
	global hValue
	global iValue

	print("austinDecode")
	u=0
	t=0

	args = list(args)
	nodes = args[-1]
	args = args [:-1]
	sample = args.pop()

	alphaList=[]
	alpha = 'a'
	for i in range(0, 26): 
		alphaList.append(alpha) 
		alpha = chr(ord(alpha) + 1)  

	for val in args:
		lim, res=findObfusMethod(val)
		if t==0:
			aLimit, aValue=lim, res
		elif t==1:
			bLimit, bValue=lim, res
		elif t==2:
			cLimit, cValue=lim, res
		elif t==3:
			dLimit, dValue=lim, res
		elif t==4:
			eLimit, eValue=lim, res
		elif t==5:
			fLimit, fValue=lim, res
		elif t==6:
			gLimit, gValue=lim, res
		elif t==7:
			hLimit, hValue=lim, res
		elif t==8:
			iLimit, iValue=lim, res
		t+=1

	tempMax(10, 10,10, 3)

	print ("aLimit", aLimit, aValue)
	print ("bLimit", bLimit, bValue)
	print ("cLimit", cLimit, cValue)
	maxTrue=3
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4


	mylist2=[]
	# for x in args:
	# 	mylist2.append(x)
	z=0

	#### TODO --build it out so it only populates with natural max--
	###populate the maxes for the range func as well with regular expressions. :-)
	t=0

	for each in args:
		x = each.replace("VALUE", alphaList[t] )
		mylist2.append(x)
		t+=1
		print (x)


		

		

	sample2=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"

	# sample=b"\x31\xc9"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
	if len(mylist2)==4:
		totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))
	if len(mylist2)==5:
		totalPerm=aLimit*bLimit*cLimit * dLimit * eLimit*(nPr(numItems,numItems-1))

	print ("total permutations: ", totalPerm)
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	encodeBytes=bytearray()
	
	# encodeBytes4=bytearray()

	# print("mylist2")
	# print(mylist2)
	# print("sample")
	# print(sample)
	# input("break")

	# 1-6, 0-3, 0-3, 0-3
	permutations = list(itertools.permutations(mylist2))
	print("PERMS")
	print(len(permutations))
	# doStuff(permutations[1] ,22, 35, 1)

	# for each in (list(itertools.permutations(mylist2))):


	tupleStart = timeit.default_timer()
	### LIST COMPREHENSION ###
	# 6000 perm time = 0.0019388999999999934
	# encodeBytes4 = [ (a,b,c,each)
	# 				for a in range (aLimit)
	# 				for b in range (bLimit)
	# 				for c in range (cLimit)
	# 				for each in (list(itertools.permutations(mylist2)))
	# 				]
	### WHILE LOOPS ###
	# 6000 perm time = 0.001719499999999985
	encodeBytes4 = []
	eachLen = len(permutations)
	a = 0
	b = 0
	c = 0
	d = 0
	e = 0
	eachInd = 0

	curPerm = 0
	listLimit = 1000000
	totalRuns = 0
	numThreads = 4
	out = []
	if(len(mylist2) == 3):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(eachInd < eachLen):
						encodeBytes4.append((a,b,c,permutations[eachInd]))
						eachInd += 1
						curPerm += 1
						if(curPerm > (listLimit // nodes)):
							for nodeID in range(nodes):
								print("RUNNING PROCS")
								print("ENCODEBYTES LEN = " + str(len(encodeBytes4)))
								print("NODE ID = " + str(nodeID))
								print("BLOCK LOW = " + str(block_low(nodeID, nodes, len(encodeBytes4))))
								print("BLOCK HIGH = " + str(block_high(nodeID, nodes, len(encodeBytes4))))
								out = out + runProcs(encodeBytes4[block_low(nodeID, nodes, len(encodeBytes4)): block_high(nodeID, nodes, len(encodeBytes4))], sample, numThreads)
							totalRuns += numThreads
							curPerm = 0
							encodeBytes4 = []
							hitLimit = True
					c += 1
					eachInd = 0
				b += 1
				c = 0
			a += 1
			b = 0

		if(totalRuns != totalPerm):
			for nodeID in range(nodes):
								print("BOTTOM RUNNING PROCS")
								print("BOTTOM ENCODEBYTES LEN = " + str(len(encodeBytes4)))
								print("BOTTOM NODE ID = " + str(nodeID))
								print("BOTTOM BLOCK LOW = " + str(block_low(nodeID, nodes, len(encodeBytes4))))
								print("BOTTOM BLOCK HIGH = " + str(block_high(nodeID, nodes, len(encodeBytes4))))
								out = out + runProcs(encodeBytes4[block_low(nodeID, nodes, len(encodeBytes4)): block_high(nodeID, nodes, len(encodeBytes4))], sample, numThreads)
			out = out + runProcs(encodeBytes4, sample, numThreads)
	
	elif(len(mylist2) == 4):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(d < dLimit):
						while(eachInd < eachLen):
							encodeBytes4.append((a,b,c,d,permutations[eachInd]))
							eachInd += 1
							curPerm += 1
							if(curPerm > listLimit):
								print("RUNNING PROCS")
								out = out + runProcs(encodeBytes4, sample, numThreads, 4)
								totalRuns += numThreads
								curPerm = 0
								encodeBytes4 = []
								hitLimit = True
						d += 1
						eachInd = 0
					c += 1
					d = 0
				b += 1
				c = 0
			a += 1
			b = 0
		if(totalRuns != totalPerm):
			out = out + runProcs(encodeBytes4, sample, numThreads, 4)

	elif(len(mylist2) == 5):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(d < dLimit):
						while(e < eLimit):
							while(eachInd < eachLen):
								encodeBytes4.append((a,b,c,d,e,permutations[eachInd]))
								eachInd += 1
								curPerm += 1
								if(curPerm > listLimit):
									print("RUNNING PROCS")
									out = out + runProcs(encodeBytes4, sample, numThreads, 5)
									totalRuns += numThreads
									curPerm = 0
									encodeBytes4 = []
									hitLimit = True
							e += 1
							eachInd = 0
						d += 1
						e = 0
					c += 1
					d = 0
				b += 1
				c = 0
			a += 1
			b = 0
		if(totalRuns != totalPerm):
			out = out + runProcs(encodeBytes4, sample, numThreads, 5)

	tupleStop = timeit.default_timer()
	print("Tuple time: " + str(tupleStop - tupleStart))

	print("LISTDONE")
	# print(encodeBytes4)
	print(len(encodeBytes4))
	sortOut = sorted(out)
	print("LEN SORT PAR", str(len(sortOut)))

	
	stop = timeit.default_timer()
	print("Total time PAR: " + str(stop - start))


	# print ("Total number of iterations:", len(encodeBytes4))
	# for xx in encodeBytes4:
		
	# 	print (xx)
	# 	print ("\n\n")
	


	finTime=stop-start
	cores=240
	print (totalPerm, "Perm")
	numSeconds=0.00001

	print ("end time: ", z/finTime )
	print ("finTime", finTime)
	return out


def specialEncoderP2(*args):
	global aLimit
	global bLimit
	global cLimit
	global dLimit
	global eLimit
	global fLimit
	global gLimit
	global hLimit
	global iLimit
	global aValue
	global bValue
	global cValue
	global dValue
	global eValue
	global fValue
	global gValue
	global hValue
	global iValue

	print("specialEncoderP2")
	u=0
	t=0

	alphaList=[]
	alpha = 'a'
	for i in range(0, 26): 
		alphaList.append(alpha) 
		alpha = chr(ord(alpha) + 1)  

	for val in args:
		lim, res=findObfusMethod(val)
		if t==0:
			aLimit, aValue=lim, res
		elif t==1:
			bLimit, bValue=lim, res
		elif t==2:
			cLimit, cValue=lim, res
		elif t==3:
			dLimit, dValue=lim, res
		elif t==4:
			eLimit, eValue=lim, res
		elif t==5:
			fLimit, fValue=lim, res
		elif t==6:
			gLimit, gValue=lim, res
		elif t==7:
			hLimit, hValue=lim, res
		elif t==8:
			iLimit, iValue=lim, res
		t+=1

	tempMax(10, 10,7, 10)

	print ("aLimit", aLimit, aValue)
	print ("bLimit", bLimit, bValue)
	print ("cLimit", cLimit, cValue)
	maxTrue=3
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4


	mylist2=[]
	# for x in args:
	# 	mylist2.append(x)
	z=0

	#### TODO --build it out so it only populates with natural max--
	###populate the maxes for the range func as well with regular expressions. :-)
	t=0
	for each in args:
		x = each.replace("VALUE", alphaList[t] )
		mylist2.append(x)
		t+=1
		print (x)


		

		

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	# sample=b"\x31\xc9"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
	if len(mylist2)==4:
		totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))
	if len(mylist2)==5:
		totalPerm=aLimit*bLimit*cLimit * dLimit * eLimit*(nPr(numItems,numItems-1))

	print ("total permutations: ", totalPerm)
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	encodeBytes=bytearray()
	
	# encodeBytes4=bytearray()

	# print("mylist2")
	# print(mylist2)
	# print("sample")
	# print(sample)
	# input("break")

	# 1-6, 0-3, 0-3, 0-3
	permutations = list(itertools.permutations(mylist2))
	print("PERMS")
	print(len(permutations))
	# doStuff(permutations[1] ,22, 35, 1)

	# for each in (list(itertools.permutations(mylist2))):


	tupleStart = timeit.default_timer()
	### LIST COMPREHENSION ###
	# 6000 perm time = 0.0019388999999999934
	# encodeBytes4 = [ (a,b,c,each)
	# 				for a in range (aLimit)
	# 				for b in range (bLimit)
	# 				for c in range (cLimit)
	# 				for each in (list(itertools.permutations(mylist2)))
	# 				]
	### WHILE LOOPS ###
	# 6000 perm time = 0.001719499999999985
	encodeBytes4 = []
	eachLen = len(permutations)
	a = 0
	b = 0
	c = 0
	d = 0
	e = 0
	eachInd = 0

	curPerm = 0
	listLimit = 1000000
	totalRuns = 0
	numThreads = 4
	out = []
	if(len(mylist2) == 3):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(eachInd < eachLen):
						encodeBytes4.append((a,b,c,permutations[eachInd]))
						eachInd += 1
						curPerm += 1
						if(curPerm > listLimit):
							print("RUNNING PROCS")
							out = out + runProcs(encodeBytes4, sample, numThreads)
							totalRuns += numThreads
							curPerm = 0
							encodeBytes4 = []
							hitLimit = True
					c += 1
					eachInd = 0
				b += 1
				c = 0
			a += 1
			b = 0

		if(totalRuns != totalPerm):
			out = out + runProcs(encodeBytes4, sample, numThreads)
	
	elif(len(mylist2) == 4):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(d < dLimit):
						while(eachInd < eachLen):
							encodeBytes4.append((a,b,c,d,permutations[eachInd]))
							eachInd += 1
							curPerm += 1
							if(curPerm > listLimit):
								print("RUNNING PROCS")
								out = out + runProcs(encodeBytes4, sample, numThreads, 4)
								totalRuns += numThreads
								curPerm = 0
								encodeBytes4 = []
								hitLimit = True
						d += 1
						eachInd = 0
					c += 1
					d = 0
				b += 1
				c = 0
			a += 1
			b = 0
		if(totalRuns != totalPerm):
			out = out + runProcs(encodeBytes4, sample, numThreads, 4)

	elif(len(mylist2) == 5):
		while(a < aLimit):
			while(b < bLimit):
				while(c < cLimit):
					while(d < dLimit):
						while(e < eLimit):
							while(eachInd < eachLen):
								encodeBytes4.append((a,b,c,d,e,permutations[eachInd]))
								eachInd += 1
								curPerm += 1
								if(curPerm > listLimit):
									print("RUNNING PROCS")
									out = out + runProcs(encodeBytes4, sample, numThreads, 5)
									totalRuns += numThreads
									curPerm = 0
									encodeBytes4 = []
									hitLimit = True
							e += 1
							eachInd = 0
						d += 1
						e = 0
					c += 1
					d = 0
				b += 1
				c = 0
			a += 1
			b = 0
		if(totalRuns != totalPerm):
			out = out + runProcs(encodeBytes4, sample, numThreads, 5)

	tupleStop = timeit.default_timer()
	print("Tuple time: " + str(tupleStop - tupleStart))

	print("LISTDONE")
	# print(encodeBytes4)
	print(len(encodeBytes4))
	sortOut = sorted(out)
	print("LEN SORT PAR", str(len(sortOut)))

	
	stop = timeit.default_timer()
	print("Total time PAR: " + str(stop - start))


	# print ("Total number of iterations:", len(encodeBytes4))
	# for xx in encodeBytes4:
		
	# 	print (xx)
	# 	print ("\n\n")
	


	finTime=stop-start
	cores=240
	print (totalPerm, "Perm")
	numSeconds=0.00001

	print ("end time: ", z/finTime )
	print ("finTime", finTime)
	return sortOut

def runProcs(encodeBytes4, sample, numThreads, version = 3):
	# if __name__ == '__main__':
			# print("in runprocs")
			# print(encodeBytes4)
			# print(sample)
			# print(numThreads)
			# print(perms)
			# numThreads = 4
			argsLen = len(encodeBytes4)
			# r = len(encodeBytes4) % numThreads
			# startChunk = 0
			# rSize = math.ceil(len(encodeBytes4)/numThreads)
			# p_rSize = len(encodeBytes4)//numThreads

			processList= []
			rets = []
			queue = multiprocessing.Queue()

			for rank in range(numThreads):
				# print("adding new process = " + str(rank))
				# print("LOW BLOCK")
				# print(block_low(rank, numThreads, argsLen))
				# print("HIGH BLOCK")
				# print(block_high(rank, numThreads, argsLen))
				processList.append(multiprocessing.Process(target=p2Encode, args = (block_low(rank, numThreads, argsLen), block_high(rank, numThreads, argsLen), encodeBytes4, sample, rank, queue, version)))


			for proc in processList:
				proc.start()

			for proc in processList:
				ret = queue.get()
				rets = rets + ret

			for proc in processList:
				proc.join()

			for proc in processList:
				proc.terminate()

			# print("rets here")
			# print(rets)
			return rets

def runProcsDistr(encodeBytes4, sample, numThreads, version = 3):
			from distrFunc import p2EncodeDistr, doStuffP2Distr, doStuffP24Distr, doStuffP25Distr
	# if __name__ == '__main__':
			# print("in runprocs")
			# print(encodeBytes4)
			# print(sample)
			# print(numThreads)
			# print(perms)
			# numThreads = 4
			argsLen = len(encodeBytes4)
			# r = len(encodeBytes4) % numThreads
			# startChunk = 0
			# rSize = math.ceil(len(encodeBytes4)/numThreads)
			# p_rSize = len(encodeBytes4)//numThreads

			processList= []
			rets = []
			queue = multiprocessing.Queue()

			for rank in range(numThreads):
				# print("adding new process = " + str(rank))
				# print("LOW BLOCK")
				# print(block_low(rank, numThreads, argsLen))
				# print("HIGH BLOCK")
				# print(block_high(rank, numThreads, argsLen))
				processList.append(multiprocessing.Process(target=p2EncodeDistr, args = (block_low(rank, numThreads, argsLen), block_high(rank, numThreads, argsLen), encodeBytes4, sample, rank, queue, version)))


			for proc in processList:
				proc.start()

			for proc in processList:
				ret = queue.get()
				rets = rets + ret

			for proc in processList:
				proc.join()

			for proc in processList:
				proc.terminate()

			# print("rets here")
			# print(rets)
			return rets

def p2Encode(low, high, encodeBytes4, sample, rank, queue, version):

	outs = []
	if(version == 3):
		for i in range(low,high):
			outs.append(doStuffP2(encodeBytes4[i], sample, rank))
	elif(version == 4):
		for i in range(low,high):
			outs.append(doStuffP24(encodeBytes4[i], sample, rank))
	elif(version == 5):
		for i in range(low,high):
			outs.append(doStuffP25(encodeBytes4[i], sample, rank))

	queue.put(outs)
def doStuffP2(inputs, sample, rank):
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
	# print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
	# return out
	return (bytesStr, out, list((a,b,c)), each)
	# return "ok"

def doStuffP24(inputs, sample, rank):
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
	print (newString, "\n", "a",a, "b",b, "c",c ,"d",d, "")
	bytesStr = bytes(encodeBytes)
	out = newString + "\n" + "a" + str(a) + "b" + str(b) + "c" + str(c) + "d" + str(d)
	print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
	return (bytesStr, out, list((a,b,c,d)), each)
	# return out
	# return "ok"

def doStuffP25(inputs, sample, rank):
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
	print (newString, "\n", "a",a, "b",b, "c",c ,"d",d, "e",e, "")
	bytesStr = bytes(encodeBytes)
	out = newString + "\n" + "a" + str(a) + "b" + str(b) + "c" + str(c) + "d" + str(d) + "e" + str(e)
	print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
	return (bytesStr, out, list((a,b,c,d,e)), each)
	# return out
	# return "ok"





def specialEncoder5perm(*args):
	global aLimit
	global bLimit
	global cLimit
	global dLimit
	global eLimit
	global fLimit
	global gLimit
	global hLimit
	global iLimit
	global aValue
	global bValue
	global cValue
	global dValue
	global eValue
	global fValue
	global gValue
	global hValue
	global iValue

	print("specialEncoder5")
	u=0
	t=0

	alphaList=[]
	alpha = 'a'
	for i in range(0, 26): 
		alphaList.append(alpha) 
		alpha = chr(ord(alpha) + 1)  

	for val in args:
		lim, res=findObfusMethod(val)
		if t==0:
			aLimit, aValue=lim, res
		elif t==1:
			bLimit, bValue=lim, res
		elif t==2:
			cLimit, cValue=lim, res
		elif t==3:
			dLimit, dValue=lim, res
		elif t==4:
			eLimit, eValue=lim, res
		elif t==5:
			fLimit, fValue=lim, res
		elif t==6:
			gLimit, gValue=lim, res
		elif t==7:
			hLimit, hValue=lim, res
		elif t==8:
			iLimit, iValue=lim, res
		t+=1

	tempMax(4, 4,4, 3)

	print ("aLimit", aLimit, aValue)
	print ("bLimit", bLimit, bValue)
	print ("cLimit", cLimit, cValue)
	maxTrue=3
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4


	mylist2=[]
	# for x in args:
	# 	mylist2.append(x)
	z=0

	#### TODO --build it out so it only populates with natural max--
	###populate the maxes for the range func as well with regular expressions. :-)
	t=0
	for each in args:
		x = each.replace("VALUE", alphaList[t] )
		mylist2.append(x)
		t+=1
		print (x)


		

		

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	# sample=b"\x31\xc9"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
	if len(mylist2)==4:
		totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))

	print ("total permutations: ", totalPerm)
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	encodeBytes=bytearray()
	
	# encodeBytes4=bytearray()

	# print("mylist2")
	# print(mylist2)
	# print("sample")
	# print(sample)
	# input("break")
	final = []
	if len(mylist2)==3:

		# for each in (list(itertools.permutations(mylist2))):
		#  	print("orig each")
		#  	print(each)
		#  	encodeBytes4 = [doStuff_testP(each, a, b, c, sample)
		#  				for a in range (aLimit)
		#  				for b in range (bLimit)
		#  				for c in range (cLimit)
		#  				]
		#  	for item in encodeBytes4:
		#  		final.append(item)

		perms = list(itertools.permutations(mylist2))
		if __name__ == '__main__':
			
			print(perms)
			numThreads = 8
			# r = len(perms) % numThreads
			# startChunk = 0
			# rSize = math.ceil(len(perms)/numThreads)
			# p_rSize = len(perms)//numThreads
			processList = []
			rets = []
			queue = multiprocessing.Queue()

			for procnum in range(len(perms)):
				each = perms[procnum]
				eachStr = ""
				processList.append(multiprocessing.Process(target=permHelp1, args = (queue, (each,), aLimit, bLimit, cLimit)))


			for proc in processList:
				proc.start()

			for proc in processList:
				ret = queue.get()
				rets.append(ret)

			for proc in processList:
				proc.join()

			for proc in processList:
				proc.terminate()
				# encodeBytes4 = result1.get()
		
			print("here final")
			print(len(rets))
			print(rets[1])
			item = rets[0]
			print("here first item")
			print(len(item))
			print(item)
			next = item[0]
			print("here next")
			print(len(next))
			print(next)
			print("###############")


			for block in rets:
				for item in block:
					print (item[0], "\n", "a",item[2], "b",item[3], "c",item[4] ,"")
					encodeBytes = item[1]
					bytesStr = bytes(encodeBytes)
					print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
		# encodeBytes4 = [doStuff(each, a, b, c, sample)
		# 				for a in range (aLimit)
		# 				for each in (list(itertools.permutations(mylist2)))
		# 				for b in range (bLimit)
		# 				for c in range (cLimit)
		# 				]
	# elif len(mylist2)==4:
	# 	encodeBytes4 = [doStuff4(each, a, b, c, d, sample)
	# 					for a in range (aLimit)
	# 					for each in (list(itertools.permutations(mylist2)))
	# 					for b in range (bLimit)
	# 					for c in range (cLimit)
	# 					for d in range (dLimit)
	# 					]

	#print("Encodebytes here")
	#print(encodeBytes4)
	stop = timeit.default_timer()
	print("Total time: " + str(stop - start))


	# print ("Total number of iterations:", len(encodeBytes4))
	# for xx in encodeBytes4:
		
	# 	print (xx)
	# 	print ("\n\n")
	


	finTime=stop-start
	cores=240
	print (totalPerm, "Perm")
	numSeconds=0.00001

	print ("end time: ", z/finTime )
	print ("finTime", finTime)

def permHelp1(queue, each, aLimit, bLimit, cLimit):


	print("hi")
	print(each)
	print(aLimit)
	print(bLimit)
	print(cLimit)
	# each = each.split("\n")
	final = []
	encodeBytes4 =[]

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"


	# encodeBytes4 = permHelp2(each,sample)
	encodeBytes4 = [doStuff_testP(each, a, b, c, sample)
						for a in range (aLimit)
						for b in range (bLimit)
						for c in range (cLimit)
						]

	# print("did stuff")
	# print(encodeBytes4)
	queue.put(encodeBytes4)
	# return encodeBytes4

# def permHelp2(each,sample):
# 	global aLimit
# 	global bLimit
# 	global cLimit
# 	global dLimit
# 	global eLimit
# 	global fLimit
# 	global gLimit
# 	global hLimit
# 	global iLimit
# 	global aValue
# 	global bValue
# 	global cValue
# 	global dValue
# 	global eValue
# 	global fValue
# 	global gValue
# 	global hValue
# 	global iValue

# 	encodeBytes4 = [doStuff_testP(each, a, b, c, sample)
# 						for a in range (aLimit)
# 						for b in range (bLimit)
# 						for c in range (cLimit)
# 						]

# 	return encodeBytes4




def specialEncoderParallel(*args):
	global aLimit
	global bLimit
	global cLimit
	global dLimit
	global eLimit
	global fLimit
	global gLimit
	global hLimit
	global iLimit
	global aValue
	global bValue
	global cValue
	global dValue
	global eValue
	global fValue
	global gValue
	global hValue
	global iValue

	print("specialEncoderParallel")
	u=0
	t=0

	alphaList=[]
	alpha = 'a'
	for i in range(0, 26): 
		alphaList.append(alpha) 
		alpha = chr(ord(alpha) + 1)  

	for val in args:
		lim, res=findObfusMethod(val)
		if t==0:
			aLimit, aValue=lim, res
		elif t==1:
			bLimit, bValue=lim, res
		elif t==2:
			cLimit, cValue=lim, res
		elif t==3:
			dLimit, dValue=lim, res
		elif t==4:
			eLimit, eValue=lim, res
		elif t==5:
			fLimit, fValue=lim, res
		elif t==6:
			gLimit, gValue=lim, res
		elif t==7:
			hLimit, hValue=lim, res
		elif t==8:
			iLimit, iValue=lim, res
		t+=1

	tempMax(10, 10,10, 3)

	print ("aLimit", aLimit, aValue)
	print ("bLimit", bLimit, bValue)
	print ("cLimit", cLimit, cValue)
	maxTrue=3
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4


	mylist2=[]
	# for x in args:
	# 	mylist2.append(x)
	z=0

	#### TODO --build it out so it only populates with natural max--
	###populate the maxes for the range func as well with regular expressions. :-)
	t=0
	for each in args:
		x = each.replace("VALUE", alphaList[t] )
		mylist2.append(x)
		t+=1
		print (x)


		

		

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	# sample=b"\x31\xc9"
	# print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
	if len(mylist2)==4:
		totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))

	print ("total permutations: ", totalPerm)
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	encodeBytes=bytearray()
	
	# encodeBytes4=bytearray()

	# print("mylist2")
	# print(mylist2)
	# print("sample")
	# print(sample)
	# input("break")
	final = []
	if len(mylist2)==3:

		# for each in (list(itertools.permutations(mylist2))):
		#  	print("orig each")
		#  	print(each)
		 	# encodeBytes4 = [doStuff_testP(each, a, b, c, sample)
		 	# 			for a in range (aLimit)
		 	# 			for b in range (bLimit)
		 	# 			for c in range (cLimit)
		 	# 			]
		#  	for item in encodeBytes4:
		#  		final.append(item)

		perms = list(itertools.permutations(mylist2))

		if __name__ == '__main__':
			
			# print(perms)
			numThreads = 8
			r = len(perms) % numThreads
			startChunk = 0
			rSize = math.ceil(len(perms)/numThreads)
			p_rSize = len(perms)//numThreads
			# processList = []
			rets = []
			queue = multiprocessing.Queue()
			procnum = 0
			while(procnum < len(perms)):
				loopThreads = 0
				print("starting from procnum = " + str(procnum))
				processList = []
				# queue = multiprocessing.Queue()
				while((procnum < len(perms)) and (loopThreads < numThreads)):
					print("adding new process = " + str(procnum))
					each = perms[procnum]
					eachStr = ""
					processList.append(multiprocessing.Process(target=threadEncode, args = (queue, (each,), aLimit, bLimit, cLimit)))
					procnum = procnum + 1
					loopThreads = loopThreads + 1

				for proc in processList:
					proc.start()

				for proc in processList:
					ret = queue.get()
					rets.append(ret)

				for proc in processList:
					proc.join()

				for proc in processList:
					proc.terminate()
					# encodeBytes4 = result1.get()
		
			# print("here final")
			# print(len(rets))
			# print(rets[1])
			# item = rets[0]
			# print("here first item")
			# print(len(item))
			# print(item)
			# next = item[0]
			# print("here next")
			# print(len(next))
			# print(next)
			# print("###############")


			for block in rets:
				for item in block:
					print (item[0], "\n", "a",item[2], "b",item[3], "c",item[4] ,"")
					encodeBytes = item[1]
					bytesStr = bytes(encodeBytes)
					print ("\nencoder5 new", binaryToStr(bytesStr),"\n\n\n")
		# encodeBytes4 = [doStuff(each, a, b, c, sample)
		# 				for a in range (aLimit)def 
		# 				for each in (list(itertools.permutations(mylist2)))
		# 				for b in range (bLimit)
		# 				for c in range (cLimit)
		# 				]
	# elif len(mylist2)==4:
	# 	encodeBytes4 = [doStuff4(each, a, b, c, d, sample)
	# 					for a in range (aLimit)
	# 					for each in (list(itertools.permutations(mylist2)))
	# 					for b in range (bLimit)
	# 					for c in range (cLimit)
	# 					for d in range (dLimit)
	# 					]

	#print("Encodebytes here")
	#print(encodeBytes4)
	stop = timeit.default_timer()
	print("Total time: " + str(stop - start))


	# print ("Total number of iterations:", len(encodeBytes4))
	# for xx in encodeBytes4:
		
	# 	print (xx)
	# 	print ("\n\n")
	


	finTime=stop-start
	cores=240
	print (totalPerm, "Perm")
	numSeconds=0.00001

	print ("end time: ", z/finTime )
	print ("finTime", finTime)


def threadEncode(queue, each, aLimit, bLimit, cLimit):


	# print("hi")
	# print(each)
	# print(aLimit)
	# print(bLimit)
	# print(cLimit)
	# each = each.split("\n")
	final = []
	encodeBytes4 =[]

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"


	# encodeBytes4 = permHelp2(each,sample)
	encodeBytes4 = [doStuffParallel(each, a, b, c, sample)
						for a in range (aLimit)
						for b in range (bLimit)
						for c in range (cLimit)
						]

	# print("did stuff")
	# print(encodeBytes4)
	queue.put(encodeBytes4)
	# return encodeBytes4

def specialEncoder5q(*args):
	if __name__ == '__main__':
		global aLimit
		global bLimit
		global cLimit
		global dLimit
		global eLimit
		global fLimit
		global gLimit
		global hLimit
		global iLimit
		global aValue
		global bValue
		global cValue
		global dValue
		global eValue
		global fValue
		global gValue
		global hValue
		global iValue

		print("specialEncoder5")
		u=0
		t=0

		alphaList=[]
		alpha = 'a'
		for i in range(0, 26): 
			alphaList.append(alpha) 
			alpha = chr(ord(alpha) + 1)  

		for val in args:
			lim, res=findObfusMethod(val)
			if t==0:
				aLimit, aValue=lim, res
			elif t==1:
				bLimit, bValue=lim, res
			elif t==2:
				cLimit, cValue=lim, res
			elif t==3:
				dLimit, dValue=lim, res
			elif t==4:
				eLimit, eValue=lim, res
			elif t==5:
				fLimit, fValue=lim, res
			elif t==6:
				gLimit, gValue=lim, res
			elif t==7:
				hLimit, hValue=lim, res
			elif t==8:
				iLimit, iValue=lim, res
			t+=1

		tempMax(4, 4,4, 3)

		print ("aLimit", aLimit, aValue)
		print ("bLimit", bLimit, bValue)
		print ("cLimit", cLimit, cValue)
		maxTrue=3
		Max=maxTrue
		maxValuU=Max#20
		maxValuW=Max#4
		maxValuT=Max#2
		maxValuR=Max#4


		mylist2=[]
		# for x in args:
		# 	mylist2.append(x)
		z=0

		#### TODO --build it out so it only populates with natural max--
		###populate the maxes for the range func as well with regular expressions. :-)
		t=0
		for each in args:
			x = each.replace("VALUE", alphaList[t] )
			mylist2.append(x)
			t+=1
			print (x)


			

			

		sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
		# sample=b"\x31\xc9"
		print (type(sample))
		print ("size", len(mylist2))
		numItems=len(mylist2)
		totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
		if len(mylist2)==4:
			totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))

		print ("total permutations: ", totalPerm)
		permPercent=0.1*totalPerm
		start = timeit.default_timer()
		encodeBytes=bytearray()
		
		# encodeBytes4=bytearray()

		# print("mylist2")
		# print(mylist2)
		# print("sample")
		# print(sample)
		# input("break")
		if len(mylist2)==3:
			encodeBytes4 = [doStuff_testQ(each, a, b, c, sample)
							for a in range (aLimit)
							for each in (list(itertools.permutations(mylist2)))
							for b in range (bLimit)
							for c in range (cLimit)
							]
		# elif len(mylist2)==4:
		# 	encodeBytes4 = [doStuff4(each, a, b, c, d, sample)
		# 					for a in range (aLimit)
		# 					for each in (list(itertools.permutations(mylist2)))
		# 					for b in range (bLimit)
		# 					for c in range (cLimit)
		# 					for d in range (dLimit)
		# 					]

		#print("Encodebytes here")
		#print(encodeBytes4)
		stop = timeit.default_timer()
		print("Total time: " + str(stop - start))


		# print ("Total number of iterations:", len(encodeBytes4))
		# for xx in encodeBytes4:
			
		# 	print (xx)
		# 	print ("\n\n")
		


		finTime=stop-start
		cores=240
		print (totalPerm, "Perm")
		numSeconds=0.00001

		print ("end time: ", z/finTime )
		print ("finTime", finTime)


def specialEncoder5_test(*args):
	if __name__ == '__main__':
		global aLimit
		global bLimit
		global cLimit
		global dLimit
		global eLimit
		global fLimit
		global gLimit
		global hLimit
		global iLimit
		global aValue
		global bValue
		global cValue
		global dValue
		global eValue
		global fValue
		global gValue
		global hValue
		global iValue

		print("specialEncoder5")
		u=0
		t=0

		alphaList=[]
		alpha = 'a'
		for i in range(0, 26): 
			alphaList.append(alpha) 
			alpha = chr(ord(alpha) + 1)  

		for val in args:
			lim, res=findObfusMethod(val)
			if t==0:
				aLimit, aValue=lim, res
			elif t==1:
				bLimit, bValue=lim, res
			elif t==2:
				cLimit, cValue=lim, res
			elif t==3:
				dLimit, dValue=lim, res
			elif t==4:
				eLimit, eValue=lim, res
			elif t==5:
				fLimit, fValue=lim, res
			elif t==6:
				gLimit, gValue=lim, res
			elif t==7:
				hLimit, hValue=lim, res
			elif t==8:
				iLimit, iValue=lim, res
			t+=1

		tempMax(4, 4,4, 3)

		print ("aLimit", aLimit, aValue)
		print ("bLimit", bLimit, bValue)
		print ("cLimit", cLimit, cValue)
		maxTrue=3
		Max=maxTrue
		maxValuU=Max#20
		maxValuW=Max#4
		maxValuT=Max#2
		maxValuR=Max#4


		mylist2=[]
		# for x in args:
		# 	mylist2.append(x)
		z=0

		#### TODO --build it out so it only populates with natural max--
		###populate the maxes for the range func as well with regular expressions. :-)
		t=0
		for each in args:
			x = each.replace("VALUE", alphaList[t] )
			mylist2.append(x)
			t+=1
			print (x)


			

			

		sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
		# sample=b"\x31\xc9"
		print (type(sample))
		print ("size", len(mylist2))
		numItems=len(mylist2)
		totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
		if len(mylist2)==4:
			totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))

		print ("total permutations: ", totalPerm)
		permPercent=0.1*totalPerm
		start = timeit.default_timer()
		encodeBytes=bytearray()
		
		# encodeBytes4=bytearray()
		#rSize = math.ceil(numRuns/numThreads)
		#p_rSize = numRuns//numThreads

		pool = multiprocessing.Pool(processes=4)

		encodeBytes4 = [pool.apply(testPool5, args = (mylist2, each, 0, 0, 0, sample, aLimit, bLimit, cLimit))]
		stop = timeit.default_timer()
		print("Total time: " + str(stop - start))


		# print ("Total number of iterations:", len(encodeBytes4))
		# for xx in encodeBytes4:
			
		# 	print (xx)
		# 	print ("\n\n")
		


		finTime=stop-start
		cores=240
		print (totalPerm, "Perm")
		numSeconds=0.00001

		print ("end time: ", z/finTime )
		print ("finTime", finTime)

def testPool5(mylist2, each, a, b, c, sample, aLimit, bLimit, cLimit):
	if len(mylist2)==3:
		encodeBytes4 = [doStuff_test(each, a, b, c, sample)
						for a in range (aLimit)
						for each in (list(itertools.permutations(mylist2)))
						for b in range (bLimit)
						for c in range (cLimit)
						]
	elif len(mylist2)==4:
		encodeBytes4 = [doStuff4(each, a, b, c, d, sample)
						for a in range (aLimit)
						for each in (list(itertools.permutations(mylist2)))
						for b in range (bLimit)
						for c in range (cLimit)
						for d in range (dLimit)
						]
	return encodeBytes4

#   (each, a, b, c, sample))
def test101(each, a,b,c, sample):
	print (each)
	print (a, b, c)
	print (sample)
	print ("\n\n")

def test102(each):
	print (each)
	print ("\n\n")


def specialEncoder6(myInput):

	global aLimit
	global bLimit
	global cLimit
	global dLimit
	global eLimit
	global fLimit
	global gLimit
	global hLimit
	global iLimit
	global aValue
	global bValue
	global cValue
	global dValue
	global eValue
	global fValue
	global gValue
	global hValue
	global iValue

	print("specialEncoder6")
	u=0
	t=0


	print (myInput)
	alphaList=[]
	alpha = 'a'
	for i in range(0, 26): 
		alphaList.append(alpha) 
		alpha = chr(ord(alpha) + 1)  
	print ("ok")
	for val in myInput:
		print ("ok1a", val)
		lim, res=findObfusMethod(val)
		print ("ok1b", lim)
		if t==0:
			aLimit, aValue=lim, res
		elif t==1:
			bLimit, bValue=lim, res
		elif t==2:
			cLimit, cValue=lim, res
		elif t==3:
			dLimit, dValue=lim, res
		elif t==4:
			eLimit, eValue=lim, res
		elif t==5:
			fLimit, fValue=lim, res
		elif t==6:
			gLimit, gValue=lim, res
		elif t==7:
			hLimit, hValue=lim, res
		elif t==8:
			iLimit, iValue=lim, res
		t+=1
	print ("ok2")
	tempMax(4, 4,4, 3)
	print ("ok3")
	print ("aLimit", aLimit, aValue)
	print ("bLimit", bLimit, bValue)
	print ("cLimit", cLimit, cValue)
	maxTrue=3
	Max=maxTrue
	maxValuU=Max#20
	maxValuW=Max#4
	maxValuT=Max#2
	maxValuR=Max#4


	mylist2=[]
	# for x in args:
	# 	mylist2.append(x)
	z=0

	#### TODO --build it out so it only populates with natural max--
	###populate the maxes for the range func as well with regular expressions. :-)
	t=0
	for each in myInput:
		x = each.replace("VALUE", alphaList[t] )
		mylist2.append(x)
		t+=1
		print (x)


		

		

	sample=b"\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76\x31\xc9\x64\x8b\x71\x30\x8b\x76"
	# sample=b"\x31\xc9"
	print (type(sample))
	print ("size", len(mylist2))
	numItems=len(mylist2)
	totalPerm=aLimit*bLimit*cLimit * (nPr(numItems,numItems-1))
	if len(mylist2)==4:
		totalPerm=aLimit*bLimit*cLimit * dLimit *(nPr(numItems,numItems-1))

	print ("total permutations: ", totalPerm)
	permPercent=0.1*totalPerm
	start = timeit.default_timer()
	encodeBytes=bytearray()
	
	# encodeBytes4=bytearray()
	pool = multiprocessing.Pool()
	inputs = [strSub, strXor,strAdd]


	outputs_async = pool.map_async(test102, alphaList)
	outputs = outputs_async.get()


	# print("Input: {}".format(inputs)) 
	# print("Output: {}".format(outputs)) 
	if len(mylist2)==3:
		# encodeBytes4 = [doStuff(each, a, b, c, sample)
		outputs_async = [pool.map_async(test101, (each, a, b, c, sample))
						# outputs = outputs_async.get()
						# inputs=[a, each, b, c]
						for a in range (aLimit)

						for each in (list(itertools.permutations(mylist2)))
						for b in range (bLimit)
						for c in range (cLimit)
						]


	elif len(mylist2)==4:
		encodeBytes4 = [doStuff4(each, a, b, c, d, sample)
						for a in range (aLimit)
						for each in (list(itertools.permutations(mylist2)))
						for b in range (bLimit)
						for c in range (cLimit)
						for d in range (dLimit)
						]

	stop = timeit.default_timer()
	print("Total time: " + str(stop - start))


	# print ("Total number of iterations:", len(encodeBytes4))
	# for xx in encodeBytes4:
		
	# 	print (xx)
	# 	print ("\n\n")
	


	finTime=stop-start
	cores=240
	print (totalPerm, "Perm")
	numSeconds=0.00001
	# print (totalPerm*numSeconds, "seconds")
	# print ((totalPerm*numSeconds)/60, "minutes")
	# print (((totalPerm*numSeconds)/60)/60, "hours")
	# print ((((totalPerm*numSeconds)/60)/60)/24, "days")
	# print ("spread across " + str(cores) + " cores: ", ((((totalPerm*numSeconds)/60)/60)/24)/cores, "days")


	print ("end time: ", z/finTime )
	print ("finTime", finTime)



####### different encoders

if __name__ == '__main__':

	XORstr="XOR(t)\n"
	ADDstr="ADD(u)\n"
	SUBstr="SUB(w)\n"
	ROTstr="ROT(rr)\n"
	LSHstr="LSH(v)\n"

	strSub="new=tohex((new ^(x)),8)\n" 
	strAdd="new=tohex((new +(u)),8)\n" 
	strXor="new=tohex((new - (w)),8)\n"


	# True

	#b1
	boolDo=False
	boolDo2=False
	boolDo3=False
	boolDo4=False
	boolDo44=False
	boolDo4ListComp=False
	boolDoExpListComp=False
	boolDo5=False
	boolDo6=False
	boolDoParallel=False
	boolDoLC=False
	boolDoTest=True

	if boolDo:
		specialEncoder(XORstr, ADDstr, ROTstr)
	# specialEncoder() is simple - just takes txt and shows that it can create designated # of distinct results.

	if boolDo2:
		specialEncoder2(20, XORstr, ADDstr, ROTstr)
	#specialencoder2() is a variation - sligtly different way - very rough, poc. timing is slightly different. can enter max value as first paramater.

	strSub="new=tohex((new ^(x)),8)\n" 
	strAdd="new=tohex((new +(u)),8)\n" 
	strXor="new=tohex((new - (w)),8)\n"

	if boolDo3:
		specialEncoder3(strSub, strAdd, strXor)
	#Doing real work now. outter: 2 for loops, inner 2 while loops, then final for loop for each byte in sample - not good!
	# Max=5, 750 total, Total time: 9.0848923

	if boolDo4:
		specialEncoder4(strSub, strAdd, strXor)
	#Doing real work now. outter: 2 for loops, inner 2 while loops
	# Max=5, 750 total, Total time: 11.468003800000002

	if boolDo44:
		specialEncoder44(strSub, strAdd, strXor)
	# just another variation, slower
	# Max=5, 750 total, Total time: 12.0538737

	if boolDo4ListComp:
		specialEncoder4ListComprehension(strSub, strAdd, strXor)
	#doing it with List Comprehension
	# Max=5, 750 total, Total time: 5.5642182

	if boolDoExpListComp:
		specialEncoderExperimental(strSub, strAdd, strXor)
		#unknown - broken - ignore

	###OLD toHEx function call works - but & 255 is faster)
	strShRight="new=tohex((new << (z)),8)\n"
	strSub="new=tohex((new -(VALUE)),8)\n" 
	strAdd="new=tohex((new +(VALUE)),8)\n" 
	strXor="new=tohex((new ^ (VALUE)),8)\n"
	### New Style
	strAdd="new=(new +VALUE) & 255\n" 
	strSub="new=(new -VALUE) & 255\n"
	strXor="new=(new ^ VALUE) & 255\n"
	strNot="new=~(new) & 255\n"
	strRol="new=rol(new,VALUE,8)\n"
	strRor="new=ror(new,VALUE,8)\n"
	strShRight="new=(new << VALUE) & 255\n"

	if boolDo5:
		specialEncoder5(strSub, strAdd, strXor, strAdd)
	# this is the final single core best list comprehension one. It takes multiple arguments, and it will go into a list comprehension based on that. It currently only supports 3 or 4 args, but could be expanded (new list comprehension for each).
	# This one uses different strings - better ones. It removes the toHex and implements the logic directly (saving on unnecessary function call).
	# This uses a function to calculate the REAL maximum set of values for each operation, based on what I determined to be acceptable for one byte. If it is more than this, it is no problem, but it will just keep repeating the same operations due to truncation - so not anything new. Thus, for try to decode (so it can find the PEB), this is not useful.
	# anything specialEncoder5 and up will use the new form  with value. ToHex would work with value, but redundant. 

	# output: 384 permutations  finTime 3.2777617 
	#    750 would be equivalent to 6.4018783203125


	if boolDoParallel:
		specialEncoderParallel(strSub, strAdd, strXor)

	if boolDoLC:
		specialEncoderP2(strXor, strAdd, strXor, strAdd, strSub)

	if boolDo6:
		myOwnList=[]
		myOwnList.append(strSub)
		myOwnList.append(strAdd)
		myOwnList.append(strXor)
		specialEncoder6(myOwnList)   # this one does 3 arguments

		inputs = [strSub, strXor,strAdd, strAdd]

	if boolDoTest:
		testSeq = specialEncoder5(strSub, strAdd, strNot)
		print("\n\n\n #################################### \n\n\n")
		testPar = specialEncoderP2(strSub, strAdd, strNot)
		testfail = False
		for i in range(len(testSeq)):
			print("SEQ: ", testSeq[i], "\n")
			print("PAR: ", testPar[i], "\n")
			if(testSeq[i] != testPar[i]):
				print("FAILED TEST")
				testfail = True
				break
		if(testfail == False):
			print("SUCCESSFUL TEST")

		# if(testSeq == testPar):
		# 	print("SUCCESS TEST")
		# else:
		# 	print("FAILED TEST")
	# specialEncoder6(inputs)              # this ones does 4

# if __name__ == '__main__':
# 	pool = multiprocessing.Pool()
# 	inputs = [strSub, strXor,strAdd]

# 	outputs_async = pool.map_async(specialEncoder6, inputs)
# 	outputs = outputs_async.get()


# 	print("Input: {}".format(inputs)) 
# 	print("Output: {}".format(outputs)) 



# specialEncoder5Experimental(strSub, strAdd, strXor)

# ans= rol(ans,1,8)
# print (2, hex(ans),"\n\n\n")



# specialEncoder5(strSub, strAdd, strRol)#,strShRight)

# specialEncoder5(strSub, strXor, strAdd)#,strShRight)


# specialEncoder5(strSub, strXor, strNot)#,strShRight)




# specialEncoder5(strSub, strNot, strRol, strNot)#,strShRight)

# LSHstr="LSH(v)\n"


# specialEncoder3(40, XORstr, ADDstr, ROTstr)
# specialEncoder(XORstr, ADDstr, ROTstr)



# print (nPr(3,3))
####   2 * 3 * 1 * 3 * 2 * 1




# 