
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


def p2EncodeDistr(low, high, encodeBytes4, sample, rank, queue, version):

	outs = []
	if(version == 3):
		for i in range(low,high):
			outs.append(doStuffP2Distr(encodeBytes4[i], sample, rank))
	elif(version == 4):
		for i in range(low,high):
			outs.append(doStuffP24Distr(encodeBytes4[i], sample, rank))
	elif(version == 5):
		for i in range(low,high):
			outs.append(doStuffP25Distr(encodeBytes4[i], sample, rank))

	queue.put(outs)
def doStuffP2Distr(inputs, sample, rank):
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

def doStuffP24Distr(inputs, sample, rank):
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

def doStuffP25Distr(inputs, sample, rank):
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

