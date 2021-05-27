
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

ans=0xff ^ 99
print (hex(ans), len(str(hex(ans)))-2)
ans =truncateTobyte(ans)
print (hex(ans))



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
ans=0xffffffff ^ 99
print (hex(ans), len(str(hex(ans)))-2)
ans =truncateToWord(ans)
print (hex(ans))

#ffff
print ("\n\n\n\n\nRight Shifting 3")
ans=0xffd59
print (0, hex(ans))
ans=ans >>3
print(1, hex(ans))
ans=ans <<3
print (2, hex(ans))


print ("\n\n\n\n\nLeft Shifting ")
ans=0x35
print (0, hex(ans))
ans=ans <<3
print(1, hex(ans))
ans=ans >>3
print (2, hex(ans))

print ("\n\n\n\n\nx & y ")
ans=0xfff
print (0, hex(ans))
ans=ans  & 3
print(1, hex(ans))
ans=3 &  ans
print (2, hex(ans))

print ("\n\n\n\n\nx | y ")
ans=0xfff
print (0, hex(ans))
ans=ans  | 34
print(1, hex(ans))
ans= ans| 34
print (2, hex(ans))




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


print ("\n\n\n\n\nrol")
ans=0xde
print (0, hex(ans))
ans=rol(ans,8, 8)
print(1, hex(ans))
ans= ror(ans,8,8)
print (2, hex(ans),"\n\n\n")

print ("\n\n\n\n\nror")
ans=0xde
print (0, hex(ans))
ans=ror(ans,8, 8)
print(1, hex(ans))
ans= rol(ans,8,8)
print (2, hex(ans),"\n\n\n")

ans=0xfff
print(1, ans)

ans=ans ^0
print(2, ans)

ans=ans^0xff
print(3, ans)

ans=ans^0xff
print(3, ans)



print ("\n\n\n\n\nLeft Shifting  ")
ans=0x355555
print (0, hex(ans))
ans=ans <<3
print(1, hex(ans))
ans=ans >>3
print (2, hex(ans))

print ("\n\n\n\n\nLeft Shifting 8")
ans=0xff
print (0, hex(ans))
ans=tohex((ans <<1),8)  ### 2 is the max for 8 bit 
print(1, hex(ans))
ans=tohex((ans >>1), 8)
print (2, hex(ans))




print ("\n\n\n\n\nLeft Shifting 8 - no tohex")
ans=0xff
print (0, hex(ans))
ans=((ans <<1))  ### 0 is the max for 8 bit  need at least a word
print(1, hex(ans))
ans=((ans >>1))
print (2, hex(ans))




print ("\n\n\n\n\nLeft Shifting 16")
ans=0xde
print (0, hex(ans))
ans=tohex((ans <<8),16)    ## 8 is max for 16 bit!!!!!
print(1, hex(ans))
ans=tohex((ans >>8), 16)
print (2, hex(ans))



print ("\n\n\n\n\nLeft Shifting 32")
ans=0xff
print (0, hex(ans))
ans=tohex((ans <<23),32)    ## 2
print(1, hex(ans))
ans=tohex((ans >>23), 32)
print (2, hex(ans))




print ("\n\n\n\n\nAdding 8")
ans=0x43
print (0, hex(ans))
ans=tohex((ans -(0xff+3)),8)    ## 2
print(1, hex(ans))
ans=tohex((ans +0xff+3), 8)
print (2, hex(ans))



print ("\n\n\n\n\nAdding 8")
ans=0x43
print (0, hex(ans))
ans=tohex((ans -2),8)    ## 2
print(1, hex(ans))
ans=tohex((ans +2), 8)
print (2, hex(ans))


print ("\n\n\n\n\nXOR 8")
ans=0xde
print (0, hex(ans))
ans=tohex((ans ^ 0xff+4),8)    ## 2
print(1, hex(ans))
ans=tohex((ans  ^ 0xff+4), 8)
print (2, hex(ans))



print ("\n\n\n\n\nXOR 8")
ans=0xde
print (0, hex(ans))
ans=tohex((ans ^ 3),8)    ## 2
print(1, hex(ans))
ans=tohex((ans  ^ 3), 8)
print (2, hex(ans))







print ("\n\n\n\n\nrortt")
ans=0xde
print (0, hex(ans))
ans=ror(ans,6, 8)
print(1, hex(ans))
ans= rol(ans,5,8)
print (2, hex(ans),"\n")
ans= rol(ans,1,8)
print (3, hex(ans),"\n")



print ("\n\n\n\nNOT 8")
ans=0xde
print (0, hex(ans))
ans=tohex((~ans),8)    ## 2
print(1, hex(ans))
ans=tohex((~ans), 8)
print (2, hex(ans))


print ("\n\n\n\nNOT 8")
ans=0x9c
print (0, hex(ans))
ans=tohex((~ans),8)    ## 2
print(1, hex(ans))
ans=tohex((~ans), 8)
print (2, hex(ans))



print ("\n\n\n\nNOT 8")
ans=0x9c
print (0, hex(ans))
ans=~ans  &255  ## 2
print(1, hex(ans))
ans=~ans &255
print (2, hex(ans))





print ("\n\n\n\nrol")
ans=0x31
print (0, hex(ans))
ans= tohex(rol(ans,7),8)
print (1, hex(ans))
ans=0x31

ans= rol(ans,7)
print (2, hex(ans))



print ("\n\n\n\n\nAdding 8")
ans=0x43
print (0, hex(ans))
ans=tohex((ans -(0xff+3)),8)    ## 2
print(1, hex(ans))
ans=tohex((ans +0xff+3), 8)
print (2, hex(ans))

print ("\n\n\n\n\nAdding 8")
ans=0x43
print (0, hex(ans))
ans=tohex((ans -2),8)    ## 2
print(1, hex(ans))
ans=tohex((ans +2), 8)
print (2, hex(ans))



print ("\n\n\n\n\nAdding 8 new")
ans=0x43
print (0, hex(ans))
ans=(ans -(0xff+3)) & 255   ## 2
print(1, hex(ans))
ans=(ans +0xff+3) & 255
print (2, hex(ans))

print ("\n\n\n\n\nAdding 8 new")
ans=0x43
print (0, hex(ans))
ans=(ans -2) & 255    ## 2
print(1, hex(ans))
ans=(ans +2) & 255
print (2, hex(ans))



print ("\n\n\n\n\nAdding bend 255")
ans=0xff
print (0, hex(ans))
ans=ans + 3   ## 2
print(1, hex(ans))
ans=(ans +3) 
print (2, hex(ans))



print ("\n\n\n\n\nAdding bend 255")
ans=0xff
print (0, hex(ans))
ans=tohex((  ans + 1), 8)   ## 2
print(3, hex(ans))
ans=tohex((ans +1), 8) 
print (3, hex(ans))


print ("\n\n\n\n\nAdding bend 255")
ans=0xff
print (0, hex(ans))
ans=(  ans + 2) & 255
print(3, hex(ans))
ans=(ans +1) & 255
print (3, hex(ans))



print ("\n\n\n\n\nsub")
ans=0x00
print (0, hex(ans))
ans=tohex((ans -(0xff+3)),8)    ## 2
print(1, hex(ans))
ans=tohex((ans +0xff+3), 8)
print (2, hex(ans))





print ("\n\n\n\n\nsub")
ans=0x00
print (0, hex(ans))
ans=tohex((ans -(2)),8)    ## 2
print(1, hex(ans))
ans=tohex((ans +2), 8)
print (2, hex(ans))




print ("\n\n\n\n\nsub new")
ans=0x00
print (0, hex(ans))
ans=(ans -(0xff+3)) & 255   ## 2
print(1, hex(ans))
ans=(ans +0xff+3) & 255
print (2, hex(ans))





print ("\n\n\n\n\nsub new")
ans=0x00
print (0, hex(ans))
ans=(ans -(2)) & 255   ## 2
print(1, hex(ans))
ans=(ans +2) & 255
print (2, hex(ans))




print ("<< testing")
new=0x02
new=tohex((new << (1)),8)
print (1, hex(new))
ans=0x25
new=tohex((new << (2)),8)
print (2, hex(new))
ans=0x25
new=tohex((new << (3)),8)
print (3, hex(new))
ans=0x25
new=tohex((new << (4)),8)
print (4, hex(new))
ans=0x25
new=tohex((new << (5)),8)
print (5, hex(new))
ans=0x25
new=tohex((new << (6)),8)
print (6, hex(new))
ans=0x25
new=tohex((new << (7)),8)
print (7, hex(new))
ans=0x25
new=tohex((new << (8)),8)
print (8, hex(new))
ans=0x25
new=tohex((new << (9)),8)
print (9, hex(new))
ans=0x25
new=tohex((new << (10)),8)
print (10, hex(new))


print ("<< testing")
new=0x02
new=(new << (1)) & 255
print (1, hex(new))
ans=0x25
new=(new << (2)) & 255
print (2, hex(new))
ans=0x25
new=(new << (3)) & 255
print (3, hex(new))
ans=0x25
new=(new << (4)) & 255
print (4, hex(new))
ans=0x25
new=(new << (5)) & 255
print (5, hex(new))
ans=0x25
new=(new << (6)) & 255
print (6, hex(new))
ans=0x25
new=(new << (7)) & 255
print (7, hex(new))
ans=0x25
new=(new << (8)) & 255
print (8, hex(new))
ans=0x25
new=(new << (9)) & 255
print (9, hex(new))
ans=0x25
new=(new << (10)) & 255
print (10, hex(new))