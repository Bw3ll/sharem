import struct
import binascii

vala=0xffffffd6
top=0xffffffff   #-1
topD=4294967295
test=0xffffff7d
print(top)
print(topD)


print (0-(topD - vala+1))
print (0-(topD - test+1))



def signedNegHexTo(signedVal):
	strSigned=str(hex(signedVal))
	ba = binascii.a2b_hex(strSigned[2:])
	new = (int.from_bytes(ba, byteorder='big', signed=True))
	return new


def twos_complement(hexstr,bits):
	value = int(hexstr,16)
	if value & (1 << (bits-1)):
		value -= 1 << bits
	return value

print (twos_complement('FFFE',16))



ans=signedNegHexTo(vala)

print(hex(ans))