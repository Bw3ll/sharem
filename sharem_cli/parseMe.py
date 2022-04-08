
parseMe="""

CRYPT_VERIFYCONTEXT 0xF0000000
CRYPT_NEWKEYSET 0x00000008
CRYPT_DELETEKEYSET 0x00000010
CRYPT_MACHINE_KEYSET 0x00000020
CRYPT_SILENT 0x00000040
CRYPT_DEFAULT_CONTAINER_OPTIONAL 0x00000080

"""







# PAGE_EXECUTE 0x10

# PAGE_EXECUTE_READ 0x20
# PAGE_EXECUTE_READWRITE 0x40
# PAGE_EXECUTE_WRITECOPY 0x80
# PAGE_NOACCESS 0x01

# PAGE_READONLY 0x02
# PAGE_READWRITE 0x04
# PAGE_WRITECOPY 0x08

# PAGE_TARGETS_INVALID 0x40000000

# PAGE_TARGETS_NO_UPDATE 0x40000000

# PAGE_GUARD 0x100

# PAGE_NOCACHE 0x200
# PAGE_WRITECOMBINE 0x400



# out = out.replace(red, "")	

###replace the parseMe!!!!!


parseMe2=parseMe.replace("=","")
# print (parsMe3)
parsMe3 = parseMe2.split("\n")

lookUp={}
reverseLookUp={}
for each in parsMe3:
	try:
		each2=each.split(" ")
		valStr=each2[0]
		try:
			hexV=each2[2]
		except:

			hexV=each2[1]
		lookUp[valStr]=hexV
		reverseLookUp[int(hexV,16)]=valStr
	except:
		print ("except", each)
		pass


word_type="mem"  ### change this

print (word_type+"_LookUp =", lookUp)
print (word_type+"_ReverseLookUp =",reverseLookUp)