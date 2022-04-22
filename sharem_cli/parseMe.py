
parseMe="""

INTERNET_FLAG_EXISTING_CONNECT 0x20000000

INTERNET_FLAG_PASSIVE 0x08000000

WININET_API_FLAG_ASYNC 0x00000001

WININET_API_FLAG_SYNC 0x00000004

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