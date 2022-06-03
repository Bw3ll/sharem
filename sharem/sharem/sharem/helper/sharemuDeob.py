import traceback

import struct
def getPattern(pattern,test):
	found=None
	try:
		found=test.index(pattern)
		# print ("found1", found)
	except:
		# print ("opps - pattern not found", found)
		pass
	return found

#test

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


class sharDeobf:
# 	o="shellcode"
# shBody="decoded body"
# shStub="decoder stub"
# shDec="decoded shellcode (full)"
	def __init__(self, rawData=None):
		# print ("init")
		print ("HELLO, I AM STARTING, sharDeobf")
		try:
			print ("size sharDeobf", len(rawData))
		except:
			print ("NONE!")
		rawFinal=[]
		
		self.rawFinal=[]
		self.rawFinalBytes=[]

		self.original=[] # original rawdata2    #0
		self.bytesInst=[]
		self.startEnd=[]
		self.rawFinalAll=[]
		self.started=False
		self.merged2=[]
		self.APIs=set()
		self.originalRaw=[]

	def create(self, rawData):
		# self.original=rawData

		sizeRaw=len(rawData)
		rawFinal=[]
		for each in rawData:
			rawFinal.append(None)

		self.rawFinal=rawFinal
		self.original=list(rawData) # original rawdata2    #0
		self.originalRaw=rawData
		self.bytesInst=rawFinal.copy()
		self.rawFinalAll=rawFinal.copy()
		self.startEnd=rawFinal.copy()


	def giveSize(self, rawData):
		# print (binaryToStr(rawData))
		# print ("size", len(rawData))
		sizeRaw=len(rawData)
		rawFinal=[]
		for each in rawData:
			rawFinal.append(None)

		self.rawFinal=rawFinal
		self.original=list(rawData) # original rawdata2    #0
		self.originalRaw=rawData
		self.bytesInst=rawFinal.copy()
		self.rawFinalAll=rawFinal.copy()
		self.startEnd=rawFinal.copy()
		# print ("size", len(rawData), len(self.rawFinal))
		# print (len(self.rawFinal), len(self.original))


	def completed(self):
		self.started=True
	def status(self):
		return self.started
	def setRawData2(self, rawData):
		self.original = rawData

    # fRaw.addBytes(shells, address, size)

	# def addBytes(self, offset, instSize, values):
	def addBytes(self, shells, address, size):
		# print ("addBytes", shells, address, size)
		# print ("**")
		# print (shells)
		# print (hex(address))
		# print (size)
		# print ("start", hex(address), "end", hex(address +size-1))

		t=address
		# print("size", hex(len(self.rawFinal)))
		# print ("address: t", t, hex(t))
		
		# print ( "***typeshells", type(shells), shells, binaryToStr(shells))
		try:
			for each in shells:
				try:
					# print (hex(t), hex(int(each)))
					self.rawFinal[t]=each
					self.startEnd[t]=(address, address+size, size)
					self.bytesInst[t]="INST"
				except:

					# print ("AddBytes - opps", hex(address), size)
					pass


				t+=1
				# print ("address, address+size, size", hex(address), hex(address+size), size)
		except Exception as e:
			
			# end=""
			# for each in self.rawFinal:
			# 	try:
			# 		end +="\\x"+hex(each)
			# 	except:
			# 		end+="\\NONE"
			# print (end)

			# print ("add_error: t", t, hex(t))
			# print("Oh no!!!", e)
			print(traceback.format_exc())
			# print (len(self.rawFinal))
			# print (self.rawFinal)


			pass

		# print ("\n\n")
	def show(self):
		# print ("size2", len(self.rawFinal))
		# input()
		pass

	def show2(self):
		print ("size2", len(self.rawFinal))
		print ("original:")
		print (self.original)
		# print (list(self.original))
		print ("rawfinal:")
		print (self.rawFinal)
		
		end=""
		t=0
		for each in self.rawFinal:
			try:
				end +="\\x"+hex(each)
			except:
				end+="\\NONE"
		print (end)
		print ("rawFinalAll:")
		print (self.rawFinalAll)
		print ("final sizes", len(self.rawFinalAll), len(self.rawFinal))
		
		end=""
		t=0
		for each in self.rawFinalAll:
			try:
				end +="\\x"+hex(each)
			except:
				end+="\\NONE"
		print (end)
		print (len(self.rawFinal))
		print ("startend:")
		print (self.startEnd)
		print ("bytesInst:")
		print (self.bytesInst)
		print (type(self.rawFinal))
		try:
			new = bytes(self.rawFinal)
			print (new)
			print (type(new))
		except:
			pass
			# input()
		
	def giveEnd(self, final):
		# print ("giveEnd")
		self.rawFinalAll=final
	def giveSize(self, rawData):
		# print (binaryToStr(rawData))
		# print ("size", len(rawData))
		sizeRaw=len(rawData)
		rawFinal=[]
		for each in rawData:
			rawFinal.append(None)

		self.rawFinal=rawFinal
		self.original=list(rawData) # original rawdata2    #0
		self.originalRaw=rawData
		self.bytesInst=rawFinal.copy()
		self.rawFinalAll=rawFinal.copy()
		self.startEnd=rawFinal.copy()
		# print ("size", len(rawData), len(self.rawFinal))
		# print (len(self.rawFinal), len(self.original))

	def add(self, api, funcName):

		ansLE=struct.pack('<I',api)
		# bprint ("addM", api)
		locInMemory=0xdeadc0de
		self.APIs.add((api, ansLE, funcName,locInMemory))
		# bprint ("done")

	

	def findAPIs(self):
		# print ("findAPIs")
		newApis=set()
		# print ("#", len(self.APIs))
		for each in self.APIs:
			pattern=each[1]
			api=each[0]
			ansLE=each[1]
			funcName=each[2]
			locInMemory=each[3]

			# print ("pattern", type(pattern), binaryToStr(pattern))
			locInMemory=getPattern(pattern,self.merged2)
			newApis.add((api, ansLE, funcName,locInMemory))
			# print ("FO?UND ONE", locInMemory, hex(locInMemory), funcName)
		# print (newApis)
		self.APIs=newApis
		# print (self.APIs)
	def testBytesAdd(self):
		test=b"\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00"
		self.original=list(test)
		# self.original=[189, 18, 0, None, None, 0, 0, 189, 21, 0, 0, 0, 189, 18, 0, 0, 0, 131, 197, 35, 131, 197, 35, 131, 197, 37, 129, 197, 85, 2, 0, 0, 189, 18, 0, 0, 0, 189, 21, 0, 0, 0, 189, 18, 0, 0, 0, 131, 197, 35, 131, 197, 35, 131, 197, 37, 129, 197, 85, 2, 0, 0]


	def merge(self):
		merged=self.original.copy()
		t=0
		# for x in range (5):
		# 	self.rawFinal[t]=None
		# 	t+=1
		for each in self.original:
			try:
				if self.rawFinal[t] != None:
					merged[t]=self.rawFinal[t]
			except:
				pass
			t+=1


		print ("merged")
		print (merged)
		print("\n\n")
		print (binaryToStr(bytes(merged)))
		print("\n\n")

		print ("origina")
		print (self.original)


	def merge2(self):
		# this one takes original, the final form, and each one that was executed as instruction.
		# some code could modify code subsequently, so having code as executed as valuable.
		# in some cases with very advanced self-modifying code, it may not be possible to capture everything, but this approach lets us get as close as we can, at least in terms of capturing instructions executed.
		# For simpler self-modifying code, there likely would be no difference between merged and merged2.
		merged=self.original.copy() 
		t=0
		# for x in range (5):
		# 	self.rawFinal[t]=None
		# 	t+=1
		for each in self.original:
			try:
				if self.rawFinalAll[t] != None:
					merged[t]=self.rawFinalAll[t]
			except:
				pass
			t+=1

		t=0
		for each in merged:
			try:
				if self.rawFinal[t] != None:
					# print ("doing it!!")
					merged[t]=self.rawFinal[t]
			except:
				pass
			t+=1

		# print ("merged2")
		# print (merged)
		# print("\n\n")
		self.merged2=bytes(merged)
		# print (binaryToStr(bytes(merged)))
		# print("\n\n")

		# print ("original")
		# print (self.original)

		self.rawFinalAll
# fRaw=sharDeobf()

