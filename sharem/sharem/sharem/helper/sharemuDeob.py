

class sharDeobf:
# 	o="shellcode"
# shBody="decoded body"
# shStub="decoder stub"
# shDec="decoded shellcode (full)"
	def __init__(self, rawData=None):
		# print ("init")
		print ("HELLO, I AM STARTING")
		rawFinal=[]
		
		self.rawFinal=[]
		self.rawFinalBytes=[]

		self.original=[] # original rawdata2    #0
		self.bytesInst=[]
		self.startEnd=[]

	def setRawData2(self, rawData):
		self.rawData2 = rawData

    # fRaw.addBytes(shells, address, size)

	# def addBytes(self, offset, instSize, values):
	def addBytes(self, shells, address, size):
		# print ("**")
		# print (shells)
		# print (hex(address))
		# print (size)
		# print ("start", hex(address), "end", hex(address +size-1))

		t=address
		for each in shells:
			# print (hex(t), hex(int(each)))
			self.rawFinal[t]=each
			self.startEnd[t]=(address, address+size-1, size)
			self.bytesInst[t]="INST"
			t+=1
		pass

		# print ("\n\n")
	def show(self):
		print ("size2", len(self.rawFinal))
		# input()

	def show2(self):
		print ("size2", len(self.rawFinal))
		print ("original:")
		print (self.original)
		# print (list(self.original))
		print ("rawfinal:")
		print (self.rawFinal)
		print ("startend:")
		print (self.startEnd)
		print ("bytesInst:")
		print (self.bytesInst)
		print (type(self.rawFinal))
		new = bytes(self.rawFinal)
		print (new)
		print (type(new))

			# input()
		

	def giveSize(self, rawData):
		print ("size", len(rawData))
		sizeRaw=len(rawData)
		rawFinal=[]
		for each in rawData:
			rawFinal.append(None)

		self.rawFinal=rawFinal
		self.original=list(rawData) # original rawdata2    #0
		self.bytesInst=rawFinal.copy()
		self.startEnd=rawFinal.copy()
		# print ("size", len(rawData), len(self.rawFinal))

		# input()

	def testBytesAdd(self):
		test=b"\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00\xBD\x12\x00\x00\x00\xBD\x15\x00\x00\x00\xBD\x12\x00\x00\x00\x83\xC5\x23\x83\xC5\x23\x83\xC5\x25\x81\xC5\x55\x02\x00\x00"
		self.original=list(test)
		# self.original=[189, 18, 0, None, None, 0, 0, 189, 21, 0, 0, 0, 189, 18, 0, 0, 0, 131, 197, 35, 131, 197, 35, 131, 197, 37, 129, 197, 85, 2, 0, 0, 189, 18, 0, 0, 0, 189, 21, 0, 0, 0, 189, 18, 0, 0, 0, 131, 197, 35, 131, 197, 35, 131, 197, 37, 129, 197, 85, 2, 0, 0]


	def merge(self):
		merged=self.original.copy()
		t=0
		for x in range (5):
			self.rawFinal[t]=None
			t+=1
		for each in self.original:
			try:
				if self.rawFinal != None:
					merged[t]=self.rawFinal[t]
			except:
				pass
			t+=1

		print ("merged")
		print (merged)
		print (bytes(merged))
fRaw=sharDeobf()

