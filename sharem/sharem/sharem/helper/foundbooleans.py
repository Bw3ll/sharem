


class foundBooleans():
	def __init__(self, name):
		self.bAnaHiddenCallsDone=False
		self.bAnaHiddenCnt=0
		self.bAnaConvertBytesDone=False
		self.bDoFindHiddenCalls=True
		self.bDoEnableComments=True
		self.bDoShowAscii=True
		self.bDoShowOffsets=True
		self.bDoshowOpcodes=True
		self.bDoFindStrings=True
		self.bShowLabels=True
		self.ignoreDisDiscovery=False
		self.bAnaFindStrDone=False
		self.bPreSysDisDone=False
		self.disAnalysisDone=False
		self.maxOpDisplay=8
		self.btsV=3     # value/option for binary to string function. #3 is default - this is just to be used so users can change how disassembly is printed.

		self.name=name
		self.bPushRetFound = False
		self.bDisassemblyFound = False
		self.bFstenvFound = False
		self.bSyscallFound = False
		self.bHeavenFound = False
		self.bPEBFound = False
		self.bCallPopFound = False
		self.bEvilImportsFound = False
		self.bModulesFound = False
		self.bWideStringFound = False
		self.bPushStringsFound = False
		self.bAsciiStrings=False
		self.bStringsFound=False
		self.bEmulationFound=False