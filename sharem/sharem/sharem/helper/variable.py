import colorama
from sharem.sharem.DLLs.emu_helpers.sharem_artifacts import Artifacts_emulation
from sharem.sharem.helper.emu import *
from sharem.sharem.singleton.helpers import Singleton


class Variables(metaclass=Singleton):
	def __init__(self):
		# Startup Modules
		self.mBool = {} #[]   # start modules CHANGED to dicitonary
		self.m = {}
		self.dictName_mBool = 'shellcode' #this is for the mBool object, was previous named 'o'
		self.shOrg = 'shellcode'
		self.shBody = 'decoded body'
		self.shStub="decoder stub"
		self.shDec="decoded shellcode (full)"
		
		
		self.bit32_argparse = False
		self.shellBit = 32
		self.rawHex = False
		self.filename = ''
		self.logged_syscalls = []
		self.emulation_multiline = True
		self.shellSizeLimit = ''
		self.bShellcodeAll = False
		
		###initilize our classes for sharem
		self.emu = EMU()
		self.art = Artifacts_emulation()
		self.emuObj = emulationOptions()
		# self.SimFileSystem = Directory_system()
		# self.txtConsolePrint = PrintingOutput()
		# self.jsonPrint = jsonPrint()
		
		#call the class inits
		# self.CreateClasses
		self.filename = ''
		self.text = '1'
		
		
		
		
##############################################################################
### Functions used everywhere, put here to clean up main code
##############################################################################

	def cleanColors(self,out):
		red,gre,yel,blu,mag,cya,whi,res,res2 = self.colors(self)
		out = out.replace(red, "")	
		out = out.replace(gre, "")	
		out = out.replace(yel, "")	
		out = out.replace(blu, "")	
		out = out.replace(mag, "")	
		out = out.replace(cya, "")	
		out = out.replace(whi, "")	
		out = out.replace(res, "")	
		return out

	def colors(self):
		red ='\u001b[31;1m'
		gre = '\u001b[32;1m'
		yel = '\u001b[33;1m'
		blu = '\u001b[34;1m'
		mag = '\u001b[35;1m'
		cya = '\u001b[36;1m'
		whi = '\u001b[37m'
		res = '\u001b[0m'
		res2 = '\u001b[0m'
		return red,gre,yel,blu,mag,cya,whi,res,res2

##############################################################################
### Initilize the classes used everywhere
##############################################################################
# def CreateClasses(self):
#     self.emu = EMU()
#These were globals, please move slowly to using this for any globals		
		# self.iatList = ''
		# self.m  = ''
		# self.mBool = ''
		# self.mL = ''
		# self.s = ''
		# self.list_of_files = ''
		# self.list_of_files32 = ''
		# self.list_of_files64 = ''
		# self.list_of_pe32 = ''
		# self.list_of_pe64 = ''
		# self.list_of_unk_files = ''
		# self.current_arch = ''
		# self.sharem_out_dir = ''
		# self.emulation_verbose = ''
		# self.labels = ''
		# self.offsets = ''
		# self.off_Label = ''
		# self.off_PossibleBad = ''
		# self.elapsed_time = ''
		# self.pebPresent = ''
		# self.doneAlready1 = ''
		# self.syscallString = ''
		# self.chMode = ''
		# self.sections = ''
		# self.numArgs = ''
		# self.peName = ''
		# self.modName = ''
		# self.PEsList = ''
		# self.PE_path = ''
		# self.PEsList_Index = ''
		# self.skipZero = ''
		# self.numPE = ''
		# self.skipPath = ''
		# self.FoundApisAddress = ''
		# self.FoundApisName = ''
		# self.saveAPI = ''
		# self.shellEntry = ''
		# self.decodedBytes = ''
		# self.maxZeroes = ''
		# self.shellEntry = ''
		# self.useDirectory = ''
		# self.VP = ''
		# self.VA = ''
		# self.MA = ''
		# self.GPA = ''
		# self.pe = ''
		# self.MemCpyAddress = ''
		# self.VPl = ''
		# self.VAl = ''
		# self.GPAl = ''
		# self.MAl = ''
		# self.Remove = ''
		# self.badChars = ''
		# self.fname = ''
		# self.entryPoint = ''
		# self.VirtualAdd = ''
		# self.ImageBase = ''
		# self.vSize = ''
		# self.startAddress = ''
		# self.endAddy = ''
		# self.gName = ''
		# self.o = ''
		# self.shOrg = ''
		# self.shBody = ''
		# self.shStub = ''
		# self.shDec = ''
		# self.t = ''
		# self.sectionName = ''
		# self.cs  = ''
		# self.cs64  = ''
		# self.directory = ''
		# self.newpath  = ''
		# self.PEtemp = ''
		# self.PE_DLL = ''
		# self.PE_DLLS  = ''
		# self.PE_DLLS2 = ''
		# self.paths = ''
		# self.DLL_Protect = ''
		# self.bit32 = ''
		# self.PE_Protect = ''
		# self.index = ''
		# self.CheckallModules = ''
		# self.present = ''
		# self.new = ''
		# self.new2 = ''
		# self.deeperLevel = ''
		# self.asciiMode = ''
		# self.stringsTemp = ''
		# self.stringsTempWide = ''
		# self.pushStringsTemp = ''
		# self.filename = ''
		# self.filename2 = ''
		# self.filenameRaw = ''
		# self.skipExtraction = ''
		# self.rawHex = ''
		# self.rawData2 = ''
		# self.useHash = ''
		# self.known_arch = ''
		# self.numArgs = ''
		# self.rawBin = ''
		# self.isPe = ''
		# self.pointsLimit = ''
		# self.maxDistance = ''
		# self.useStringsFile = ''
		# self.minStrLen = ''
		# self.mEAX = ''
		# self.mEBX = ''
		# self.mEDX = ''
		# self.mECX = ''
		# self.mEBP = ''
		# self.mESP = ''
		# self.gDisassemblyText = ''
		# self.gDisassemblyTextNoC = ''
		# self.emulation_multiline = ''
		# self.linesForward = ''
		# self.bPushRet = ''
		# self.bFstenv = ''
		# self.bSyscall = ''
		# self.bHeaven = ''
		# self.bCallPop = ''
		# self.bPrintEmulation = ''
		# self.bDisassembly  = ''
		# self.bAnaHiddenCallsDone = ''
		# self.bAnaConvertBytesDone = ''
		# self.bAnaFindStrDone = ''
		# self.deobfShell  = ''
		# self.fastMode = ''
		# self.pebPoints = ''
		# self.p2screen = ''
		# self.configOptions = ''
		# self.print_style = ''
		# self.stubFile = ''
		# self.sameFile = ''
		# self.stubEntry = ''
		# self.stubEnd = ''
		# self.shellSizeLimit = ''
		# self.conFile = ''
		# self.workDir = ''
		# self.bit32_argparse = ''
		# self.save_bin_file = ''
		# self.linesForward = ''
		# self.linesBack = ''
		# self.bytesForward = ''
		# self.bytesBack = ''
		# self.unencryptedShell = ''
		# self.decoderShell = ''
		# self.unencryptedBodyShell = ''
		# self.sample = ''
		# self.allObject = ''
		# self.gDirectory = ''
		# self.debugging = ''
		# self.shHash = ''
		# self.emuObj = ''
		# self.patt = ''
		# self.sBy = ''
		# self.sh = ''
		# self.IATs = ''
		# self.syscallRawHexOverride = ''
		# self.heavRawHexOverride = ''
		# self.fstenvRawHexOverride = ''
		# self.emuSyscallSelection = ''
		# self.GoodStrings = ''
		# self.toggList  = ''
		# self.brawHex  = ''
		# self.bstrLit = ''
		# self.bfindString = ''
		# self.bdeobfCode = ''
		# self.bdeobfCodeFound  = ''
		# self.bfindShell = ''
		# self.bfindShellFound = ''
		# self.bComments = ''
		# self.shellBit = ''
		# self.filename = ''
		# # HookAPI Emulation Values = ''
		# self.HandlesDict = ''
		# self.HeapsDict = ''
		# self.RegistryKeys = ''
		# self.commandLine_arg = ''
		# self.registry_values = ''
		# self.registry_keys = ''
		# # Sharemu values = ''
		# self.coverage_objects = ''
		# self.programCounter = ''
		# self.loggedList = ''
		# self.logged_syscalls = ''
		# self.logged_dlls = ''
		# self.paramValues = ''
		# self.network_activity = ''
		# self.jmpInstructs = ''
		# self.traversedAdds = ''
		# self.coverageAdds = ''
		# self.loadModsFromFile  = ''
		# self.cleanStackFlag = ''
		# self.stopProcess = ''
		# self.cleanBytes = ''
		# self.bad_instruct_count = ''
		
		# #for json Dissasembly
		# self.decoder = ''
		# self.caller = ''
		
		
