from sharem.sharem.singleton.helpers import Singleton


class EMU(metaclass=Singleton):
    def __init__(self):
        self.maxCounter = 500000
        self.arch = 32
        self.debug = False
        self.breakOutOfLoops = True
        self.maxLoop = 50000  # to break out of loops
        self.entryOffset = 0
        self.codeCoverage = True
        self.beginCoverage = False
        self.timelessDebugging = False  # todo: bramwell
        # self.winVersion = "Windows 7" # "Windows 10" ## Should make these value config. 
        # self.winSP = "SP1" # "2004"
        self.winVersion = "Windows 10"
        self.winSP = "2004"
        self.timeless_debugging_stack = False


class emulationOptions(metaclass=Singleton):
    def __init__(self):
        self.verbose = False
        self.maxEmuInstr = 500000
        self.cpuArch = 32
        self.breakLoop = True
        self.timeless_debugging_stack = False
        self.numOfIter = 30000
