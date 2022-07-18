
from sharem.sharem.DLLs.structures import MODULEENTRY32, PROCESSENTRY32, THREADENTRY32


class System_SnapShot: # Needs Reworked For new Struct System
    def __init__(self, fakeThreads: bool, fakeModules: bool):
        self.processOffset = 0
        self.threadOffset = 0
        self.moduleOffset = 0
        self.baseThreadID = 1000
        self.processDict = {4: PROCESSENTRY32(0, 10, 0, 0, 'System'),
                            2688: PROCESSENTRY32(2688, 16, 0, 4, 'explorer.exe'),
                            9172: PROCESSENTRY32(9172, 10, 2688, 10, 'calc.exe'),
                            8280: PROCESSENTRY32(8280, 50, 2688, 16, 'chrome.exe'),
                            11676: PROCESSENTRY32(11676, 78, 2688, 15, 'notepad.exe'),
                            8768: PROCESSENTRY32(8768, 20, 2688, 4, 'firefox.exe')}
        self.threadDict: dict[int, THREADENTRY32] = {}
        self.moduleList: list[MODULEENTRY32] = []
        if fakeThreads:
            self.fakeThreads()
        # if fakeModules: # Need To Fix Modules Thing
            # self.fakeModules()
        self.resetOffsets()

    def fakeThreads(self):
        for k, v in self.processDict.items():  # Create Fake Threads
            for i in range(v.cntThreads):
                self.threadDict.update(
                    {self.baseThreadID: THREADENTRY32(self.baseThreadID, v.th32ProcessID, v.pcPriClassBase)})
                self.baseThreadID += 1

    # def fakeModules(self):
    #     allDllsSizeDict = {'ntdll.dll': NTDLL_TOP - NTDLL_BASE, 'kernel32.dll': KERNEL32_TOP - KERNEL32_BASE,
    #                        'KernelBase.dll': KERNELBASE_TOP - KERNELBASE_BASE,
    #                        'advapi32.dll': ADVAPI32_TOP - ADVAPI32_BASE, 'comctl32.dll': COMCTL32_TOP - COMCTL32_BASE,
    #                        'comdlg32.dll': COMDLG32_TOP - COMDLG32_BASE, 'gdi32.dll': GDI32_TOP - GDI32_BASE,
    #                        'gdiplus.dll': GDIPLUS_TOP - GDIPLUS_BASE, 'imm32.dll': IMM32_TOP - IMM32_BASE,
    #                        'mscoree.dll': MSCOREE_TOP - MSCOREE_BASE, 'msvcrt.dll': MSVCRT_TOP - MSVCRT_BASE,
    #                        'netapi32.dll': NETAPI32_TOP - NETAPI32_BASE, 'ole32.dll': OLE32_TOP - OLE32_BASE,
    #                        'oleaut32.dll': OLEAUT32_TOP - OLEAUT32_BASE, 'shell32.dll': SHELL32_TOP - SHELL32_BASE,
    #                        'shlwapi.dll': SHLWAPI_TOP - SHLWAPI_BASE, 'urlmon.dll': URLMON_TOP - URLMON_BASE,
    #                        'user32.dll': USER32_TOP - USER32_BASE, 'wininet.dll': WININET_TOP - WININET_BASE,
    #                        'winmm.dll': WINMM_TOP - WINMM_BASE, 'ws2_32.dll': WS2_32_TOP - WS2_32_BASE,
    #                        'wsock32.dll': WSOCK32_TOP - WSOCK32_BASE, 'advpack.dll': ADVPACK_TOP - ADVPACK_BASE,
    #                        'bcrypt.dll': BCRYPT_TOP - BCRYPT_BASE, 'crypt32.dll': CRYPT32_TOP - CRYPT32_BASE,
    #                        'dnsapi.dll': DNSAPI_TOP - DNSAPI_BASE, 'mpr.dll': MPR_TOP - MPR_BASE,
    #                        'ncrypt.dll': NCRYPT_TOP - NCRYPT_BASE, 'netutils.dll': NETUTILS_TOP - NETUTILS_BASE,
    #                        'samcli.dll': SAMCLI_TOP - SAMCLI_BASE, 'secur32.dll': SECUR32_TOP - SECUR32_BASE,
    #                        'wkscli.dll': WKSCLI_TOP - WKSCLI_BASE, 'wtsapi32.dll': WTSAPI32_TOP - WTSAPI32_BASE}
    #     for k, v in self.processDict.items():
    #         moduleCount = randint(2, 16)  # Add Random Number of Modules
    #         modules = set()
    #         for i in range(moduleCount):
    #             selectedDLL = choice(list(allDllsDict))
    #             if selectedDLL not in modules:
    #                 modules.add(selectedDLL)
    #                 path = "C:\Windows\SysWOW64\\" + selectedDLL
    #                 self.moduleList.append(
    #                     MODULEENTRY32(v.th32ProcessID, allDllsDict[selectedDLL], allDllsSizeDict[selectedDLL],
    #                                          allDllsDict[selectedDLL], selectedDLL, path))

    def resetOffsets(self):
        try:
            self.processOffset = list(self.processDict.keys())[0]
            self.threadOffset = list(self.threadDict.keys())[0]
            self.moduleOffset = 0
        except:
            pass