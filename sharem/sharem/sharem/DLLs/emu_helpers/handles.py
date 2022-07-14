from enum import Enum, auto

HandlesDict: 'dict[int,Handle]' = {}  # Dictionary of All Handles


class HandleType(Enum):
    # Threads
    Thread = auto()
    # Process
    Process = auto()
    SetWindowsHookExA = auto()
    SetWindowsHookExW = auto()
    CreateToolhelp32Snapshot = auto()
    # Internet Handles
    HINTERNET = auto()
    InternetOpenA = auto()
    InternetOpenW = auto()
    InternetConnectA = auto()
    InternetConnectW = auto()
    InternetOpenUrlA = auto()
    InternetOpenUrlW = auto()
    HttpOpenRequestA = auto()
    HttpOpenRequestW = auto()
    FtpOpenFileA = auto()
    FtpOpenFileW = auto()
    # File Handles
    CreateFileA = auto()
    CreateFileW = auto()
    CreateFile2 = auto()
    CreateFileMappingA = auto()
    CreateFileMappingW = auto()
    CreateFileMappingNumaA = auto()
    CreateFileMappingNumaW = auto()
    SendMessageA = auto()
    # Mutex
    Mutex = auto()
    # Service Handles
    SC_HANDLE = auto()
    # PIPE
    pipeName = auto()
    ReadPipe = auto()
    WritePipe = auto()
    ReadWritePipe = auto()
    # CHAR
    charName = auto()
    # Other
    HGLOBAL = auto()
    Timer = auto()
    DuplicateToken = auto()
    # Module
    HMODULE = auto()
    # Desktop/Window
    HWND = auto()
    ClipBoard = auto()
    # Registry
    HKEY = auto()
    Transaction = auto()
    # Sockets
    Socket = auto()
    # Events
    Event = auto()


class Handle:
    nextValue = 0x88880000  # Start of Handle IDs

    def __init__(self, type: HandleType, data=None, name='', handleValue=0):
        if handleValue == 0:
            # Generate Handle Value
            handleValue = Handle.nextValue
            Handle.nextValue += 8
        self.value = handleValue
        self.type = type
        self.name = name
        self.data = data
        HandlesDict.update({self.value: self})