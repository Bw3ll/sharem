class EmulationSimulationValues:
    def __init__(self):
        # Values Not From Config
        self.availMem = 0x25000000
        self.lastErrorCode = 0x0
        self.nextProcessID = 10000
        self.nextThreadID = 20000
        self.processIDs: 'list[int]' = [] # Figure Out How To Track ProcessIDs
        self.threadIDs: 'list[int]' = []

        # Values From Config
        self.user_name = "administrator"
        self.computer_name = "Desktop-SHAREM"
        self.temp_file_prefix = "SHAREM"
        self.default_registry_value = "(SHAREM Default Value)"
        self.computer_ip_address = "192.168.1.111"
        self.timezone = "UTC"
        self.system_time_since_epoch = 0
        self.system_uptime_minutes = 60
        self.clipboard_data = "https://sharem.com/login/#"
        self.users = ["administrator"]
        self.drive_letter = "C:"
        self.start_directory = "C:\\users\\adminitsrator\\desktop"

    def getNextPID(self, pid: int = 0):
        if pid == 0:
            id = self.nextProcessID
            self.nextProcessID += 8
        else:
            id = pid
        self.processIDs.append(id)
        return id

    def getNextTID(self, tid: int = 0):
        if tid == 0:
            id = self.nextThreadID
            self.nextThreadID += 8
        else:
            id = tid
        self.threadIDs.append(id)
        return id


emuSimVals = EmulationSimulationValues()
