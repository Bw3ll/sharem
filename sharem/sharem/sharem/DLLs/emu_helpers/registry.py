from enum import Enum
from struct import pack

from sharem.sharem.DLLs.emu_helpers.handles import Handle, HandleType, HandlesDict
from sharem.sharem.DLLs.emu_helpers.sim_values import emuSimVals
from sharem.sharem.parseconf import Configuration
from ...helper.emuHelpers import Uc

RegistryKeys: 'dict[str,RegKey]' = {} # Dictionary of All Reg Keys


class RegValueTypes(Enum):
    REG_BINARY = 3  # Binary data in any form.
    REG_DWORD = 4  # A 32-bit number.
    # REG_DWORD_LITTLE_ENDIAN = 4  # A 32-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_DWORD in the Windows header files.
    REG_DWORD_BIG_ENDIAN = 5  # A 32-bit number in big-endian format. Some UNIX systems support big-endian architectures.
    REG_EXPAND_SZ = 2  # A null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%"). It will be a Unicode or ANSI string depending on whether you use the Unicode or ANSI functions. To expand the environment variable references, use the ExpandEnvironmentStrings function.
    REG_LINK = 6  # A null-terminated Unicode string that contains the target path of a symbolic link that was created by calling the RegCreateKeyEx function with REG_OPTION_CREATE_LINK.
    REG_MULTI_SZ = 7  # A sequence of null-terminated strings, terminated by an empty string (\0). The following is an example: String1\0String2\0String3\0LastString\0\0 The first \0 terminates the first string, the second to the last \0 terminates the last string, and the final \0 terminates the sequence. Note that the final terminator must be factored into the length of the string.
    REG_NONE = 0  # No defined value type.
    REG_QWORD = 11	# A 64-bit number.
    # REG_QWORD_LITTLE_ENDIAN = 11  # A 64-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_QWORD in the Windows header files.
    REG_SZ = 1  # A null-terminated string. This will be either a Unicode or an ANSI string, depending on whether you use the Unicode or ANSI functions.

class RegKey:
    Frozen = False # Used by NtFreezeRegistry and NtThawRegistry
    PreDefinedKeys = {0x80000000: 'HKEY_CLASSES_ROOT',0x80000001: 'HKEY_CURRENT_USER',0x80000002: 'HKEY_LOCAL_MACHINE',0x80000003: 'HKEY_USERS',0x80000004: 'HKEY_PERFORMANCE_DATA',0x80000005: 'HKEY_CURRENT_CONFIG',0x80000006: 'HKEY_DYN_DATA'}
    nextHandleValue = 0x80000010 # Registry Uses Different Range of Handles
    nextRemoteHandleValues = 0x90000010 # Registry Start value for Remote Computer Handles
    securityAccessRights = {983103: 'KEY_ALL_ACCESS', 32: 'KEY_CREATE_LINK', 4: 'KEY_CREATE_SUB_KEY', 8: 'KEY_ENUMERATE_SUB_KEYS', 131097: 'KEY_READ', 16: 'KEY_NOTIFY', 1: 'KEY_QUERY_VALUE', 2: 'KEY_SET_VALUE', 512: 'KEY_WOW64_32KEY', 256: 'KEY_WOW64_64KEY', 131078: 'KEY_WRITE'}

    def __init__(self, path: str, handle=0, remote: bool = False):
        pathSplit = path.split('\\')
        parentKeyPath = '\\'.join(pathSplit[:-1]) # Get Parent Key Path
        if len(pathSplit) > 2: # Create Parent Keys of Subkey
            newPath = ''
            for i in range(len(pathSplit)-1):
                if i == 0:
                    newPath += pathSplit[i]
                else:
                    newPath += '\\' + pathSplit[i]
                if newPath not in RegistryKeys:
                    RegKey(newPath,remote=remote)
        self.name = pathSplit[-1]
        self.path = path
        self.values: dict[str,KeyValue] = {}
        self.childKeys: dict[str,RegKey] = {}
        if handle == 0:
            if not remote:
                handle = RegKey.nextHandleValue
                RegKey.nextHandleValue += 8
            else:
                handle = RegKey.nextRemoteHandleValues
                RegKey.nextRemoteHandleValues += 8
        self.handle = Handle(HandleType.HKEY, handleValue=handle, name=self.path)
        RegistryKeys.update({self.path: self})
        self.parentKey = None
        if parentKeyPath != '':
            for key, val in RegistryKeys.items():
                if key == parentKeyPath:
                    self.parentKey = val
                    val.childKeys.update({self.name: self})            

    def createPreDefinedKeys():
        # Create Default Keys
        for key, val in RegKey.PreDefinedKeys.items():
            RegKey(path=val, handle=key)

    def deleteKey(self):
        # if self.handle.value in HandlesDict: # Remove Handle
        #     HandlesDict.pop(self.handle.value)
        if self.path in RegistryKeys: # Delete Key
            # print(f'Key: {self.path} deleted')
            RegistryKeys.pop(self.path)
            if self.name in self.parentKey.childKeys:
                parent = self.parentKey.childKeys
                parent.pop(self.name)

    def setValue(self, valueType: RegValueTypes, data, valueName = '(Default)'):
        val = KeyValue(valueType, data, valueName)
        self.values.update({val.name: val})

    def getValue(self, valueName: str = '(Default)'):
        if valueName in self.values:
            return self.values[valueName]
        else: # Return Value Not Set
            conr = Configuration()
            value = KeyValue(RegValueTypes.REG_SZ,conr.simulatedValues_default_registry_value,valueName)
            return value

    def deleteValue(self, valueName: str = '(Default)'):
        if valueName in self.values:
            # print(f'Value: {self.values[valueName].name} deleted')
            return self.values.pop(valueName)

    def printInfo(self):
        print(f'Name: {self.name}')
        print(f'Path: {self.path}')
        print(f'Handle: {hex(self.handle.value)}')
        if isinstance(self.parentKey,RegKey):
            parentName = self.parentKey.name
        else:
            parentName = 'No Parent'
        print(f'Parent Key: {parentName}')
        print(f'Child Keys Count: {len(self.childKeys)}')
        if len(self.childKeys) > 0:
            for sKey, sVal in self.childKeys.items():
                print(f' >> {sKey}')
        print(f'Values Count: {len(self.values)}')
        if len(self.values) > 0:
            print ("{:<20} {:<20} {:<20}".format('Name','Type','Data'))
            for key, val in self.values.items():
                print ("{:<20} {:<20} {:<20}".format(val.name,val.type.name,val.dataAsStr))

    def printInfoAllKeys():
        print(f'Number of Registry Keys: {len(RegistryKeys)}')
        for rkey, rval in RegistryKeys.items():
            print(f'Name: {rval.name}')
            print(f'Path: {rval.path}')
            print(f'Handle: {hex(rval.handle.value)}')
            if isinstance(rval.parentKey,RegKey): 
                parentName = rval.parentKey.name
            else: 
                parentName = 'No Parent'
            print(f'Parent Key: {parentName}')
            print(f'Child Keys Count: {len(rval.childKeys)}')
            if len(rval.childKeys) > 0:
                for sKey, sVal in rval.childKeys.items():
                    print(f' >> {sKey}')
            print(f'Values Count: {len(rval.values)}')
            if len(rval.values) > 0:
                print ("{:<20} {:<20} {:<20}".format('Name','Type','Data'))
                for key, val in rval.values.items():
                    print ("{:<20} {:<20} {:<20}".format(val.name,val.type.name,val.dataAsStr))
            print('\n')
    
    def printTree():
        def printTreeRecursive(key: RegKey, level=0):
            if level == 0:
                print(key.name)
            else:
                print(('  ' * level) + '└─╴' + key.name)
            for sKey, sVal in key.childKeys.items():
                printTreeRecursive(sVal, level+1)

        print('Registry Tree')
        for key, value in RegKey.PreDefinedKeys.items():
            if value in RegistryKeys:
                rKey = RegistryKeys[value]
                printTreeRecursive(rKey)
        print('\n')
    
        
            
class KeyValue():
    def __init__(self, valueType: RegValueTypes, data, valueName: str):
        self.name = valueName
        self.type = valueType
        self.data = data
        if isinstance(data, str):
            self.dataAsStr = data
        elif isinstance(data, int):
            self.dataAsStr = hex(data)
        elif isinstance(data, bytearray):
            self.dataAsStr = data.hex()
        elif isinstance(data, list):
            self.dataAsStr = (' ').join(data)
        else:
            self.dataAsStr = str(data)

    def writeToMemory(self, uc: Uc, address: int, unicode: bool = True):
        if unicode:
            if self.type == RegValueTypes.REG_BINARY:
                uc.mem_write(address,pack(f'<{len(self.data)}s',self.data))
            elif self.type == RegValueTypes.REG_DWORD:
                uc.mem_write(address,pack(f'<I',self.data))
            elif self.type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                uc.mem_write(address,pack(f'>I',self.data))
            elif self.type == RegValueTypes.REG_QWORD:
                uc.mem_write(address,pack(f'<Q',self.data))
            elif self.type == RegValueTypes.REG_SZ:
                uc.mem_write(address,pack(f'<{(len(self.dataAsStr)*2)+2}s',self.dataAsStr.encode('utf-16')[2:]))
            elif self.type == RegValueTypes.REG_EXPAND_SZ:
                uc.mem_write(address,pack(f'<{(len(self.dataAsStr)*2)+2}s',self.dataAsStr.encode('utf-16')[2:]))
            elif self.type == RegValueTypes.REG_MULTI_SZ:
                uc.mem_write(address,pack(f'<{(len(self.dataAsStr)*2)+2}s',self.dataAsStr.encode('utf-16')[2:]))
            elif self.type == RegValueTypes.REG_LINK:
                uc.mem_write(address,pack(f'<{(len(self.dataAsStr)*2)+2}s',self.dataAsStr.encode('utf-16')[2:]))
            elif self.type == RegValueTypes.REG_NONE:
                uc.mem_write(address,pack(f'<{(len(self.dataAsStr)*2)+2}s',self.dataAsStr.encode('utf-16')[2:]))
        else: # Ascii
            if self.type == RegValueTypes.REG_BINARY:
                uc.mem_write(address,pack(f'<{len(self.data)}s',self.data))
            elif self.type == RegValueTypes.REG_DWORD:
                uc.mem_write(address,pack(f'<I',self.data))
            elif self.type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                uc.mem_write(address,pack(f'>I',self.data))
            elif self.type == RegValueTypes.REG_QWORD:
                uc.mem_write(address,pack(f'<Q',self.data))
            elif self.type == RegValueTypes.REG_SZ:
                uc.mem_write(address,pack(f'<{len(self.dataAsStr)+2}s',self.dataAsStr.encode('ascii')))
            elif self.type == RegValueTypes.REG_EXPAND_SZ:
                uc.mem_write(address,pack(f'<{len(self.dataAsStr)+2}s',self.dataAsStr.encode('ascii')))
            elif self.type == RegValueTypes.REG_MULTI_SZ:
                uc.mem_write(address,pack(f'<{len(self.dataAsStr)+2}s',self.dataAsStr.encode('ascii')))
            elif self.type == RegValueTypes.REG_LINK:
                uc.mem_write(address,pack(f'<{(len(self.dataAsStr)*2)+2}s',self.dataAsStr.encode('utf-16')[2:]))
            elif self.type == RegValueTypes.REG_NONE:
                uc.mem_write(address,pack(f'<{len(self.dataAsStr)+2}s',self.dataAsStr.encode('ascii')))

    def dataLength(self, unicode: bool = True):
        if unicode:
            if self.type == RegValueTypes.REG_BINARY:
                return len(self.data)
            elif self.type == RegValueTypes.REG_DWORD:
                return 4
            elif self.type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                return 4
            elif self.type == RegValueTypes.REG_QWORD:
                return 8
            elif self.type == RegValueTypes.REG_SZ:
                return (len(self.dataAsStr)*2)+2
            elif self.type == RegValueTypes.REG_EXPAND_SZ:
                return (len(self.dataAsStr)*2)+2
            elif self.type == RegValueTypes.REG_MULTI_SZ:
                return len(self.dataAsStr)+1
            elif self.type == RegValueTypes.REG_LINK:
                return (len(self.dataAsStr)*2)+2
            elif self.type == RegValueTypes.REG_NONE:
                return (len(self.dataAsStr)*2)+2
            else:
                return (len(self.dataAsStr)*2)+2
        else: # Ascii
            if self.type == RegValueTypes.REG_BINARY:
                return len(self.data)
            elif self.type == RegValueTypes.REG_DWORD:
                return 4
            elif self.type == RegValueTypes.REG_DWORD_BIG_ENDIAN:
                return 4
            elif self.type == RegValueTypes.REG_QWORD:
                return 8
            elif self.type == RegValueTypes.REG_SZ:
                return len(self.dataAsStr)+2
            elif self.type == RegValueTypes.REG_EXPAND_SZ:
                return len(self.dataAsStr)+2
            elif self.type == RegValueTypes.REG_MULTI_SZ:
                return len(self.dataAsStr)+1
            elif self.type == RegValueTypes.REG_LINK:
                return (len(self.dataAsStr)*2)+2
            elif self.type == RegValueTypes.REG_NONE:
                return len(self.dataAsStr)+2
            else:
                return len(self.dataAsStr)+2

# Create Default Registry Keys
RegKey.createPreDefinedKeys()