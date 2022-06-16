class Artifacts_emulation:
    def __init__(self):
        self.path_artifacts = []
        self.file_artifacts = []
        self.commandLine_artifacts = []
        self.web_artifacts = []
        self.registry_artifacts = []
        self.exe_dll_artifacts = []
        self.commandLine_HookApis = set()
        self.registry_edit_keys = set()
        self.registry_add_keys = set()
        self.registry_delete_keys = set()
        self.registry_misc = set()
        self.registry_persistence = set()
        self.registry_credentials = set()
        self.registry_discovery = set()
        self.reg_HKCR = set()
        self.reg_HKCU = set()
        self.reg_HKLM = set()
        self.reg_HKU = set()
        self.reg_HKCC = set()

    def removeDuplicates(self):
        self.path_artifacts = set(self.path_artifacts)
        self.path_artifacts = list(self.path_artifacts)

        self.file_artifacts = set(self.file_artifacts)
        self.file_artifacts = list(self.file_artifacts)

        self.commandLine_artifacts = set(self.commandLine_artifacts)
        self.commandLine_artifacts = list(self.commandLine_artifacts)

        self.web_artifacts = set(self.web_artifacts)
        self.web_artifacts = list(self.web_artifacts)

        self.exe_dll_artifacts = set(self.exe_dll_artifacts)
        self.exe_dll_artifacts = list(self.exe_dll_artifacts)

        self.registry_misc = self.registry_misc - self.registry_add_keys
        #This will need to be built out better in the future, currently we do not have any functions that edit/delete with special values we want such as desktop being passed into it.
        #self.registry_misc = self.registry_misc - self.registry_edit_keys
        #self.registry_misc = self.registry_misc - self.registry_delete_keys
  

    def combineRegexEmuCMDline(self):
        self.commandLine_artifacts = set(self.commandLine_artifacts)|self.commandLine_HookApis
        self.commandLine_artifacts = list(self.commandLine_artifacts)

    def regTechniquesSort(self):
        persistenceShorthand = ['run','shell folder', 'userinitmprlogonscript', 'print\\monitors','installed components','currentcontrolset\\services','control panel\desktop','print\\processors\\','\\windows\\load' ]
        credsShorthand = ['\\sam', 'sam\\', 'policy\\secrets']
        systemDiscoverShorthand = ['language']

        if(len(self.registry_add_keys) > 0):
            for keyPath in self.registry_add_keys:
                for each in persistenceShorthand:
                    if( each in keyPath.lower()):
                        self.registry_persistence.add(keyPath)
                for each in credsShorthand:
                    if(each in keyPath.lower()):
                        self.registry_credentials.add(keyPath)
                for each in systemDiscoverShorthand:
                    if(each in keyPath.lower()):
                        self.registry_discovery.add(keyPath)

        if(len(self.registry_edit_keys) > 0):
            for keyPath in self.registry_edit_keys:
                keyPath = keyPath[0]
                for each in persistenceShorthand:
                    if (each in keyPath.lower()):
                       self.registry_persistence.add(keyPath)
                for each in credsShorthand:
                    if(each in keyPath.lower()):
                        self.registry_credentials.add(keyPath)
                for each in systemDiscoverShorthand:
                    if(each in keyPath.lower()):
                        self.registry_discovery.add(keyPath)

        if(len(self.registry_delete_keys) > 0):
           for keyPath in self.registry_delete_keys:
                if(type(keyPath) == tuple):
                    keyPath = keyPath[0]
                for each in persistenceShorthand:
                    if (each in keyPath.lower()):
                       self.registry_persistence.add(keyPath)
                for each in credsShorthand:
                    if(each in keyPath.lower()):
                        self.registry_credentials.add(keyPath)
                for each in systemDiscoverShorthand:
                    if(each in keyPath.lower()):
                        self.registry_discovery.add(keyPath)

    def hierarchySort(self):
        if(len(self.registry_add_keys) > 0):
            for keyPath in self.registry_add_keys:
                if("hkey_classes_root" in keyPath.lower()):
                    self.reg_HKCR.add(keyPath)
                if("hkey_current_user" in keyPath.lower()):
                    self.reg_HKCU.add(keyPath)
                if("hkey_local_machine" in keyPath.lower()):
                    self.reg_HKLM.add(keyPath)
                if("hkey_users" in keyPath.lower()):
                    self.reg_HKU.add(keyPath)
                if("hkey_current_config" in keyPath.lower()):
                    self.reg_HKCC.add(keyPath)

        if(len(self.registry_edit_keys) > 0):
            for keyPath in self.registry_edit_keys:
                keyPath = keyPath[0]
                if("hkey_classes_root" in keyPath.lower()):
                    self.reg_HKCR.add(keyPath)
                if("hkey_current_user" in keyPath.lower()):
                    self.reg_HKCU.add(keyPath)
                if("hkey_local_machine" in keyPath.lower()):
                    self.reg_HKLM.add(keyPath)
                if("hkey_users" in keyPath.lower()):
                    self.reg_HKU.add(keyPath)
                if("hkey_current_config" in keyPath.lower()):
                    self.reg_HKCC.add(keyPath)

        if(len(self.registry_delete_keys) > 0):
            for keyPath in self.registry_delete_keys:
                if(type(keyPath) == tuple):
                    keyPath = keyPath[0]
                if("hkey_classes_root" in keyPath.lower()):
                    self.reg_HKCR.add(keyPath)
                if("hkey_current_user" in keyPath.lower()):
                    self.reg_HKCU.add(keyPath)
                if("hkey_local_machine" in keyPath.lower()):
                    self.reg_HKLM.add(keyPath)
                if("hkey_users" in keyPath.lower()):
                    self.reg_HKU.add(keyPath)
                if("hkey_current_config" in keyPath.lower()):
                    self.reg_HKCC.add(keyPath)

    def RegexIntoMisc(self):
        self.registry_misc= self.registry_misc|set(self.registry_artifacts)
