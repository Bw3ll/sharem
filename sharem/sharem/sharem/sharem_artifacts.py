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
		exe_dll_COPY = self.exe_dll_artifacts
		#convert to set
		self.path_artifacts = set(self.path_artifacts)
		self.file_artifacts = set(self.file_artifacts)
		self.commandLine_artifacts = set(self.commandLine_artifacts)
		self.web_artifacts = set(self.web_artifacts)
		self.exe_dll_artifacts = set(self.exe_dll_artifacts)
		self.registry_misc = self.registry_misc - self.registry_add_keys

		#This will need to be built out better in the future, currently we do not have any functions that edit/delete with special values we want such as desktop being passed into it.
		#self.registry_misc = self.registry_misc - self.registry_edit_keys
		#self.registry_misc = self.registry_misc - self.registry_delete_keys

		##this can be moved to a function later - removes powershell and cmd from the exe/dlls as it is picked up from the files and command line.
		#exe_dll_COPY = self.exe_dll_artifacts
		for each in exe_dll_COPY:
			if('powershell' in each.lower()):
				self.exe_dll_artifacts.discard(each)
			elif('cmd' in each.lower()):
				self.exe_dll_artifacts.discard(each)
			else:
				pass

		#convert back
		self.path_artifacts = list(self.path_artifacts)
		self.file_artifacts = list(self.file_artifacts)
		self.commandLine_artifacts = list(self.commandLine_artifacts)
		self.web_artifacts = list(self.web_artifacts)
		self.exe_dll_artifacts = list(self.exe_dll_artifacts)

	def combineRegexEmuCMDline(self):
		self.commandLine_artifacts = set(self.commandLine_artifacts)|self.commandLine_HookApis
		self.commandLine_artifacts = list(self.commandLine_artifacts)

	def regTechniquesFind(self):
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

	def hierarchyFind(self):
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

	def regexIntoMisc(self):
		self.registry_misc= self.registry_misc|set(self.registry_artifacts)

		self.registry_misc = self.registry_misc - self.registry_add_keys
		self.registry_misc = self.registry_misc - self.registry_delete_keys
		self.registry_misc = self.registry_misc - self.registry_edit_keys
		
		self.removeShortDuplicates()

	def removeShortDuplicates(self):
		#removes the short registry paths that the regex picks up if they are duplicates
		for each in self.registry_add_keys:
			if("HKEY_CLASSES_ROOT" in each):
				each = each.split("HKEY_CLASSES_ROOT\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_CURRENT_USER" in each):
				each = each.split("HKEY_CURRENT_USER\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_LOCAL_MACHINE" in each):
				each = each.split("HKEY_LOCAL_MACHINE\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_USERS" in each):
				each = each.split("HKEY_USERS\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_CURRENT_CONFIG" in each):
				each = each.split("HKEY_CURRENT_CONFIG\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass

		for each in self.registry_edit_keys:
			each = each[0]
			if("HKEY_CLASSES_ROOT" in each):
				each = each.split("HKEY_CLASSES_ROOT\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_CURRENT_USER" in each):
				each = each.split("HKEY_CURRENT_USER\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_LOCAL_MACHINE" in each):
				each = each.split("HKEY_LOCAL_MACHINE\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_USERS" in each):
				each = each.split("HKEY_USERS\\")
				print(each)
				try:
					print(1)
					self.registry_misc.discard(each[1])
					print(1)
				except:
					pass
			if("HKEY_CURRENT_CONFIG" in each):
				each = each.split("HKEY_CURRENT_CONFIG\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass

		for each in self.registry_delete_keys:
			if (type(each) == tuple):
				each = each[0]
			if("HKEY_CLASSES_ROOT" in each):
				each = each.split("HKEY_CLASSES_ROOT\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_CURRENT_USER" in each):
				each = each.split("HKEY_CURRENT_USER\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_LOCAL_MACHINE" in each):
				each = each.split("HKEY_LOCAL_MACHINE\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_USERS" in each):
				each = each.split("HKEY_USERS\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
			if("HKEY_CURRENT_CONFIG" in each):
				each = each.split("HKEY_CURRENT_CONFIG\\")
				try:
					self.registry_misc.discard(each[1])
				except:
					pass
	def exePathToCategory(self):
		for item in self.path_artifacts:
			if ("exe" in item.lower()):
				self.exe_dll_artifacts.append(item)
			elif ("dll" in item.lower()):
				self.exe_dll_artifacts.append(item)
			else:
				pass