import re

class Artifacts_regex:
	def __init__(self):
		self.total_findPath = None
		self.find_totalFiles = None
		self.find_totalFilesBeginning = None
		self.total_commandLineArguments = None
		self.total_webTraffic = None
		self.total_Registry = None
		self.find_exe_dll = None

	def initializeRegex(self):
		self.Paths()
		self.Files()
		self.CommandLineArgs()
		self.Web()
		self.Registry()
		self.ExeDLL()

	def Paths(self):
		find_environment = r"(?:(?:\%[A-Za-z86]+\%)(?:(?:\\|\\\\)(?:[^<>\"\*\/\\\|\?\n])+)+)"
		find_environment_2 = r"(?:(?:\%[A-Za-z86]+\%)(?:(?:\/)(?:[^<>\"\*\/\\\|\?\n])+)+)"
		find_letterDrives = r"(?:(?:[A-za-z]:)(?:(?:\\|\\\\)(?:[^<>\"\*\/\\\|\?\n])+)+)"
		find_letterDrives_2 = r"(?:(?:[A-za-z]:)(?:(?:\/)(?:[^<>\"\*\/\\\|\?\n])+)+)"
		find_letterDrives2 = r"(?:(?:[A-za-z]:)(?:(?:\\|\\\\)(?:[^<>\"\*\/\\\|\?\n])+)+(?:\.[^<>\"\*\/\\\|\?\n]{2,4}))"
		find_letterDrives2_2 = r"(?:(?:[A-za-z]:)(?:(?:\/)(?:[^<>\"\*\/\\\|\?\n])+)+(?:\.[^<>\"\*\/\\\|\?\n]{2,4}))"
		find_relativePaths = r"(?:(?:\.\.)(?:(?:\\|\\\\)(?:[^<>\"\*\/\\\|\?\n]+))+)"
		find_relativePaths_2 = r"(?:(?:\.\.)(?:(?:\/)(?:[^<>\"\*\/\\\|\?\n]+))+)"
		find_networkShares = r"(?:(?:\\\\)(?:[^<>\"\*\/\\\|\?\n]+)(?:(?:\\|\\\\)(?:[^<>\"\*\/\\\|\?\n]+(?:\$|\:)?))+)"
		find_networkShares_2 = r"(?:(?:\\\\)(?:[^<>\"\*\/\\\|\?\n]+)(?:(?:\/)(?:[^<>\"\*\/\\\|\?\n]+(?:\$|\:)?))+)"
		self.total_findPaths = find_letterDrives2 +"|"+find_letterDrives2_2+"|"+find_letterDrives+"|"+find_letterDrives_2+"|"+find_relativePaths+"|"+find_relativePaths_2+"|"+find_networkShares+"|"+find_networkShares_2+"|"+find_environment+"|"+find_environment_2

	def Files(self):
		find_files = r"(?:[^<>:\"\*\/\\\|\?\n]+)(?:\.[A-Za-z1743]{2,5})"
		# gives a couple false positives, but this can be improved upon slowly
		## works best when paired with other regex.
		find_zip = r"(?:[^<>:\"\*\/\\\|\?\n]+\.)(?:7z|zip|rar|tar|tar\.gz|gzip|bzip2|wim|xz)(?:\b)"
		find_genericFiles = r"(?:[^<>:\"\*\/\\\|\?\n]+\.)(?:bin|log|exe|dll|txt|ini|ico|lnk|tmp|bak|cfg|config|msi|dat|rtf|cer|sys|cab|iso|db|asp|aspx|html|htm|rdp|temp)(?:\b)"
		find_images = r"(?:[^<>:\"\*\/\\\|\?\n]+\.)(?:jpg|gid|gmp|jpeg|png|tif|gif|bmp|tiff|svg)(?:\b)"
		find_programming = r"(?:[^<>:\"\*\/\\\|\?\n]+\.)(?:cpp|java|js|php|py|bat|c|pyc|py3|pyw|jar|eps|vbs|scr|cs|ps1|ps1xml|ps2|ps2xml|psc1|psc2|r|rb|php3|vbx)(?:\b)"
		find_workRelated = r"(?:[^<>:\"\*\/\\\|\?\n]+\.)(?:xls|xlsm|xlsx|ppt|pptx|doc|docx|pdf|wpd|odt|dodp|pps|key|diff|docm|eml|email|msg|pst|pub|sldm|sldx|wbk|xll|xla|xps|dbf|accdb|accde|accdr|accdt|sql|sqlite|mdb)(?:\b)"
		find_videoAudio = r"(?:[^<>:\"\*\/\\\|\?\n]+\.)(?:mp4|mpg|mpeg|avi|mp3|wav|aac|adt|adts|aif|aifc|aiff|cda|flv|m4a)(?:\b)"
		find_misc1 = r"(?:[^<>:\"\*\/\\\|\?\n]+\.)(?:reg|inf|application|gadget|msp|hta|cpl|msc|vb|vbe|jse|ws|wsf|wsc|wsh|scf|sh|csv|vmdk|cmx|vdi|yaml|raw|msh|msh1|msh1xml|msh2|msh2xml|mshxml|mst|ops|osd|pcd|pl|plg|prf|prg|printerexport|psd1|psdm1|pssc|pyo)(?:\b)"
		find_misc2 = r"(?:[^<>:\"\*\/\\\|\?\n]+\.)(?:swf|aru|shs|pgm|pif|vba|hlp|apk|dotm|xltm|xlam|pptm|potm|ppam|ppsm|css|chm|drv|vxd|isp|its|jnlp|ksh|mad|maf|mag|mam|maq|mar|mas|mat|mau|mav|maw|mcf|mda|mde|mdt|mdw|mdz|msu)(?:\b)"
		find_misc3 = r"(?:[^<>:\"\*\/\\\|\?\n]+\.)(?:md|info|epub|tga|url|sym|a\.out|btm|lua|ade|adp|app|appcontent-ms|appref-ms|bas|cdxml|cmd|cnt|crt|csh|der|diagcab|fxp|grp|hpj|ins|settingcontent-ms|shb|theme|udl|vbp|vsmacros|vsw|webpnp|website|wsb|xbap|xnk|pyz|sct|pyzw)(?:\b)"
		self.find_totalFiles = find_genericFiles+"|"+find_images+"|"+find_programming+"|"+find_workRelated+"|"+find_videoAudio+"|"+find_misc1+"|"+find_misc2+"|"+find_misc3
		self.find_totalFilesBeginning = "^"+find_genericFiles+"|^"+find_images+"|^"+find_programming+"|^"+find_workRelated+"|^"+find_videoAudio+"|^"+find_misc1+"|^"+find_misc2+"|^"+find_misc3
		
	def CommandLineArgs(self):
		valid_cmd_characters = r"(?:[A-Za-z0-9 \/\\=\-_:!@#\$%\^&\*\(\)><\.\"'`\{\};\[\]\+,\|]+)"
		find_cmdLine = r"(?:(?:cmd(?:\.exe)?)(?:\s+(?:\/[cCkKaAuUdDxXqQ]|\/[eEfFvV]:..|\/[tT]:[0-9a-fA-F])+)+)"
		find_powershell = r"(?:powershell(?:\.exe)?)"
		find_regCMD = r"(?:reg(?:\.exe)?(?:\s+(?:add|compare|copy|delete|export|import|load|query|restore|save|unload))+)"
		find_netCMD = r"(?:net(?:\.exe)?(?:\s+(?:accounts|computer|config|continue|file|group|help|helpmsg|localgroup|name|pause|print|send|session|share|start|statistics|stop|time|use|user|view))+)"
		find_schtasksCMD = r"(?:schtasks(?:\.exe)?\s+)(?:\/(?:change|create|delete|end|query|run))"
		find_netsh = r"(?:netsh(?:\.exe)?\s+(?:abort|add|advfirewall|alias|branchcache|bridge|bye|commit|delete|dhcpclient|dnsclient|dump|exec|exit|firewall|help|http|interface|ipsec|ipsecdosprotection|lan|namespace|netio|offline|online|popd|pushd|quit|ras|rpc|set|show|trace|unalias|    wfp|winhttp|winsock))"
		cmdline_args = find_cmdLine+valid_cmd_characters
		powershell_args= find_powershell+valid_cmd_characters
		reg_args = find_regCMD+valid_cmd_characters
		net_args = find_netCMD+valid_cmd_characters
		netsh_args = find_netsh+valid_cmd_characters
		schtask_args = find_schtasksCMD+valid_cmd_characters
		self.total_commandLineArguments = cmdline_args+"|"+powershell_args+ "|"+reg_args+"|"+net_args+"|"+netsh_args+"|"+schtask_args

	def Web(self):
		valid_web_ending1 = r"(?:\\|\/|\\\\|:)(?:[^\s\'\",]+)"
		valid_web_ending2 = r"(?:\b)"
		find_website = r"(?:(?:(?:http|https):\/\/|www)(?:[^\s\'\",]+))"
		find_doubleLetterDomains = r"(?:www)?(?:[^\\\s\'\",])+\.(?:cn|bd|it|ul|cd|ch|br|ml|ga|us|pw|eu|cf|uk|ws|zw|ke|am|vn|tk|gq|pl|ca|pe|su|de|me|au|fr|be|pk|th|it|nid|tw|cc|ng|tz|lk|sa|ru)"
		find_tripleLetterDomains = r"(?:www)?(?:[^\\\s\'\",])+\.(?:xyz|top|bar|cam|sbs|org|win|arn|moe|fun|uno|mail|stream|club|vip|ren|kim|mom|pro|gdn|biz|ooo|xin|cfd|men|com|net|edu|gov|mil|org|int)"
		find_4LettersDomains = r"(?:www)?(?:[^\\\s\'\",])+\.(?:host|rest|shot|buss|cyou|surf|info|help|life|best|live|archi|acam|load|part|mobi|loan|asia|jetzt|email|space|site|date|want|casa|link|bond|store|click|work|mail)"
		find_5MoreDomains = r"(?:www)?(?:[^\\\s\'\",])+\.(?:monster|name|reset|quest|finance|cloud|kenya|accountants|support|solar|online|yokohama|ryukyu|country|download|website|racing|digital|tokyo|world)"
		find_2_valid1 = find_doubleLetterDomains + valid_web_ending1
		find_2_valid2 = find_doubleLetterDomains + valid_web_ending2
		find_3_valid1 = find_tripleLetterDomains + valid_web_ending1
		find_3_valid2 = find_tripleLetterDomains + valid_web_ending2
		find_4_valid1 = find_4LettersDomains + valid_web_ending1
		find_4_valid2 = find_4LettersDomains + valid_web_ending2
		find_5_valid1 = find_5MoreDomains + valid_web_ending1
		find_5_valid2 = find_5MoreDomains + valid_web_ending2
		find_genericTLD = r"(?:(?:[A-Za-z\.])+\.(?:[A-Za-z0-9]{2,63}))"
		find_ftp = r"(?:(?:ftp):\/\/(?:[\S]+))"
		find_ipAddress = r"(?:(?:[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3})(?:[^\s\'\",]+))"
		self.total_webTraffic = find_website+"|"+find_ftp+"|"+find_ipAddress+"|"+find_2_valid1+"|"+find_2_valid2+"|"+find_3_valid1+"|"+find_3_valid2+"|"+    find_4_valid1+"|"+find_4_valid2+"|"+find_5_valid1+"|"+find_5_valid2

	def Registry(self):
		find_HKEY = r"(?:(?:HKEY|HKLM|HKCU|HKCC|HKCR|HKU)(?:\:)?(?:[_A-z0-9])+(?:\\[^\\\n]+)+)"
		find_CurrentUser = r"(?:(?:AppEvents|Console|Control Panel|Environment|EUDC|Identities|Keyboard Layout|Network|Printers|Remote|Software|System|Uninstall|Volatile Environment)(?:\\[^\n]+)+)"
		find_LocalMachine = r"(?:(?:SOFTWARE|SYSTEM|HARDWARE|SAM|BCD00000000)(?:\\[^\n]+){+)"
		find_Users = r"(?:(?:\.DEFAULT|S[\-0-9]+(?:_Classes)?)(?:\\[^\n]+)+)"
		find_CurrentConfig = r"(?:(?:SOFTWARE|SYSTEM)(?:\\[^\n]+)+)"
		self.total_Registry = find_HKEY + "|" + find_CurrentUser + "|" + find_LocalMachine + "|" + find_Users + "|" + find_CurrentConfig

	def ExeDLL(self):
		self.find_exe_dll = r"(?:.*)(?:\.exe|\.dll)"

class Artifacts_emulation:
	def __init__(self):
		self.correlation = []

		self.path_artifacts = []
		self.path_copy = []
		self.path_move = []

		self.file_artifacts = []
		self.files_create = []
		self.files_write = []
		self.files_delete = []
		self.files_access= []
		self.files_copy = []
		self.files_move = []
		self.files_hashes = []

		self.commandLine_artifacts = []
		self.commandLine_HookApis = set()

		self.web_artifacts = []

		self.exe_dll_artifacts = []

		self.registry_artifacts = []
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
		self.files_create = set(self.files_create)
		self.files_write = set(self.files_write)
		self.files_delete = set(self.files_delete)
		self.files_access = set(self.files_access)
		self.files_copy = set(self.files_copy)
		self.files_hashes = set(self.files_hashes)
		self.path_copy = set(self.path_copy)
		self.path_move = set(self.path_move)
		self.correlation = set(self.correlation)
		#This will need to be built out better in the future, currently we do not have any functions that edit/delete with special values we want such as desktop being passed into it.
		#self.registry_misc = self.registry_misc - self.registry_edit_keys
		#self.registry_misc = self.registry_misc - self.registry_delete_keys
		#remove regex picking up file/web artifacts that are duplicates
		## EX.
		##		warpeace3498tols.pdf <-- removes this
		##		warpeace3498tols.pdf : bdb4133424ef3125be7259eea3f156d0
		self.web_artifacts = self.dupRemoveArtifacts(self.web_artifacts)
		self.file_artifacts = self.dupRemoveArtifacts(self.file_artifacts)
		##this can be moved to a function later - removes powershell and cmd from the exe/dlls as it is picked up from the files and command line.
		#exe_dll_COPY = self.exe_dll_artifacts
		for each in exe_dll_COPY:
			if('powershell' in each.lower()):
				self.exe_dll_artifacts.discard(each)
			elif('cmd' in each.lower()):
				self.exe_dll_artifacts.discard(each)
			else:
				pass

		#remove any objects like ***<sharem.sharem.DLLs.emu_helpers.handles.Handle object at 0x0327E9D0>*** that get picked up from the regex
		self.removeObjectsFromDLLS()

		#convert back
		self.correlation = list(self.correlation)
		self.path_copy = list(self.path_copy)
		self.path_move = list(self.path_move)
		self.files_hashes = list(self.files_hashes)
		self.files_copy = list(self.files_copy)
		self.files_create = list(self.files_create)
		self.files_write = list(self.files_write)
		self.files_delete = list(self.files_delete)
		self.files_access = list(self.files_access)
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

	def removeObjectsFromDLLS(self):
		dllsObject = '<sharem.sharem.DLLs.emu_helpers.'
		for each in self.exe_dll_artifacts:
			if dllsObject in each:
				self.exe_dll_artifacts.remove(each)

	def removeStructures(self,Regex):
		#go through and find structures
		pathUpdateRemove = set()
		filesUpdateRemove = set()
		exeUpdateRemove = set()
		registryUpdateRemove = set()

		for each in self.path_artifacts:
			if('\', ' in each):
				temp = each.split('\', ')
				for next in temp:
					next = next.strip('\'')
					self.path_artifacts += re.findall(Regex.total_findPaths,next,re.IGNORECASE)
					pathUpdateRemove.add(each)
	
		for each in self.file_artifacts:
			if('\', ' in each):
				temp = each.split('\', ')
				for next in temp:
					next = next.strip('\'')
					self.file_artifacts += re.findall(Regex.find_totalFiles,next,re.IGNORECASE)
					filesUpdateRemove.add(each)

		for each in self.registry_misc:
			if('\', ' in each):
				temp = each.split('\', ')
				for next in temp:
					next = next.strip('\'')
					self.registry_artifacts += re.findall(Regex.total_Registry,next,re.IGNORECASE)
					registryUpdateRemove.add(each)

		for each in self.exe_dll_artifacts:
			if('\', ' in each):
				temp = each.split('\', ')
				for next in temp:
					next = next.strip('\'')
					self.exe_dll_artifacts += re.findall(Regex.find_exe_dll,next,re.IGNORECASE)
					exeUpdateRemove.add(each)


		#update the path artifacts
		for each in pathUpdateRemove:
			self.path_artifacts.remove(each)
		for each in filesUpdateRemove:
			self.file_artifacts.remove(each)
		for each in registryUpdateRemove:
			self.registry_misc.remove(each)
		for each in exeUpdateRemove:
			self.exe_dll_artifacts.remove(each)


		self.removeDuplicates()


	def dupRemoveArtifacts(self,artifact_set):
		#remove the duplicate artifacts that are also tuples
		tempSet = set()
		for item in artifact_set:
			if(type(item) == tuple):
				tempSet.add(item[0])
			else:
				pass
		artifact_set = artifact_set - tempSet
		return artifact_set

############################################################################################
############################			Documentation			############################
############################################################################################
#