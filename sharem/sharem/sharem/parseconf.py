import os
import configparser
import sys
import ast
from sharem.sharem.helper.emu import *
from sharem.sharem.helper.foundbooleans import foundBooleans
from sharem.sharem.helper.variable import Variables

from .singleton import Singleton

"""
1. add a commented template file
2. the template can be restored if the user wants it
	any comments will be delted when we write to the file.


"""
# Comments Appear Above the Value
configComments = {
	"default_outdir =": "Directory for writing out the findings of SHAREM.\n#\tif left blank will default to the logs folder in the sharem directory.",
	"pushret =": "Finding common shellcode techniques\n#\tOptions:[True,False]",
	"pebpoints =": "Will match that amount of lines to the lines needed to do standard PEB walking\n#\tOPTIONS:[1-5]",
	"shellentry =": "Defines the entry location of the shellcode",
	"self.search_save_bin_file =": "Whether to save the emulated shellcode to a binary file for further analysis\n#\tOptions:[True,False]",
	"print_format_style =": "Reading format for different viewing experiences\n#\tOPTIONS:[left,right]",
	"startup_enabled =": "If set to TRUE, will run SHAREM with this current config and generate output directly.\n# Set to FALSE, allows the use of menus to do operations, along with editing this config.",
	"max_num_of_instr =": "Max number of assembly instructions to emulate.\n# Emulation time will increase with a higher value.",
	"break_infinite_loops =":"Allows the option to break out of infinite loops",
	"iterations_before_break =": "If break_infinit_loops is True, the max amount of iterations before a loop is terminated.",
	"emulation_verbose_mode =": "If this is true, will write out to emulation.log file in the SHAREM folder containing\n# the detail of every register during each assembly instruction emulation.",
	"complete_code_coverage =": "Allows for the option to turn on and off Code Coverage.\n# Code Coverage allows SHAREM to save the memory at each compare in the assembly.\n# When one branch from this compare is done emulating, SHAREM will go back and\n# load the memory at the compare and then go down the other branch and continue emulation.",
	"users =": "# These are core system values that must be set for SHAREM emulation.\n# Set the users for the computer, this can include mulitple users, like so\n#\t['Administrator', 'SHAREM_User1', 'SHAREM_User2']",
	"user_name = ": "computer main values [computer name, ip, ...]",
	"computer_name =": "Set the computer name for the emulation.",
	"computer_ip_address =": "Set a custom IPv4 address for the emulation, currently only supports IPv4 address.",
	"timezone =": "Set the timezone\n#\tOPTIONS:[UTC,{add the other options}]",
	"default_registry_value =": "Misc values that are used within emulation.\n#\tThis allows you to set a default value for our registry system.",
	"system_time_since_epoch =": "Milliseconds Since Epoch. A value of 0 equals Current Time",
	"clipboard_data =": "Set some dummy values for the clipboard data in our emulation.",
	"drive_letter =": "These settings are the main drivers for SHAREM's filesystem emulation.\n# Set the drive letter for the file system. Currently only supports one emulated filesystem.",
	"start_directory =": "This will set the current directory value for the shellcode when emulation happens.\n# Please make sure that spelling is correct, otherwise SHAREM's filesystem\n# will create the directory with the spelling you give it.",
	"temp_file_prefix =": "For any temp files the shellcode creates this will be appended to it\n# for easier view in our artifacts section on output.",
	"file_to_read_from =": "These option allows you to use any files that the shellcode would depend on to check for content and then run with.\n#\tTo set options, provide the full path to the file, ex. C:\\Users\\Administrator\\Desktop\\secrets.txt",
	"output_emulated_files =": "If the shellcode writes to a file, and you wish to see the contents as a file. The files will be outputed into the default_dir."
}


class Configuration(metaclass=Singleton):
	def __init__(self, cfgFile = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.cfg')):
		self.cfgFile = cfgFile
		self.comments = True
		
		##[CONFIG]
		self.include_comments_in_this_file = True
		
		##[SHAREM SEARCH]
		self.search_default_outdir = 'current_dir'
		self.search_pushret = True
		self.search_callpop = True
		self.search_fstenv = True
		self.search_syscall = True
		self.search_heaven = True
		self.search_peb = True
		self.search_max_num_of_zeroes = 200
		self.search_imports = True
		self.search_lmodules = True
		self.search_disassembly = True
		self.search_pebpresent = False
		self.search_bit32 = True
		self.search_print_to_screen = True
		self.search_pebpoints = 3
		self.search_max_bytes_forward = 15
		self.search_max_bytes_backward = 10
		self.search_max_lines_forward = 7
		self.search_max_lines_backward = 10
		self.search_shellentry = 0x00
		self.search_save_bin_file = True
		self.search_print_format_style = 'right'
		self.search_max_callpop_distance = 15

		##[SHAREM PATTERNS]
		self.pattern_path_pattern = 10
		self.pattern_lang_code_pattern = 10
		self.pattern_dotted_word_pattern = 10
		self.pattern_variable_pattern = 10

		##[SHAREM STRINGS]
		self.strings_push_stack_strings = True
		self.strings_ascii_strings = True
		self.strings_wide_char_strings = True
		self.strings_minimum_str_length = 7

		##[SHAREM SYSCALLS]
		self.selected_syscalls = ['s80', 'r10', 'd', 'D']

		##[SHAREM STARTUP]
		self.startup_enabled = False

		##[SHAREM DECRYPT]
		self.decrypt_fast_mode = True
		self.decrypt_find_all = True
		self.decrypt_dist_mode = False
		self.decrypt_cpu_count = 'auto'
		self.decrypt_nodes_file = 'nodes.txt'
		self.decrypt_output_file = True
		self.decrypt_dec_operation_type = ['^', '-']
		self.decrypt_file = 'shellcode.txt'
		self.decrypt_stub_file = 'stub.txt'
		self.decrypt_use_same_file = True
		self.decrypt_stub_entry_point = 0
		self.decrypt_stub_end = -1

		##[SHAREM EMULATION]
		self.emulation_max_num_of_instr = 900000
		self.emulation_timeless_debugging = False
		self.emulation_break_infinite_loops = True
		self.emulation_iterations_before_break = 5000
		self.emulation_verbose_mode = True
		self.emulation_multiline = True
		self.emulation_print_emulation_result = True
		self.emulation_fast_mode = True
		self.emulation_find_all = True
		self.emulation_dist_mode = False
		self.emulation_cpu_count = 'auto'
		self.emulation_nodes_file = 'nodes.txt'
		self.emulation_output_file = True
		self.emulation_dec_operation_type = ['^', '-']
		self.emulation_decrypt_file = 'shellcode.txt'
		self.emulation_emu_stub_file = 'stub.txt'
		self.emulation_use_same_file = True
		self.emulation_stub_entry_point = 0
		self.emulation_stub_end = -1
		self.emulation_complete_code_coverage = True
		self.emulation_windows_version = 'Windows 10'
		self.emulation_windows_release_osbuild = '2004'
		self.emulation_windows_syscall_code = 'xp1'

		##[SHAREM DISASSEMBLY]
		self.dissassembly_enable_hidden_calls = True
		self.dissassembly_enable_assembly_comments = True
		self.dissassembly_enable_assembly_ascii = True
		self.dissassembly_enable_find_strings = True
		self.dissassembly_ignore_dis_discovery = False
		self.dissassembly_max_disassembly_operands = 8
		self.dissassembly_binary_to_string = 3
		self.dissassembly_shellcode_size_limit = 120
		self.dissassembly_show_disassembly_offsets = True
		self.dissassembly_show_disassembly_opcodes = True
		self.dissassembly_show_disassembly_labels = True

		##[SHAREM EMULATION SIMULATED VALUES]
		self.simulatedValues_current_user = 'Administrator'
		self.simulatedValues_computer_name = 'Desktop-SHAREM'
		self.simulatedValues_computer_ip_address = '192.168.1.111'
		self.simulatedValues_timezone = 'UTC'
		self.simulatedValues_default_registry_value = '(SHAREM Default Value)'
		self.simulatedValues_system_time_since_epoch = 0
		self.simulatedValues_system_uptime_minutes = 300
		self.simulatedValues_clipboard_data = 'https://sharem.com/login/#'
		self.simulatedValues_users = ['Administrator']
		self.simulatedValues_drive_letter = 'C:'
		self.simulatedValues_start_directory = 'C:\\Users\\Administrator\\AppData'
		self.simulatedValues_temp_file_prefix = 'SHAREM'
		# self.simulatedValues_file_to_read_from = []
		# self.simulatedValues_output_emulated_files = True
		self.simulatedValues_download_files = False

	def readConf(self):
		conf = configparser.RawConfigParser()
		_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.cfgFile)
		conf.read(_path)
		self.config = conf
		#initialize the config
		
		
		
		# self.decryptConf(conf)
		# self.searchConf(conf)
		# self.disassemblyConf(conf)
		# self.emulationConf(conf)
		# self.emulationSimValueConf(conf)
		# self.stringsConf(conf)
		# self.syscallsConf(conf)
		# self.patternConf(conf)
		# self.startUp(conf)
		return conf
		


	def changeConf(self, *args):

		conf = configparser.RawConfigParser()
		_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.cfgFile)
		conf.read(_path)
		self.config = conf
		self.args = args[0]

		self.comments = self.config.getboolean("CONFIG","include_comments_in_this_file")

		sharem_strings = self.config.items("SHAREM STRINGS")
		sharem_search = self.config.items("SHAREM SEARCH")
		sharem_syscalls = self.config.items("SHAREM SYSCALLS")
		sharem_decoder = self.config.items("SHAREM DECRYPT")
		sharem_emulation = self.config.items("SHAREM EMULATION")
		sharem_disassembly = self.config.items("SHAREM DISASSEMBLY")
		sharem_emuSimValues = self.config.items("SHAREM EMULATION SIMULATED VALUES")

		for key, val in self.args.items():
			for x in sharem_search:
				if key in x:
					self.config["SHAREM SEARCH"][str(key)] = str(val)
			for x in sharem_strings:
				if key in x:
					self.config["SHAREM STRINGS"][str(key)] = str(val)
			for x in sharem_syscalls:
				if key in x:
					self.config["SHAREM SYSCALLS"][str(key)] = str(val)
			for x in sharem_decoder:
				if key in x:
					self.config["SHAREM DECRYPT"][str(key)] = str(val)
			for x in sharem_emulation:
				if key in x:
					self.config["SHAREM EMULATION"][str(key)] = str(val)
			for x in sharem_disassembly:
				if key in x:
					self.config["SHAREM DISASSEMBLY"][str(key)] = str(val)
			for x in sharem_emuSimValues:
				if key in x:
					self.config["SHAREM EMULATION SIMULATED VALUES"][str(key)] = str(val)
			

			# print("Key: ", key, "Val: ", val)
			# print(vars(self.config))

		# if "pushret" in self.args:
		#     self.config['SHAREM SEARCH']['pushret'] = str(self.args['pushret'])

		# save = self.save()

	def save(self):
		# print("save")
		_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.cfgFile)
		with open(_path, "w") as configfile:
			self.config.write(configfile)

		if self.comments: # Adds Comments to Config File
			configLines = open(_path).readlines()
			for k, v in configComments.items():
				for line, index in zip(configLines, range(len(configLines))):
					if k in line:
						if v[0] != '#':
							v = "# " + v + '\n'
						else:
							v = v + '\n'
						configLines.insert(index, v)
						break

			with open(_path, "w") as commentFile:
				commentFile.writelines(configLines)



##############################
#### Set Values from Config
##############################

	def decryptConf(self,conr):
		#update the prining to be put into a log file.
		red,gre,yel,blu,mag,cya,whi,res,res2 = Variables.colors(self= Variables)
		
		self.decrypt_fast_mode = conr.getboolean('SHAREM DECRYPT','fast_mode')
		self.decrypt_find_all = conr.getboolean('SHAREM DECRYPT','find_all')
		self.decrypt_dist_mode = conr.getboolean('SHAREM DECRYPT','dist_mode')
		self.decrypt_output_file = conr.getboolean('SHAREM DECRYPT','output_file')
		try:
			self.decrypt_cpu_count = int(conr['SHAREM DECRYPT']['cpu_count'])
		except:
			self.decrypt_cpu_count = "auto"
		self.decrypt_nodes_file =  conr['SHAREM DECRYPT']['nodes_file']
		if not (os.path.exists(self.decrypt_nodes_file)):
			# print(red +"\n\nConfig file Error:", yel + self.decrypt_nodes_file + res, red + "doesn't exist!" + res)
			pass
		self.decrypt_dec_operation_type = conr['SHAREM DECRYPT']['dec_operation_type']
		try:
			self.decrypt_dec_operation_type = ast.literal_eval(self.decrypt_dec_operation_type)
		except:
			print(yel + "The value of", red + self.decrypt_dec_operation_type, yel + "is not correct or malformed!!"+ res)
			sys.exit()
		self.decrypt_file =  conr['SHAREM DECRYPT']['decrypt_file']
		if not (os.path.exists(self.decrypt_file)):
			# print(red +"\n\nConfig file Error:", yel + self.decrypt_file + res, red + "doesn't exist!" + res)
			pass
		self.decrypt_stub_file =  conr['SHAREM DECRYPT']['stub_file']
		if not (os.path.exists(self.decrypt_stub_file)):
			# print(red +"\n\nConfig file Error:", yel + self.decrypt_stub_file + res, red + "doesn't exist!" + res)
			pass
		self.decrypt_use_same_file = conr.getboolean('SHAREM DECRYPT','use_same_file')
		try:
			self.decrypt_stub_entry_point = int(conr['SHAREM DECRYPT']['stub_entry_point'])
		except:
			self.decrypt_stub_entry_point = int(conr['SHAREM DECRYPT']['stub_entry_point'],16)

		try:
			self.decrypt_stub_end = int(conr['SHAREM DECRYPT']['stub_end'])
		except:
			self.decrypt_stub_end = int(conr['SHAREM DECRYPT']['stub_end'],16)
			
	def searchConf(self,conr):
		vars = Variables()
		
		self.default_outdir = conr['SHAREM SEARCH']['default_outdir']
		self.search_max_callpop_distance = int(conr['SHAREM SEARCH']['max_callpop_distance'])
		self.search_max_num_of_zeroes = int(conr['SHAREM SEARCH']['max_num_of_zeroes'])
		self.search_pushret= conr.getboolean('SHAREM SEARCH','pushret')
		self.search_callpop= conr.getboolean('SHAREM SEARCH','callpop')
		self.search_fstenv= conr.getboolean('SHAREM SEARCH','fstenv')
		self.search_syscall= conr.getboolean('SHAREM SEARCH','syscall')
		self.search_heaven= conr.getboolean('SHAREM SEARCH','heaven')
		self.search_peb= conr.getboolean('SHAREM SEARCH','peb')
		self.search_save_bin_file = conr.getboolean('SHAREM SEARCH','save_bin_file')
		self.search_disassembly= conr.getboolean('SHAREM SEARCH','disassembly')
		self.search_pebpresent = conr.getboolean('SHAREM SEARCH','pebpresent')
		
		self.search_imports = conr.getboolean('SHAREM SEARCH', 'imports')
		
		if vars.rawHex and not vars.bit32_argparse:
			self.search_bit32 = conr.getboolean('SHAREM SEARCH','bit32')

			if self.search_bit32:
				vars.shellBit = 32
			else:
				vars.shellBit = 64


		self.search_print_to_screen =  conr.getboolean('SHAREM SEARCH','print_to_screen')
		self.search_pebpoints = int(conr['SHAREM SEARCH']['pebpoints'])
		##Follow up:
		#   Why exist. If it can only go up to 4, put that in the config as a comment describing it.
		if self.search_pebpoints > 4:
			self.search_pebpoints=4
		try:
			self.search_shellentry = int(conr['SHAREM SEARCH']['shellEntry'])
		except:
			self.search_shellentry = int(conr['SHAREM SEARCH']['shellEntry'], 16)
		try:
			vars = Variables()
			vars.em.entryOffset = self.search_shellentry
		except:
			print ("Config error: emu object not initialized.")
		try:
			self.search_max_bytes_forward = int(conr['SHAREM SEARCH']['max_bytes_forward'])
		except:
			self.search_max_bytes_forward = int(conr['SHAREM SEARCH']['max_bytes_forward'],16)

		try:
			self.search_max_bytes_backward = int(conr['SHAREM SEARCH']['max_lines_backward'])
		except:
			self.search_max_bytes_backward = int(conr['SHAREM SEARCH']['max_lines_backward'],16)

		try:
			self.search_max_lines_forward = int(conr['SHAREM SEARCH']['max_lines_forward'])
		except:
			self.search_max_lines_forward = int(conr['SHAREM SEARCH']['max_lines_forward'],16)

		try:
			self.search_max_lines_backward = int(conr['SHAREM SEARCH']['max_lines_backward'])
		except:
			self.search_max_lines_backward = int(conr['SHAREM SEARCH']['max_lines_backward'],16)

		self.search_print_format_style = conr['SHAREM SEARCH']['print_format_style']           
			
	def disassemblyConf(self,conr):
		self.dissassembly_enable_hidden_calls = conr.getboolean('SHAREM DISASSEMBLY','enable_hidden_calls')
		self.dissassembly_enable_assembly_comments = conr.getboolean('SHAREM DISASSEMBLY','enable_assembly_comments')
		self.dissassembly_enable_assembly_ascii = conr.getboolean('SHAREM DISASSEMBLY','enable_assembly_ascii')
		self.dissassembly_enable_find_strings = conr.getboolean('SHAREM DISASSEMBLY','enable_find_strings')
		self.dissassembly_ignore_dis_discovery = conr.getboolean('SHAREM DISASSEMBLY','ignore_dis_discovery')
		self.dissassembly_max_disassembly_operands = int(conr['SHAREM DISASSEMBLY']['max_disassembly_operands'])
		self.dissassembly_binary_to_string = int(conr['SHAREM DISASSEMBLY']['binary_to_string'])
		self.dissassembly_shellcode_size_limit = int(conr['SHAREM DISASSEMBLY']['shellcode_size_limit'])
		self.dissassembly_show_disassembly_offsets = conr.getboolean('SHAREM DISASSEMBLY','show_disassembly_offsets')
		self.dissassembly_show_disassembly_opcodes = conr.getboolean('SHAREM DISASSEMBLY','show_disassembly_opcodes')
		self.dissassembly_show_disassembly_labels = conr.getboolean('SHAREM DISASSEMBLY','show_disassembly_labels')        

		#init shellsize
		var = Variables()
		var.shellSizeLimit = self.dissassembly_shellcode_size_limit
		
		#init the mbool Dict with values from config
		mBool = var.mBool
		o_shell = var.shOrg
		
		mBool[o_shell].bDoFindHiddenCalls = self.dissassembly_enable_hidden_calls
		mBool[o_shell].bDoEnableComments = self.dissassembly_enable_hidden_calls
		mBool[o_shell].bDoShowAscii = self.dissassembly_enable_hidden_calls
		mBool[o_shell].bDoFindStrings = self.dissassembly_enable_hidden_calls
		mBool[o_shell].ignoreDisDiscovery = self.dissassembly_enable_hidden_calls
		mBool[o_shell].maxOpDisplay = self.dissassembly_enable_hidden_calls
		mBool[o_shell].btsV = self.dissassembly_enable_hidden_calls
		mBool[o_shell].bDoShowOffsets = self.dissassembly_enable_hidden_calls
		mBool[o_shell].bDoShowOpcodes = self.dissassembly_enable_hidden_calls
		mBool[o_shell].bDoShowLabels = self.dissassembly_enable_hidden_calls
		
	def emulationConf(self,conr):

		self.emulation_print_emulation_result = conr.getboolean('SHAREM EMULATION', 'print_emulation_result')
		self.emulation_verbose_mode = conr.getboolean('SHAREM EMULATION', 'emulation_verbose_mode')
		self.emulation_multiline = conr.getboolean('SHAREM EMULATION', 'emulation_multiline')
		self.emulation_max_num_of_instr = int(conr['SHAREM EMULATION']['max_num_of_instr'])
		self.emulation_iterations_before_break = int(conr['SHAREM EMULATION']['iterations_before_break'])
		self.emulation_break_infinite_loops = conr.getboolean('SHAREM EMULATION', 'break_infinite_loops')
		self.emulation_verbose_mode = conr.getboolean('SHAREM EMULATION', 'timeless_debugging')
		self.emulation_complete_code_coverage = conr.getboolean('SHAREM EMULATION',"complete_code_coverage")

		self.emulation_windows_version = conr['SHAREM EMULATION']['windows_version']
		self.emulation_windows_release_osbuild = conr['SHAREM EMULATION']['windows_release_osbuild']
		self.emulation_windows_syscall_code = conr['SHAREM EMULATION']['emulation_windows_syscall_code']      
		
		#set the default values for the emulation object.
		emuObj = emulationOptions()
		emuObj.maxEmuInstr = self.emulation_max_num_of_instr
		emuObj.numOfInter = self.emulation_iterations_before_break
		emuObj.breakLoop = self.emulation_break_infinite_loops
		emuObj.verbose = self.emulation_timeless_debugging
		
		em = EMU()
		em.maxCounter = self.emulation_max_num_of_instr
		em.maxLoop = self.emulation_iterations_before_break
		em.breakOutOfLoops = self.emulation_break_infinite_loops
		em.codeCoverage = self.emulation_timeless_debugging
		em.winVersion = self.emulation_windows_version
		em.winSP = self.emulation_windows_release_osbuild
		
		#set misc
		var = Variables()
		var.emulation_multiline = self.emulation_multiline
		
	def emulationSimValueConf(self,conr):

		self.simulatedValues_current_user = conr['SHAREM EMULATION SIMULATED VALUES']['current_user']
		self.simulatedValues_computer_name = conr['SHAREM EMULATION SIMULATED VALUES']['computer_name']
		self.simulatedValues_temp_file_prefix = conr['SHAREM EMULATION SIMULATED VALUES']['temp_file_prefix']
		self.simulatedValues_default_registry_value = conr['SHAREM EMULATION SIMULATED VALUES']['default_registry_value']
		self.simulatedValues_computer_ip_address = conr['SHAREM EMULATION SIMULATED VALUES']['computer_ip_address']
		self.simulatedValues_timezone = conr['SHAREM EMULATION SIMULATED VALUES']['timezone']
		self.simulatedValues_system_time_since_epoch = int(conr['SHAREM EMULATION SIMULATED VALUES']['system_time_since_epoch'])
		self.simulatedValues_system_uptime_minutes = int(conr['SHAREM EMULATION SIMULATED VALUES']['system_uptime_minutes'])
		self.simulatedValues_clipboard_data = conr['SHAREM EMULATION SIMULATED VALUES']['clipboard_data']
		self.simulatedValues_users = ast.literal_eval(conr['SHAREM EMULATION SIMULATED VALUES']['users'])
		self.simulatedValues_drive_letter = conr['SHAREM EMULATION SIMULATED VALUES']['drive_letter']
		self.simulatedValues_start_directory = conr['SHAREM EMULATION SIMULATED VALUES']['start_directory']  
		self.simulatedValues_download_files = conr['SHAREM EMULATION SIMULATED VALUES']['file_download']
		
	def stringsConf(self,conr):
		# global bPushStackStrings
		# global bWideCharStrings
		# global bAsciiStrings
		# global minStrLen

		self.strings_push_stack_strings =  conr.getboolean('SHAREM STRINGS','push_stack_strings')
		self.strings_ascii_strings =  conr.getboolean('SHAREM STRINGS','ascii_strings')
		self.strings_wide_char_strings =  conr.getboolean('SHAREM STRINGS','wide_char_strings')
		self.strings_minimum_str_length = int(conr['SHAREM STRINGS']['minimum_str_length'])
			
	def syscallsConf(self,conr):

		# global syscallSelection
		
		# initSysCallSelect()

		
		# try:
		#     list_of_syscalls = ast.literal_eval(list_of_syscalls)
		#     if(type(list_of_syscalls) != list):
		#         print("Error:", list_of_syscalls, "<-- this should be a list.")

		# except:
		#     print(yel + "The value of", red + list_of_syscalls, yel + "is not correct or malformed!!"+ res)
		#     sys.exit()

		# for selected in list_of_syscalls:
		#     for osv in syscallSelection:
		#         if osv.code == selected:
		#             osv.toggle = True
		self.selected_syscalls = str(conr['SHAREM SYSCALLS']['selected_syscalls'])

	def patternConf(self,conr):
		# global patt 
		# patt.setPatterns(int(conr['SHAREM PATTERNS']['path_pattern']))
		self.pattern_path_pattern = int(conr['SHAREM PATTERNS']['path_pattern'])
		self.pattern_lang_code_pattern = int(conr['SHAREM PATTERNS']['lang_code_pattern'])
		self.pattern_dotted_word_pattern = int(conr['SHAREM PATTERNS']['dotted_word_pattern'])
		self.pattern_variable_pattern = int(conr['SHAREM PATTERNS']['variable_pattern'])
		
	def startUp(self,conr):
		self.startup_enabled = conr.getboolean('SHAREM STARTUP','startup_enabled')
		
		
		
		
		
		
		
		