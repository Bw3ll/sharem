import os
import configparser

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
    "save_bin_file =": "Whether to save the emulated shellcode to a binary file for further analysis\n#\tOptions:[True,False]",
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
    def __init__(self, cfgFile):
        self.cfgFile = cfgFile
        self.comments = True

    def readConf(self):
        conf = configparser.RawConfigParser()
        _path = os.path.join(os.path.dirname(os.path.abspath(__file__)), self.cfgFile)
        conf.read(_path)
        self.config = conf
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
