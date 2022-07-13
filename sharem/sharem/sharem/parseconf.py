import os
import configparser

from .singleton import Singleton
'''
1. add a commented template file
2. the template can be restored if the user wants it
    any comments will be delted when we write to the file.


'''

class Configuration(metaclass=Singleton):

    def __init__(self, cfgFile):
        self.cfgFile = cfgFile


    def readConf(self):
        conf = configparser.RawConfigParser()
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.cfgFile
                )
        conf.read(_path)
        self.config = conf
        return conf

    def changeConf(self, *args):

        conf = configparser.RawConfigParser()
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.cfgFile
                )
        conf.read(_path)
        self.config = conf
        self.args = args[0]

        sharem_strings = self.config.items('SHAREM STRINGS')
        sharem_search = self.config.items('SHAREM SEARCH')
        sharem_syscalls = self.config.items('SHAREM SYSCALLS')
        sharem_decoder = self.config.items('SHAREM DECRYPT')
        sharem_emulation = self.config.items('SHAREM EMULATION')
        sharem_disassembly = self.config.items('SHAREM DISASSEMBLY')

        for key, val in self.args.items():
            for x in sharem_search:
                if(key in x):
                    self.config['SHAREM SEARCH'][str(key)] = str(val)
            for x in sharem_strings:
                if(key in x):
                    self.config['SHAREM STRINGS'][str(key)] = str(val)

            for x in sharem_syscalls:
                if(key in x):
                    self.config['SHAREM SYSCALLS'][str(key)] = str(val)
            for x in sharem_decoder:
                if(key in x):

                    self.config['SHAREM DECRYPT'][str(key)] = str(val)
           
            for x in sharem_emulation:
                if(key in x):

                    self.config['SHAREM EMULATION'][str(key)] = str(val)
            for x in sharem_disassembly:
                if(key in x):

                    self.config['SHAREM DISASSEMBLY'][str(key)] = str(val)




            # print("Key: ", key, "Val: ", val)
            # print(vars(self.config))


        # if "pushret" in self.args:
        #     self.config['SHAREM SEARCH']['pushret'] = str(self.args['pushret'])
     



        #save = self.save() 
    def save(self):
        # print("save")
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), self.cfgFile
                )
        with open(_path, "w") as configfile:
            self.config.write(configfile)
