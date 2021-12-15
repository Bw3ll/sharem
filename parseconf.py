import os
import configparser

from helpers import Singleton


class Configuration(metaclass=Singleton):

    def __init__(self):
        pass

    def readConf(self):
        conf = configparser.RawConfigParser()
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.cfg"
                )
        conf.read(_path)
        self.config = conf
        return conf

    def changeConf(self, *args):

        conf = configparser.RawConfigParser()
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.cfg"
                )
        conf.read(_path)
        self.config = conf
        self.args = args[0]

        sharem_strings = self.config.items('SHAREM STRINGS')
        sharem_search = self.config.items('SHAREM SEARCH')
        sharem_syscalls = self.config.items('SHAREM SYSCALLS')

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


            # print("Key: ", key, "Val: ", val)
            # print(vars(self.config))


        # if "pushret" in self.args:
        #     self.config['SHAREM SEARCH']['pushret'] = str(self.args['pushret'])
     



        #save = self.save() 
    def save(self):
        # print("save")
        _path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "config.cfg"
                )
        with open(_path, "w") as configfile:
            self.config.write(configfile)
