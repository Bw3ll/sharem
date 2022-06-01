import os
import json 

class SharemWrapper(object):
	def __init__(self):
		pass

	def read_disasm(self):
		file = open(os.path.join(os.path.dirname(__file__), "..", "logs", "default", "jsondefaultdisasm.json"), "r")
		data = json.load(file)
		file.close()
		return data
			
	def read_main(self):
		file = open(os.path.join(os.path.dirname(__file__), "..", "logs", "default", "jsondefault.json"), "r")
		data = json.load(file)
		file.close()
		return data	