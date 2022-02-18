import os
class SharemWrapper(object):
	def __init__(self):
		pass

	def read_disasm(self):
		data = open(os.path.join(os.path.dirname(__file__), "..", "logs", "default", "jsondefaultdisasm.json"), "r")
		_ = data.read()
		return _	
			
	def read_main(self):
		data = open(os.path.join(os.path.dirname(__file__), "..", "logs", "default", "jsondefault.json"), "r")
		_ = data.read()
		return _		
