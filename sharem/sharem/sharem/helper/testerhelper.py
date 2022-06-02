
import os

def generateTester(filename, rawSh,shellEntry):

	prevDir = '\\'.join((os.path.join(os.path.dirname(__file__))).split("\\")[:-1])
	# print(prevDir)
	templatePath = os.path.join(os.path.dirname(__file__),"tester_template.txt")

	testerPath = os.path.join(os.path.dirname(__file__), "..", "logs", filename, filename+"_tester.c")
	fp = open(templatePath, "r")
	fpData = fp.read()

	# print(fpData)
	rawSh = rawSh.replace("String Literal:", "").strip()
	newData = fpData.replace("<code>", rawSh)

	newData = newData.replace("<size>", str(len(rawSh)+1))
	newData2 = newData.replace("<offset>", str(shellEntry))

	# print(newData)
	
	fp.close()

	fp = open(testerPath, "w")
	fp.write(newData2)
	fp.close()
	# print(os.path.join(os.path.dirname(__file__), "..\\"))

