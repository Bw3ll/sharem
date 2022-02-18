
import os

def generateTester(filename, rawSh):

	prevDir = '\\'.join((os.path.join(os.path.dirname(__file__))).split("\\")[:-1])
	# print(prevDir)
	templatePath = os.path.join(prevDir,"tester_template.txt")

	testerPath = os.path.join(prevDir, "logs", filename, filename+"_tester.c")
	fp = open(templatePath, "r")
	fpData = fp.read()

	# print(fpData)
	rawSh = rawSh.replace("String Literal:", "").strip()
	newData = fpData.replace("<code>", rawSh)

	newData = newData.replace("<size>", str(len(rawSh)))
	# print(newData)
	
	fp.close()

	fp = open(testerPath, "w")
	fp.write(newData)
	fp.close()
	# print(os.path.join(os.path.dirname(__file__), "..\\"))

