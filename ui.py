import sys
import re
import colorama
colorama.init()
# readRegs()
# testingAssembly()

red ='\u001b[31;1m'
gre = '\u001b[32;1m'
yel = '\u001b[33;1m'
blu = '\u001b[34;1m'
mag = '\u001b[35;1m'
cya = '\u001b[36;1m'
whi = '\u001b[37m'
res = '\u001b[0m'

def banner():
	text = '''

  ____  _   _    _    ____  _____ __  __ 
 / ___|| | | |  / \  |  _ \| ____|  \/  |
 \___ \| |_| | / _ \ | |_) |  _| | |\/| |
  ___) |  _  |/ ___ \|  _ <| |___| |  | |
 |____/|_| |_/_/   \_\_| \_\_____|_|  |_|
                                         
'''
	return text
def showOptions(shellBit):

	print(gre + banner() + res)
	optionsLabel = """
  .............
     Options
  .............
"""
	optionsLabel = yel + optionsLabel + res
	options = """
   h:		{}
   d:		{}
   D:		{}
   i:		{}
   p:		{}
   b:		{}
   q:		{}
   s:		{}
   k:		{}
   j:		{}
   m:		{}
   e:		{}
   o:		{}
   a:		{}
   c:		{}
   x:		{}
	""".format( cya +"Display options."+res, 
				cya+ "Disassembly of shellcode submenu"+res, 
				cya+ "Disassemble shellcode"+res, 
				cya+"Show PE file info."+res,
				cya+"Print menu."+res,
				cya+"Brute-force deobfuscation of shellcode." +res,
				cya+"Quick find all."+res,
				cya+"Find shellcode instructions."+res,
				cya+"Find strings."+res,
				cya+"Find shellcode strings."+res,
				cya+"Find InMemoryOrderModuleList."+res,
				cya+"Find imports."+res,
				cya+"Output bins and ASCII text."+res,
				cya+"Change architecture, 32-bit or 64-bit."+res +yel +" [ "+str(shellBit)+"-bit ]"+res,
				cya +"Save configuration."+res,
				cya+"Exit."+res
				)
	# options = "\nOptions:\n"
	# options +="h: Display options.\n"
	# options +="i: Show PE file info.\n"
	# options +="p: Print menu.\n"
	# options +="q: Quick find all.\n"
	# options +="s: Find shellcode instructions.\n"
	# options +="k: Find strings.\n"
	# options +="j: Find shellcode strings.\n"
	# options +="m: Find InMemoryOrderModuleList.\n"
	# options +="e: Find imports\n"
	# options +="o: Output bins and ASCII text.\n"
	# options +="b: Change bits.\n"
	# options +="x: Exit\n"
	print(optionsLabel, options)

def printBitMenu():
	bitMenu = "\nChange bit mode, "+yel+"32-bit "+res+ "or"+yel+ " 64-bit\n" + res
	bitMenu +="Enter 32 or 64: "
	print(bitMenu)

def displayCurrentInstructions(bPushRet, bCallPop, bFstenv, bEgg, bHeaven, bPEB, bDisass, bAll): #Display current shellcode instruction selections
	info = ''
	info = " Shellcode instructions:\n"
	info += yel +"\tpr"+res+cya+" - Push ret\t\t\t"+res+"[" 
	info += yel +"x" +res if bPushRet else " "
	info += "]\n"
	info += yel +"\tcp"+res+cya+" - Call pop / GetPC\t\t"+res+"[" 
	info += yel +"x" +res if bCallPop else " "
	info += "]\n"
	info += yel + "\tfe"+res+cya+" - Fstenv / GetPC\t\t"+res+"[" 
	info += yel +"x"+res if bFstenv else  " "
	info += "]\n"
	info += yel +"\tsy"+res+cya+" - Windows syscall\t\t"+res+"[" 
	info += yel +"x"+res if bEgg else " "
	info += "]\n"
	info += yel + "\thg"+res+cya+" - Heaven's gate\t\t"+res+"[" 
	info += yel +"x"+res if bHeaven else " "
	info += "]\n"
	info += yel +"\tpb"+res+cya+" - Walking the PEB\t\t"+res+"[" 
	info += yel +"x"+res if bPEB else " "
	info += "]\n"
	info += yel +"\tfd"+res+cya+" - Find disassembly\t\t"+res+"["
	info += yel +"x"+res if bDisass else " "
	info += "]\n"
	info += yel +"\tall"+res+cya+" - All selections\t\t"+res+"["
	info += yel +"x"+res if bAll else " "
	info += "]\n\t\t*Default\n\n"
	# info += "Toggle choices by entering input.\n"
	print(info)

def displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisass, bpAll): #Displays current print selections
	iMenu = " Selections to print:\n"
	iMenu += cya + "\tpr"+yel+" - Push ret\t\t\t[" 
	iMenu += cya + "x" + res if bpPushRet else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\tcp"+yel+" - Call pop / GetPC\t\t[" 
	iMenu += cya + "x" + res if bpCallPop else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\tfe"+yel+" - Fstenv / GetPC\t\t[" 
	iMenu += cya + "x" + res if bpFstenv else  " "
	iMenu += yel +"]\n" +res

	iMenu += cya + "\tsy"+yel+" - Windows syscall\t\t[" 
	iMenu += cya + "x" + res if bpSyscall else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\thg"+yel+" - Heaven's gate\t\t[" 
	iMenu += cya + "x" + res if bpHeaven else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\tpb"+yel+" - Walking the PEB\t\t[" 
	iMenu += cya + "x" + res if bpPEB else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\tim"+yel+" - Imports\t\t\t[" 
	iMenu += cya + "x" + res if bpEvilImports else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\tlm"+yel+" - Loaded modules\t\t[" 
	iMenu += cya + "x" + res if bpModules else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\tst"+yel+" - Strings \t\t\t["
	iMenu += cya + "x" + res if bpStrings else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\tps"+yel+" - Push Stack Strings \t["
	iMenu += cya + "x" + res if bpPushStrings else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\tfd"+yel+" - Find disassembly\t\t["
	iMenu += cya + "x" + res if bDisass else " "
	iMenu += yel +"]\n" +res
	iMenu += cya + "\tall"+yel+" - All selections\t\t["
	iMenu += cya + "x" + res if bpAll else " "

	iMenu += "]\n\t\t"+red+"*Default\n\n" + res
	print(iMenu)

#ui Discover Menu text
def instructionsMenu(bPushRet, bCallPop, bFstenv, bEgg, bHeaven, bPEB, bDisass, bAll):
	iMenu = "\n"
	iMenu += " Selections to find:\n"
	iMenu += cya +"\tpr"+res+yel+" - Push ret\t\t\t"+res+"[" 
	iMenu += cya +"x" +res if bPushRet else " "
	iMenu += "]\n"
	iMenu += cya +"\tcp"+res+yel+" - Call pop / GetPC\t\t"+res+"[" 
	iMenu += cya +"x" +res if bCallPop else " "
	iMenu += "]\n"
	iMenu += cya + "\tfe"+res+yel+" - Fstenv / GetPC\t\t"+res+"[" 
	iMenu += cya +"x"+res if bFstenv else  " "
	iMenu += "]\n"
	iMenu += cya +"\tsy"+res+yel+" - Windows syscall\t\t"+res+"[" 
	iMenu += cya +"x"+res if bEgg else " "
	iMenu += "]\n"
	iMenu += cya + "\thg"+res+yel+" - Heaven's gate\t\t"+res+"[" 
	iMenu += cya +"x"+res if bHeaven else " "
	iMenu += "]\n"
	iMenu += cya +"\tpb"+res+yel+" - Walking the PEB\t\t"+res+"[" 
	iMenu += cya +"x"+res if bPEB else " "
	iMenu += "]\n"
	iMenu += cya +"\tfd"+res+yel+" - Find disassembly\t\t"+res+"["
	iMenu += cya +"x"+res if bDisass else " "
	iMenu += "]\n"
	iMenu += cya +"\tall"+res+yel+" - All selections\t\t"+res+"["
	iMenu += cya +"x"+res if bAll else " "
	iMenu += "]\n\t\t*Default\n\n"
	iMenu += cya +"\n h"+res+yel+" - Show options.\n"
	iMenu += cya + " g"+res+yel+" - Toggle selections.\n"
	iMenu += cya + " c"+res+yel+" - Clear all selections.\n"
	iMenu += cya +" s"+res+yel+" - Change technical setttings for finding shellcode instructions.\n"
	iMenu += cya + " z"+res+yel+" - Find instructions.\n"
	iMenu += cya + " r"+res+yel+" - Reset found instructions.\n"
	iMenu += cya + " x"+res+yel+" - Exit.\n" + res
	print(iMenu)

def instructionSelectMenu():
	iSMenu = "\n\n ...................\n"
	iSMenu += " Toggle Instructions"
	iSMenu += "\n ...................\n"
	iSMenu += " Enter each instruction set code to toggle, delimitied by a space.\n"
	iSMenu +="\t e.g. cp, fe, peb, all, none\n\n"
	iSMenu +=" x to exit.\n\n"
	print(iSMenu)

def techSettingsMenu(bytesForward, bytesBack, linesForward, linesBack):
	tMenu =  "\n"
	tMenu += " Global PE settings:\n"
	tMenu += cya + "\t Max bytes to dissassemble forward:  " + yel + str(bytesForward) + res
	tMenu += "\n"
	tMenu += cya + "\t Max bytes to dissassemble backward: " + yel + str(bytesBack) + res
	tMenu += "\n\n"

	tMenu += " Global Shellcode settings:\n"

	tMenu += cya + "\t Max instructions to check forward:  " + yel + str(linesForward) + res
	tMenu += "\n"
	tMenu += cya + "\t Max instructions to check backward: " + yel + str(linesBack) + res
	tMenu += "\n\n\n"
	tMenu += "  h - Display options.\n"
	tMenu += "  g - Global settings.\n"
	tMenu += "  c - Call pop.\n"
	tMenu += "  p - Walking the PEB.\n"
	tMenu += "  k - Change minimum length of strings.\n"
	tMenu += "  \t*Used for Syscall\n"
	tMenu += "  x - Exit.\n"
	print(tMenu)

def globalTechMenu(bytesForward, bytesBack, linesForward, linesBack):
	gtMenu = "\n h - Display options.\n"
	gtMenu +=  "\n"
	# gtMenu += "Global PE settings:\n"
	gtMenu += " fb -" + cya + " Max bytes to dissassemble forward:  " + red + str(bytesForward) + res
	gtMenu += "\n"
	gtMenu += " bb -" + cya + " Max bytes to dissassemble backward: " + red + str(bytesBack) + res
	gtMenu += "\n\n"

	# gtMenu += "Global Shellcode settings:\n"

	gtMenu += " fi -" + cya + " Max instructions to check forward:  " + red + str(linesForward) + res
	gtMenu += "\n"
	gtMenu += " bi -" + cya + " Max instructions to check backward: " + red + str(linesBack) + res
	gtMenu += "\n\n"
	gtMenu += " x  - Exit.\n"


	# gtMenu += " fb - Max bytes to dissassemble forward: "
	# gtMenu += str(bytesForward)
	# gtMenu += "\n"
	# gtMenu += " bb - Max bytes to dissassemble backward: "
	# gtMenu += str(bytesBack)
	# gtMenu += "\n\n"

	# gtMenu += "Global settings for shellcode:\n"
	# gtMenu += " fi - Max instructions to check forward: "
	# gtMenu += str(linesForward)
	# gtMenu += "\n"
	# gtMenu += " bi - Max instructions to check backward: "
	# gtMenu += str(linesBack)
	# gtMenu += "\n\n"
	print(gtMenu)

def cpTechMenu(maxDistance):
	cpTMenu = "\nMax call distance: "
	cpTMenu += str(maxDistance)
	cpTMenu += "\n"
	cpTMenu += " *How far forward you can go for GetPC.\n\n"
	cpTMenu += "Enter max call distance: "
	print(cpTMenu)



def setRegValMenu():
	print("")
	print("proto")

def printMenu(bpPushRet, bpCallPop, bpFstenv, bpEgg, bpHeaven, bpPEB, bExportAll, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisass, bpAll, p2screen=None):
	

	if p2screen:
		p2screen = "x"
	else:
		p2screen = " "

	iMenu = " Selections to print:\n"
	iMenu += cya + "\tpr"+yel+" - Push ret\t\t\t["+res 
	iMenu += cya + "x" + res if bpPushRet else " "
	iMenu += yel + "]\n" + res
	iMenu += cya + "\tcp"+yel+" - Call pop / GetPC\t\t[" + res
	iMenu += cya + "x" + res if bpCallPop else " "
	iMenu += yel + "]\n" + res
	iMenu += cya + "\tfe"+yel+" - Fstenv / GetPC\t\t[" + res
	iMenu += cya + "x" + res if bpFstenv else  " "
	iMenu += yel + "]\n" + res 
	iMenu += cya + "\tsy"+yel+" - Windows syscall\t\t[" + res
	iMenu += cya + "x" + res if bpEgg else " "
	iMenu += yel + "]\n" + res
	iMenu += cya + "\thg"+yel+" - Heaven's gate\t\t[" + res
	iMenu += cya + "x" + res if bpHeaven else " "
	iMenu += yel + "]\n"+ res
	iMenu += cya + "\tpb"+yel+" - Walking the PEB\t\t[" + res
	iMenu += cya + "x" + res if bpPEB else " "
	iMenu += yel + "]\n" + res
	iMenu += cya + "\tim"+yel+" - Imports\t\t\t[" + res
	iMenu += cya + "x" + res if bpEvilImports else " "
	iMenu += yel + "]\n" + res
	iMenu += cya + "\tlm"+yel+" - Loaded modules\t\t[" + res
	iMenu += cya + "x" + res if bpModules else " "
	iMenu += yel + "]\n" + res 
	iMenu += cya + "\tst"+yel+" - Strings \t\t\t["
	iMenu += cya + "x" if bpStrings else " "
	iMenu += yel + "]\n"
	iMenu += cya + "\tps"+yel+" - Push Stack Strings \t["
	iMenu += cya + "x" if bpPushStrings else " "
	iMenu += yel + "]\n"
	iMenu += cya + "\tfd"+yel+" - Disassembly \t\t["
	iMenu += cya + "x" if bDisass else " "
	iMenu += yel + "]\n"
	iMenu += cya + "\tall"+yel+" - All selections\t\t["
	iMenu += cya + "x" if bpAll else " "
	iMenu += yel + "]\n\t\t*Default\n\n" + res
	iMenu += " {} {} \t[".format(cya + "j"+ res, yel + "- Export all to JSON." + res)
	iMenu += cya + "x" + res if bExportAll else " "
	iMenu += "]\n"
	iMenu += " {} {} \t\t[{}]\n".format(cya + "p" + res, yel + "- Print to screen" + res, cya + p2screen + res)
	iMenu += " {} {}\n".format(cya + "h" + res, yel + "- Show options." + res)
	iMenu += " {} {}\n".format(cya + "c" + res, yel + "- Clear all print selections." + res)
	iMenu += " {} {}\n".format(cya + "s" + res, yel + "- Windows syscall submenu." + res)
	iMenu += " {} {}\n".format(cya + "g" + res, yel + "- Toggle selections." + res)
	iMenu += " {} {}\n".format(cya + "z" + res, yel + "- Print selections." + res)
	iMenu += " {} {}\n".format(cya + "x" + res, yel + "- Exit." + res)
	print(iMenu)

def osFindSelectionPrint(osVersion):
	if(type(osVersion) == "<class '__main__.OSVersion'>"):
		return osVersion.toggle

	else:
		
		print("false")

def osFindSelection(osVersion):	
	#Returns [ ] if false else [x] 
	menuString = ""
	g = ""
	if(osVersion.toggle):
		menuString += "[x]"
		g = "[x]"
	else:
		menuString += "[ ]"
		g = "[ ]"
	return g

def syscallPrintSubMenu(syscallSelection, showDisassembly, syscallPrintBit, showOptions):
	vMenu = ""
	if(showOptions):
		vMenu += yel + " Selections:\n" + res
	nada = ""
	column1 = 0 		#The col1 position in syscallSelection
	column2 = 0
	col1Newline = False
	col2Newline = False
	col1Category = ''
	col2Category = ''
	t = 0
	while not ((column1 == -1) and (column2 == -1)):

	#Prints two columns recursively from our list
	#-1 indicates column is done
		if  not (column1 == -1): 

			#check for newline
			if not (syscallSelection[column1].category == col1Category):
				col1Newline = True
				col1Category = syscallSelection[column1].category


			#check if we've reached the last in a category	
			if(re.search("server", syscallSelection[column1].category, re.IGNORECASE)):
				#Look for next col1 category
				for i in range(len(syscallSelection[column1 + 1:])):
					if not (re.search("server", syscallSelection[i + column1].category, re.IGNORECASE)):
						column1 = i + column1
						col1Category = syscallSelection[column1].category
						break

					#bounds checking
					if i == len(syscallSelection[column1 + 1:])-1:
						column1 = -1

		if  not (column2 == -1):

			if not (syscallSelection[column2].category == col2Category):
				col2Newline = True
				col2Category = syscallSelection[column2].category
			#check if we've reached the last in a category
			if not (re.search("server", syscallSelection[column2].category, re.IGNORECASE)):

				#Look for next col2 category
				for i in range(len(syscallSelection[column2 + 1:])):
					if (re.search("server", syscallSelection[i + column2].category, re.IGNORECASE)):
						column2 = i + column2
						col2Category = syscallSelection[column2].category
						break

			#bounds checking
			#After it finds the end of the list, it sets the position (column2) to -1 to know it is at the end
			if column2 >= (len(syscallSelection)):
						print("Col2 end")
						column2 = -1

		#Add col1 item
		if not (column1 == -1):
			if(col1Newline):
				vMenu += (' {:<32}'.format(nada))
			else:

				#Format non categories
				if not (syscallSelection[column1].name == syscallSelection[column1].category):
					vMenu += (' {:<5s} {:<4s} {:<12s} {:<8}'.format(nada, syscallSelection[column1].code, syscallSelection[column1].name, osFindSelection(syscallSelection[column1]))) 

				#Format Categories
				else:
					vMenu += (' {:<4s} {:<17s}  {:<8}'.format(syscallSelection[column1].code , syscallSelection[column1].name, osFindSelection(syscallSelection[column1]))) 
				column1 += 1
				if column1 >= (len(syscallSelection)):
							column1 = -1
		if not (column2 == -1):
			if not col2Newline: 

				#Format non categories
				if not (syscallSelection[column2].name == syscallSelection[column2].category) and not (syscallSelection[column2].category == "server Column multiselect variables"):
					vMenu += (' {:<6s} {:<5s} {:<27s} {:<5}'.format(nada, syscallSelection[column2].code, syscallSelection[column2].name, osFindSelection(syscallSelection[column2])))

				#Format categories
				else:
					vMenu += (' {:<4s} {:<35s} {:<5}'.format(syscallSelection[column2].code, syscallSelection[column2].name, osFindSelection(syscallSelection[column2])))  
				column2 += 1
				if column2 >= (len(syscallSelection)):
							column2 = -1
		vMenu += "\n"
		col1Newline = False
		col2Newline = False
	vMenu += "\n"

	if showOptions:
		vMenu += "\n Functional Commands:\n\n"
		vMenu += " {} - Options.\n".format(cya + "h" + res)
		vMenu += " {} - Clear syscall selections.\n".format(cya + "c" + res)
		vMenu += " {} - Enter syscall selections.\n".format(cya + "g" + res)
		vMenu += " {} - Change bit mode for syscall.\t[".format(cya + "b" + res)
		vMenu += str(syscallPrintBit)
		vMenu += "]\n"
		vMenu += " {} - Display disassembly.\t[".format(cya + "d" + res)
		vMenu += "x" if showDisassembly else " "
		vMenu += "]\n"
		vMenu += " {} - Print syscalls.\n".format(cya + "z" + res)
		# vMenu += "b - Change bits 64]\n"
		vMenu += " {} - Exit.\n".format(cya + "x" + res)

	print(vMenu)

def printModulesMenu(modulesMode):
	iMenu = 'Select one of the following options:\n'
	iMenu += "\t1 - Find only DLLs in IAT"
	if(modulesMode == 1):
		iMenu += "\t\t[x]\n"
	else:
		iMenu += "\t\t[ ]\n"
	iMenu += "\t2 - Find DLLs in IAT and beyond"
	if(modulesMode == 2):
		iMenu += "\t\t[x]\n"
	else:
		iMenu += "\t\t[ ]\n"
	iMenu += "\t3 - Find DLLs in IAT, beyond, and more"
	if(modulesMode == 3):
		iMenu += "\t[x]\n"
	else:
		iMenu += "\t[ ]\n"
	iMenu += "\t\t*Default\n"
	iMenu += "\t\t**This must be selected to find InMemoryOrderModuleList.\n"
	iMenu += "\t h - Show options.\n"
	iMenu += "\t p - Print.\n"
	iMenu += "\t z - Execute.\n"
	iMenu += "\t r - Reset InMemoryOrderModuleList.\n"
	iMenu += "\t x - Exit.\n"
	print(iMenu)

def stringMenu(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s, useStringsFile, stringsEmu):
	if useStringsFile:
		strFile = "Yes"
	else:
		strFile = "No"

	if stringsEmu:
		emu = "Yes"
	else:
		emu = "No"
	iMenu = ''
	iMenu += gre + " Strings to find:\n\n" + res
	iMenu += cya + "\tas"+ yel + " - ASCII strings\t[" + res
	iMenu += cya + "x"+res if bAsciiStrings else " "
	iMenu += yel + "]\n" + res
	iMenu += cya + "\twc"+ yel + " - Wide char strings\t[" + res
	iMenu += cya + "x" +res if bWideCharStrings else " "
	iMenu += yel + "]\n" + res
	iMenu += cya + "\tps"+ yel + " - Push stack strings\t[" + res
	iMenu += cya + "x"+res if bPushStackStrings else " "
	iMenu += yel + "]\n" + res
	iMenu += cya + "\tall"+ yel + " - All strings\t[" + res
	iMenu += cya + "x" +res if bAllStrings else " "
	iMenu += yel + "]\n\n" + res
	# iMenu += "Sections:\n"
	# for sec in s:
	# 	iMenu += "\t" + sec.sectionName.decode() + "\n"
	# iMenu += "\n"
	iMenu += cya + " h"+yel + " - Show options.\n"
	iMenu += cya + " g"+yel +" - Toggle selections.\n\n"
	iMenu += gre + " Strings emulation:\n\n" + res
	iMenu += yel+"\tm - Manually set register values for emulation.\n" + res
	
	iMenu +=gre+ "\t\tNote: This is only a sanity check.\n" + res
	iMenu +=yel+ "\tn - Change name of registers text file for emulation ["+res +"{}".format(cya + strFile + res) + yel + "]\n" + res
	iMenu +=yel+ "\t\tDefault: " + res + cya + "regs.txt\n" + res
	iMenu +=yel+ "\te - Enable emulation of stack strings with use of registers ["+res +"{}".format(cya + emu + res) + yel + "]\n" + res
	iMenu +=gre+ "\t\tNote: This should not be used ordinarily.\n" + res
	iMenu +=yel+ "\ts - Check accuracy of found stack strings.\n\n" + res
	iMenu += cya + " c"+yel + " - Clear selections.\n"
	iMenu += cya + " p"+yel + " - Print found strings.\n"
	iMenu += cya + " z"+yel + " - Find strings.\n"
	iMenu += cya + " r"+yel + " - Reset found strings.\n"
	iMenu += cya + " x"+yel + " - Exit.\n"
	print(iMenu)


def disToggleMenu(toggList=None):

	if toggList != None:
		string = toggList['findString']
		deobfcode = toggList['deobfCode']
		findshell = toggList['findShell']
		comments = toggList['comments']
	else:
		string = True
		deobfcode = False
		findshell = False
		comments = True
	
	if string == True:
		strTogg = "x"
	else:
		strTogg = " "

	if deobfcode == True:
		deobfTogg = "x"
	else:
		deobfTogg = " "

	if findshell == True:
		findshellTogg = "x"
	else:
		findshellTogg = " "
	if comments == True:
		commentsTogg = "x"
	else:
		commentsTogg = " "

	text = """
  Selections:

  """
	text += "\t{}      [{}]\n".format(cya + "  s"+yel+" - Find strings in shellcode"+ res, cya + strTogg + res)
	text += "\t{}     [{}]\n".format(cya + "  d"+yel+" - Use deobfuscated shellcode"+ res, cya + deobfTogg + res)
	text += "\t{} [{}]\n".format(cya + "  p"+yel+" - Find all shellcode insructions"+ res, cya + findshellTogg+ res)
	text += "\t{} [{}]\n".format(cya + "  c"+yel+" - Enable comments in disassembly"+ res, cya + commentsTogg+ res)

	print(text)
  	# s - Find strings in shellcode      [{}]
  	# d - Use deobfuscated shellcode     [{}]
  	# p - Find all shellcode insructions [{}]
  	# c - Enable comments in disassembly [{}]

	# """.format(cya + strTogg + res, cya + deobfTogg + res, cya + findshellTogg + res, cya + commentsTogg + res)

	# print (text)
	


def disassembleUiMenu(shellEntry):
	
	menu = """
  ......................
   Disassembly Options
  ......................

   {}:		Display options.
   {}:		Modify shellcode range.
   {}:		Toggle selections.
   {}:		Output raw shellcode to Json format.
   {}:		Change entry point ({})
   {}:		Find instructions.
   {}:		Return to main menu.
 
	""".format(yel +"h"+res, yel+"m"+res, yel+"g"+res, yel+"j"+res, yel+"e"+res, cya + hex(shellEntry) + res, yel+"z"+res, yel+"x"+res)

	print (menu)
def shellcodeStringMenu(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s):
	iMenu = ''
	iMenu += "Strings to find:\n"
	iMenu += "\tas - ASCII strings\t["
	iMenu += "x" if bAsciiStrings else " "
	iMenu += "]\n"
	iMenu += "\twc - Wide char strings\t["
	iMenu += "x" if bWideCharStrings else " "
	iMenu += "]\n"
	iMenu += "\tps - Push stack strings\t["
	iMenu += "x" if bPushStackStrings else " "
	iMenu += "]\n"
	iMenu += "\tall - All strings\t["
	iMenu += "x" if bAllStrings else " "
	iMenu += "]\n\n"
	# iMenu += "Sections:\n"
	# for sec in s:
	# 	iMenu += "\t" + sec.sectionName.decode() + "\n"
	# iMenu += "\n"
	iMenu += "h - Show options.\n"
	iMenu += "g - Toggle selections.\n"
	iMenu += "c - Clear selections.\n"
	iMenu += "p - Print found strings.\n"
	iMenu += "m - Change minimum shellcode length.\n"
	iMenu += "z - Find strings.\n"
	iMenu += "r - Reset found strings.\n"
	iMenu += "x - Exit.\n"
	print(iMenu)

def showStringSelections(bAsciiStrings, bWideCharStrings, bPushStackStrings, bAllStrings, s):
	iMenu = "\nSelections changed.\n\n"
	iMenu += "Strings to find:\n"
	iMenu += "\tas - ASCII strings\t["
	iMenu += "x" if bAsciiStrings else " "
	iMenu += "]\n"
	iMenu += "\twc - Wide char strings\t["
	iMenu += "x" if bWideCharStrings else " "
	iMenu += "]\n"
	iMenu += "\tps - Push stack strings\t["
	iMenu += "x" if bPushStackStrings else " "
	iMenu += "]\n"
	iMenu += "\tall - All strings\t["
	iMenu += "x" if bAllStrings else " "
	iMenu += "]\n\n"
	print(iMenu)

def importsMenu():
	iMenu = ''
	iMenu +='h - Show options.\n'
	iMenu +='p - Print imports.\n'
	iMenu +='z - Execute.\n'
	iMenu +='r - Reset found imports.\n'
	iMenu +='x - Exit.\n'
	print(iMenu)