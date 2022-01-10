import sys
import re
import colorama
import itertools
from sharem import get_max_length

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


def bannerOld():
	text = '''

  ____  _   _    _    ____  _____ __  __ 
 / ___|| | | |  / \  |  _ \| ____|  \/  |
 \___ \| |_| | / _ \ | |_) |  _| | |\/| |
  ___) |  _  |/ ___ \|  _ <| |___| |  | |
 |____/|_| |_/_/   \_\_| \_\_____|_|  |_|
 

'''
	return text


def banner():
	text = '''

  ____  _   _    _    ____  _____ __  __       ("`-''-/").___..--''"`-._          
 / ___|| | | |  / \  |  _ \| ____|  \/  |       `6_ 6  )   `-.  (     ).`-.__.`)  
 \___ \| |_| | / _ \ | |_) |  _| | |\/| |       (_Y_.)'  ._   )  `._ `. ``-..-'   
  ___) |  _  |/ ___ \|  _ <| |___| |  | |     _..`--'_..-_/  /--'_.' ,'           
 |____/|_| |_/_/   \_\_| \_\_____|_|  |_|    (il),-''  (li),'  ((!.-'             
 

'''
	return text

  
   #   ("`-''-/").___..--''"`-._          
   #    `6_ 6  )   `-.  (     ).`-.__.`)  
   #    (_Y_.)'  ._   )  `._ `. ``-..-'   
   #  _..`--'_..-_/  /--'_.' ,'           
   # (il),-''  (li),'  ((!.-'             

   # Felix Lee <flee@cse.psu.edu>


def showOptions(shellBit, rawHex, name,hMd5):
	if rawHex:
		showType="shellcode"
		showType2="\n\tShellcode: "
	else:
		showType="PE file"
		showType2="\n\tPE file: "
	print(gre + banner() + res)
	print (whi+"  Shellcode Analysis & Emulation Framework, v. 1.0"+res)
	
	print (gre+showType2+ cya+name+gre +"\tMd5: "+cya+hMd5+res)
	optionsLabel = """
  .............
     Options
  .............
"""
	optionsLabel = yel + optionsLabel + res
	options = cya+"""
   h		{}
   s		{}
   d		{}
   D		{}
   ?		{}
   p		{}
   b		{}
   q		{}
   k		{}
   m		{}
   e		{}
   o		{}
   i		{}
   a		{}
   c		{}
   z		{}
   x		{}
	""".format( res +"Display options."+cya, 
				res+"Find Assembly instructions associated with shellcode."+cya,
				res+ "Disassembly of shellcode submenu"+cya, 
				res+ "Disassemble shellcode"+cya, 
				res+ "Shellcode Emulator"+cya, 
				res+"Print menu."+cya,
				res+"Brute-force deobfuscation of shellcode." +cya,
				res+"Quick find all."+cya,
				res+"Find strings."+cya,
				res+"Find modules in the IAT and beyond."+cya,
				res+"Find imports."+cya,
				res+"Output bins and ASCII text."+cya,
				res+"Show basic "+showType+" info."+cya,
				res+"Change architecture, 32-bit or 64-bit."+yel +" [ "+cya+str(shellBit)+"-bit"+yel+" ]"+cya,
				res +"Save current configuration."+cya,
				res+"Do everything with current selections."+cya,
				res+"Exit."+cya,
				)
	print(optionsLabel, options)

def printBitMenu():
	bitMenu = "\nChange bit mode, "+yel+"32-bit "+res+ "or"+red+ " 64-bit\n" + res
	bitMenu +="Enter 32 or 64: "
	print(bitMenu)

def displayCurrentInstructions(bPushRet, bCallPop, bFstenv, bEgg, bHeaven, bPEB, bDisass, bAll): #Display current shellcode instruction selections
	
	iMenu = "\n"
	iMenu += " Shellcode instructions to find:\n"
	iMenu += cya +"\tpr"+res+" -"+yel+" Push ret\t\t\t"+res+"[" 
	iMenu += cya +"x" +res if bPushRet else " "
	iMenu += "]\n"
	iMenu += cya +"\tcp"+res+" -"+yel+" Call pop / GetPC\t\t"+res+"[" 
	iMenu += cya +"x" +res if bCallPop else " "
	iMenu += "]\n"
	iMenu += cya + "\tfe"+res+" -"+yel+" Fstenv / GetPC\t\t"+res+"[" 
	iMenu += cya +"x"+res if bFstenv else  " "
	iMenu += "]\n"
	iMenu += cya +"\tsy"+res+" -"+yel+" Windows syscall\t\t"+res+"[" 
	iMenu += cya +"x"+res if bEgg else " "
	iMenu += "]\n"
	iMenu += cya + "\thg"+res+" -"+yel+" Heaven's gate\t\t"+res+"[" 
	iMenu += cya +"x"+res if bHeaven else " "
	iMenu += "]\n"
	iMenu += cya +"\tpb"+res+" -"+yel+" Walking the PEB\t\t"+res+"[" 
	iMenu += cya +"x"+res if bPEB else " "
	iMenu += "]\n"
	iMenu += cya +"\tfd"+res+" -"+yel+" Find disassembly\t\t"+res+"["
	iMenu += cya +"x"+res if bDisass else " "
	iMenu += "]\n"
	iMenu += cya +"\tall"+res+" -"+yel+" All selections\t\t"+res+"["
	iMenu += cya +"x"+res if bAll else " "
	iMenu += "]\n\t\t*Default\n\n"
	# print(iMenu)
	return iMenu

# goodone
def displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisass, bpAll): #Displays current print selections
	iMenu = " Selections to print:\n"
	iMenu += cya + "\tpr"+res+" -"+yel+" Push rets\t\t\t"+res+"[" 
	iMenu += cya + "x" + res if bpPushRet else " "
	iMenu += res +"]\n" 
	iMenu += cya + "\tcp"+res+" -"+yel+" Call pop / GetPC\t\t"+res+"[" 
	iMenu += cya + "x" + res if bpCallPop else " "
	iMenu += res +"]\n" 
	iMenu += cya + "\tfe"+res+" -"+yel+" Fstenv / GetPC\t\t"+res+"[" 
	iMenu += cya + "x" + res if bpFstenv else  " "
	iMenu += res +"]\n" 

	iMenu += cya + "\tsy"+res+" -"+yel+" Windows syscall\t\t"+res+"[" 
	iMenu += cya + "x" + res if bpSyscall else " "
	iMenu += res +"]\n" 
	iMenu += cya + "\thg"+res+" -"+yel+" Heaven's gate\t\t"+res+"[" 
	iMenu += cya + "x" + res if bpHeaven else " "
	iMenu += res +"]\n" 
	iMenu += cya + "\tpb"+res+" -"+yel+" Walking the PEB\t\t"+res+"[" 
	iMenu += cya + "x" + res if bpPEB else " "
	iMenu += res +"]\n" 
	iMenu += cya + "\tim"+res+" -"+yel+" Imports\t\t\t"+res+"[" 
	iMenu += cya + "x" + res if bpEvilImports else " "
	iMenu += res +"]\n" 
	iMenu += cya + "\tlm"+res+" -"+yel+" Loaded modules\t\t"+res+"[" 
	iMenu += cya + "x" + res if bpModules else " "
	iMenu += res +"]\n" 
	iMenu += cya + "\tst"+res+" -"+yel+" Strings \t\t\t"+res+"["
	iMenu += cya + "x" + res if bpStrings else " "
	iMenu += res +"]\n" 	
	iMenu += cya + "\tps"+res+" -"+yel+" Push Stack Strings \t"+res+"["
	iMenu += cya + "x" + res if bpPushStrings else " "
	iMenu += res +"]\n" 
	iMenu += cya + "\tfd"+res+" -"+yel+" Find disassembly\t\t"+res+"["
	iMenu += cya + "x" + res if bDisass else " "
	iMenu += res +"]\n" 
	iMenu += cya + "\tall"+res+" -"+yel+" All selections\t\t"+res+"["
	iMenu += cya + "x" + res if bpAll else " "

	iMenu += "]\n\t\t"+red+"*Default\n\n" + res
	# print(iMenu)
	return iMenu

#ui Discover Menu text
def instructionsMenu(bPushRet, bCallPop, bFstenv, bEgg, bHeaven, bPEB, bDisass, bAll):
	iMenu=displayCurrentInstructions(bPushRet, bCallPop, bFstenv, bEgg, bHeaven, bPEB, bDisass, bAll)
	iMenu += gre +"\n h"+res+whi+" - Show options.\n"
	iMenu += gre + " g"+res+whi+" - Toggle selections.\n"
	iMenu += gre + " c"+res+whi+" - Clear all selections.\n"
	iMenu += gre +" t"+res+whi+" - Change technical setttings for finding shellcode instructions.\n"
	iMenu += gre + " z"+res+whi+" - Find instructions.\n"
	iMenu += gre + " r"+res+whi+" - Reset found instructions.\n"
	iMenu += gre + " x"+res+whi+" - Exit.\n" + res
	print(iMenu)

def instructionSelectMenu():
	iSMenu = "\n\n ...................\n"
	iSMenu += " Toggle Instructions"
	iSMenu += "\n ...................\n"
	iSMenu += " Enter each instruction set code to toggle, delimitied by a space.\n"
	iSMenu +="\t e.g. cp, fe, peb, all, none\n\n"
	iSMenu +=" x to exit.\n\n"
	print(iSMenu)

def techSettingsMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex):
	tMenu =  "\n"
	if not rawHex:
		tMenu += " Global PE settings:\n"
		tMenu += cya + "\t Max bytes to dissassemble forward:  " + yel + str(bytesForward) + res
		tMenu += "\n"
		tMenu += cya + "\t Max bytes to dissassemble backward: " + yel + str(bytesBack) + res
	else:
		tMenu += " Global Shellcode settings:\n"

		tMenu += cya + "\t Max instructions to check forward:  " + yel + str(linesForward) + res
		tMenu += "\n"
		tMenu += cya + "\t Max instructions to check backward: " + yel + str(linesBack) + res
	tMenu += "\n\n\n"
	tMenu += "  "+gre+"h"+res+" - Display options.\n"
	tMenu += "  "+gre+"g"+res+" - Global settings.\n"
	tMenu += "  "+gre+"c"+res+" - Call pop / GetPC.\n"
	tMenu += "  "+gre+"p"+res+" - Walking the PEB.\n"
	tMenu += "  "+gre+"k"+res+" - Change minimum length of strings.\n"
	tMenu += "  "+gre+"x"+res+" - Exit.\n"
	print(tMenu)

def globalTechMenu(bytesForward, bytesBack, linesForward, linesBack, rawHex):
	if not rawHex:
		gtMenu =  "\nModify global PE file settings:\n"
		gtMenu += gre+"\tfb " + res + "- Max bytes to dissassemble forward:  " + yel + str(bytesForward) + res
		gtMenu += "\n"
		gtMenu += gre+"\tbb " + res + "- Max bytes to dissassemble backward: " + yel + str(bytesBack) + res
		gtMenu += "\n\n"+res

	else:
		gtMenu = "\nModify global Shellcode settings:\n"

		gtMenu += gre+"\tfi " + res + "- Max lines to check forward:  " + yel + str(linesForward) + res
		gtMenu += "\n"
		gtMenu += gre+"\tbi " + res + "- Max lines to check backward: " + yel + str(linesBack) + res
		gtMenu += "\n\n"
		gtMenu += gre+ "x"+res+"  - Exit.\n"+res


	print(gtMenu)

def cpTechMenu(maxDistance):
	cpTMenu = "\nMax call distance: "+ yel+ str(maxDistance) + res+"\n"
	cpTMenu += "\tHow far forward can you go for GetPC.\n\n"
	cpTMenu += "Enter max call distance below.\n"
	print(cpTMenu)

# def displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisass, bpAll): #Displays current print selections

def printMenu(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bExportAll, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisass, bpAll,outDir, p2screen=None):
	

	if p2screen:
		p2screen = "x"
	else:
		p2screen = " "

	iMenu=displayCurrentSelections(bpPushRet, bpCallPop, bpFstenv, bpSyscall, bpHeaven, bpPEB, bpStrings, bpEvilImports, bpModules, bpPushStrings, bDisass, bpAll)

	iMenu += " {} {} \t\t[".format(gre + "j"+ res, whi + "- Export all to JSON." + res)
	iMenu += cya + "x" + res if bExportAll else " "
	iMenu += "]\n"
	iMenu += " {} {} \t\t\t[{}]\n".format(gre + "p" + res, whi + "- Print to screen" + res, cya + p2screen + res)
	iMenu += " {} {} \t\t{}\n".format(gre + "d" + res, whi + "- Change output directory" + res, cya + outDir + res)
	iMenu += " {} {}\n".format(gre + "h" + res, whi + "- Show options." + res)
	iMenu += " {} {}\n".format(gre + "c" + res, whi + "- Clear all print selections." + res)
	iMenu += " {} {}\n".format(gre + "s" + res, whi + "- Windows syscall submenu." + res)
	iMenu += " {} {}\n".format(gre + "g" + res, whi + "- Toggle selections." + res)
	iMenu += " {} {}\n".format(gre + "z" + res, whi + "- Print selections." + res)
	iMenu += " {} {}\n".format(gre + "x" + res, whi + "- Exit." + res)
	print(iMenu)

# def osFindSelectionPrint(osVersion):
# 	if(type(osVersion) == "<class '__main__.OSVersion'>"):
# 		return osVersion.toggle

# 	else:
		
# 		print("false")

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

def newSysCallPrint(syscallSelection):
	
	codes = ['xp', 'v', 'w7', 'w8', 'w10', 's3', 's8', 's12', 'all']

	all_selections = []
	list_of_strings1 = []
	list_of_strings2 = []

	for ver in syscallSelection:
		all_selections.append(ver)

	column1 = []
	column2 = []

	for i in all_selections:
		if i.code == "w10":
			index = all_selections.index(i)

	column1 = all_selections[:index-1]
	column2 = all_selections[index:]

	for i in column1:
		list_of_strings1.append(i.code + "  " + i.name )

	for i in column2:
		list_of_strings2.append(i.code + "  " + i.name )

	for both in itertools.zip_longest(column1, column2):
		col1 = both[0]
		col2 = both[1]
		if col1 != None:
			code1 = col1.code
			toggle1 = col1.toggle
			if toggle1:
				toggle1 = "x"
			else:
				toggle1 = " "
			cat1 = col1.category
			name1 = col1.name
		if col2 != None:
			code2 = col2.code
			toggle2 = col2.toggle
			if toggle2:
				toggle2 = "x"
			else:
				toggle2 = " "
			cat2 = col2.category
			name2 = col2.name

		maxLen1 = get_max_length(list_of_strings1)
		maxLen2 = get_max_length(list_of_strings2)
		L1Len = len(code1 + " " + name1)
		L2Len = len(code2 + "  "+ name2)
		if col1 != None and col2 != None:
			
			if code1 in codes and code2 in codes:
				print(" {}  {}{:>{x}}[{}]\t{}  {}{:>{y}}[{}]".format(gre+code1+res, cya + name1 + res, "",red + toggle1+res, gre + code2+res, cya + name2 + res, "",red + toggle2+res, x=(maxLen1-L1Len+8), y=(maxLen2-L2Len+10)))
			else:
				print("\t{}  {} {:>{x}}[{}]\t\t{}  {}{:>{y}}[{}]".format(yel + code1 + res, name1, "",red + toggle1+res, yel + code2 + res, name2, "",red + toggle2+res, x=(maxLen1-L1Len), y=(maxLen2-L2Len+2)))
		elif col2 == None:

			if code1 in codes:
				print(" {}  {}{:>{x}}[{}]".format(gre + code1 + res, cya + name1 + res, "", red + toggle1+res, x=(maxLen1-L1Len+8)))
			else:
				print("\t{}  {} {:>{x}}[{}]".format(yel + code1 +res, name1, "",red + toggle1+res, x=(maxLen1-L1Len)))
		elif col1 == None:
			if code2 in codes:
				print(" {}  {}{:>{x}}[ ]".format(code2, name2))
			else:
				print("\t{}  {} {:>{x}}[ ]".format(code2, name2))
	# print("+------------------------+")
	# codes = ['xp', 'v', 'w7', 'w8', 'w10', 's3', 's8', 's12', 'all']
	# maxLen1 = get_max_length(list_of_strings1)
	# maxLen2 = get_max_length(list_of_strings2)

	# for both in itertools.zip_longest(column1, column2):

	# 	col1 = both[0]
	# 	col2 = both[1]
	# 	if col1 != None:
	# 		code1 = col1.code
	# 		toggle1 = col1.toggle
	# 		cat1 = col1.category
	# 		name1 = col1.name
	# 	if col2 != None:
	# 		code2 = col2.code
	# 		toggle2 = col2.toggle
	# 		cat2 = col2.category
	# 		name2 = col2.name
	# 	if col1 != None and col2 != None:
	# 		if code1 in codes or code2 in codes:
	# 			curLen1 = len(code1 + cat1)
	# 			curLen2 = len(code2 + cat2)
	# 			curNameLen1 = len(code1 + "  " + name1)
	# 			curNameLen2 = len(code2 + "  " + name2)
	# 			curNameLen2 = curNameLen2 +  curNameLen1

	# 			print(" {}  {} {:>{x}}[]   {}  {} {:>{y}}[]".format(code1, cat1, "", code2, cat2, "", x=(maxLen1-curLen1), y=(maxLen2-curLen2)))
	# 		else:
	# 			print("\t{}  {} {:>{x}}[]\t\t{}  {} {:>{y}}[]".format(code1, name1, "", code2, name2, "", x=(maxLen1-curNameLen1), y=(maxLen2-curNameLen2)))

	# 	elif col2 == None:
	# 		if code1 in codes:
	# 			print("{}  {} []".format(code1, cat1))
	# 		else:
	# 			print("{}  {} []".format(code1, name1))



def syscallPrintSubMenu(syscallSelection, showDisassembly, syscallPrintBit, showOptions):
	vMenu = ""

	#Used for list of OSVersions to print for syscall
	# def _init_(self, name, category, toggle, code):
	# 	self.name = name 			#Version, e.g. SP1
	# 	self.category = category 	#OS, e.g. Windows 10
	# 	self.toggle = toggle 		#To print or not
	# 	self.code = code 			#The opcode, e.g. xp1

	#  xp   Windows XP         [ ]      s3   Windows Server 2003                 [ ]
 #       xp1  SP1          [ ]             s30   SP0                         [ ]
 #       xp2  SP2          [ ]             s32   SP2                         [ ]
 #                                         s3r   R2                          [ ]
 # v    Windows Vista      [ ]             s3r2  R2 SP2                      [ ]
	

		# print(x.category, x.name, x.toggle, x.code)
	if(showOptions):
		print(mag + " \n Selections:\n" + res)
		newSysCallPrint(syscallSelection)

	# 	vMenu += mag + " Selections:\n" + res
	# nada = ""
	# column1 = 0 		#The col1 position in syscallSelection
	# column2 = 0
	# col1Newline = False
	# col2Newline = False
	# col1Category = ''
	# col2Category = ''
	# t = 0
	# while not ((column1 == -1) and (column2 == -1)):

	# #Prints two columns recursively from our list
	# #-1 indicates column is done
	# 	if  not (column1 == -1): 

	# 		#check for newline
	# 		if not (syscallSelection[column1].category == col1Category):
	# 			col1Newline = True
	# 			col1Category = syscallSelection[column1].category


	# 		#check if we've reached the last in a category	
	# 		if(re.search("server", syscallSelection[column1].category, re.IGNORECASE)):
	# 			#Look for next col1 category
	# 			for i in range(len(syscallSelection[column1 + 1:])):
	# 				if not (re.search("server", syscallSelection[i + column1].category, re.IGNORECASE)):
	# 					column1 = i + column1
	# 					col1Category = syscallSelection[column1].category
	# 					break

	# 				#bounds checking
	# 				if i == len(syscallSelection[column1 + 1:])-1:
	# 					column1 = -1

	# 	if  not (column2 == -1):

	# 		if not (syscallSelection[column2].category == col2Category):
	# 			col2Newline = True
	# 			col2Category = syscallSelection[column2].category
	# 		#check if we've reached the last in a category
	# 		if not (re.search("server", syscallSelection[column2].category, re.IGNORECASE)):

	# 			#Look for next col2 category
	# 			for i in range(len(syscallSelection[column2 + 1:])):
	# 				if (re.search("server", syscallSelection[i + column2].category, re.IGNORECASE)):
	# 					column2 = i + column2
	# 					col2Category = syscallSelection[column2].category
	# 					break

	# 		#bounds checking
	# 		#After it finds the end of the list, it sets the position (column2) to -1 to know it is at the end
	# 		if column2 >= (len(syscallSelection)):
	# 					print("Col2 end")
	# 					column2 = -1

	# 	#Add col1 item
	# 	if not (column1 == -1):
	# 		if(col1Newline):
	# 			vMenu += (' {:<32}'.format(nada))
	# 		else:

	# 			#Format non categories
	# 			if not (syscallSelection[column1].name == syscallSelection[column1].category):
	# 				vMenu += (' {:<5s} {:<4s} {:<12s} {:<8}'.format(nada, syscallSelection[column1].code, syscallSelection[column1].name, osFindSelection(syscallSelection[column1]))) 

	# 			#Format Categories
	# 			else:
	# 				vMenu += (' {:<4s} {:<17s}  {:<8}'.format(syscallSelection[column1].code , syscallSelection[column1].name, osFindSelection(syscallSelection[column1]))) 
	# 			column1 += 1
	# 			if column1 >= (len(syscallSelection)):
	# 						column1 = -1
	# 	if not (column2 == -1):
	# 		if not col2Newline: 

	# 			#Format non categories
	# 			if not (syscallSelection[column2].name == syscallSelection[column2].category) and not (syscallSelection[column2].category == "server Column multiselect variables"):
	# 				vMenu += (' {:<6s} {:<5s} {:<27s} {:<5}'.format(nada, syscallSelection[column2].code, syscallSelection[column2].name, osFindSelection(syscallSelection[column2])))

	# 			#Format categories
	# 			else:
	# 				vMenu += (' {:<4s} {:<35s} {:<5}'.format(syscallSelection[column2].code, syscallSelection[column2].name, osFindSelection(syscallSelection[column2])))  
	# 			column2 += 1
	# 			if column2 >= (len(syscallSelection)):
	# 						column2 = -1
	# 	vMenu += "\n"
	# 	col1Newline = False
	# 	col2Newline = False
	# vMenu += "\n"
	vMenu = ""
	if showOptions:
		vMenu += mag+" \n\n Functional Commands:\n\n"+res
		vMenu += " {} - Options.\n".format(cya + "h" + res)
		vMenu += " {} - Clear syscall selections.\n".format(cya + "c" + res)
		vMenu += " {} - Enter syscall selections.\n".format(cya + "g" + res)
		vMenu += " {} - Change architecture for syscall.\t[".format(cya + "b" + res)
		vMenu += red+str(syscallPrintBit)+"-bit"+res
		vMenu += "]\n"
		vMenu += "    -    "+yel+"Note:"+res+" This should generally remain 64-bit.\n"
		vMenu += " {} - Display disassembly.\t[".format(cya + "d" + res)
		vMenu += red+"x"+res if showDisassembly else " "
		vMenu += "]\n"
		vMenu += " {} - Print syscalls.\n".format(cya + "z" + res)
		# vMenu += "b - Change bits 64]\n"
		vMenu += " {} - Exit.\n".format(cya + "x" + res)

	print(vMenu)

def printModulesMenu(modulesMode):
	# gMS_API_MIN_skip
	iMenu = gre + '\tNote: This feature is experimental and not always accurate.\n\n'+ res
	iMenu += 'Select one of the following options:\n'
	iMenu += "\t"+cya+"1"+res+" - Find only DLLs in IAT"
	if(modulesMode == 1):
		iMenu += "\t\t["+red+"x"+res+"]\n"
	else:
		iMenu += "\t\t[ ]\n"
	iMenu += "\t"+cya+"2"+res+" - Find DLLs in IAT and beyond"
	if(modulesMode == 2):
		iMenu += "\t\t["+red+"x"+res+"]\n"
	else:
		iMenu += "\t\t[ ]\n"
	iMenu += "\t"+cya+"3"+res+" - Find DLLs in IAT, beyond, and more"
	# iMenu += "\t\t**This must be selected to find InMemoryOrderModuleList.\n"
	if(modulesMode == 3):
		iMenu += "\t["+red+"x"+res+"]\n"
	else:
		iMenu += "\t[ ]\n"
	iMenu += gre+"\t\tDefault\n"+res
	# iMenu += "\t\t**This must be selected to find InMemoryOrderModuleList.\n"
	iMenu += "\t "+cya+"h"+res+" - Show options.\n"

	iMenu += "\t "+cya+"p"+res+" - Print.\n"
	iMenu += "\t "+cya+"z"+res+" - Execute.\n"
	iMenu += "\t "+cya+"r"+res+" - Reset .\n"
	iMenu += "\t "+cya+"x"+res+" - Exit.\n"
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
	iMenu += cya + "\tas"+ yel + res+" -"+yel+" ASCII strings\t"+res+"[" 
	iMenu += cya + "x"+res if bAsciiStrings else " "
	iMenu += res + "]\n" 
	iMenu += cya + "\twc"+ yel + res+" -"+yel+" Wide char strings\t"+res+"[" 
	iMenu += cya + "x" +res if bWideCharStrings else " "
	iMenu += res + "]\n" 
	iMenu += cya + "\tps"+ yel + res+" -"+yel+" Push stack strings\t"+res+"[" 
	iMenu += cya + "x"+res if bPushStackStrings else " "
	iMenu += res + "]\n" 
	iMenu += cya + "\tall"+ yel + res+" -"+yel+" All strings\t"+res+"[" 
	iMenu += cya + "x" +res if bAllStrings else " "
	iMenu += res + "]\n\n"
	# iMenu += "Sections:\n"
	# for sec in s:
	# 	iMenu += "\t" + sec.sectionName.decode() + "\n"
	# iMenu += "\n"
	iMenu += mag + " h"+res + " - Show options.\n"
	iMenu += mag + " g"+res +" - Toggle selections.\n\n"
	iMenu += gre + " Strings emulation:\n\n" + res
	iMenu += gre+"\tm"+res+" - Manually set register values for emulation.\n" + res
	
	iMenu +=yel+ "\t\tNote: This is only a sanity check.\n" + res
	iMenu +=gre+ "\tn"+res+" - Change name of registers text file for emulation "+yel+"["+res +"{}".format(cya + strFile + res) + yel + "]\n" + res
	iMenu +=gre+ "\t\tDefault: " + res + cya + "regs.txt\n" + res
	iMenu +=gre+ "\te"+res+" - Enable emulation of stack strings with use of registers "+yel+"["+res +"{}".format(cya + emu + res) + yel + "]\n" + res
	iMenu +=yel+ "\t\tNote: This should not be used ordinarily.\n" + res
	iMenu +=gre+ "\ts"+res+" - Check accuracy of found stack strings.\n" + res
	iMenu +=gre+ "\tk"+res+" - Change minimum length of strings.\n\n" + res

	iMenu += mag + " c"+res + " - Clear selections.\n"
	iMenu += mag + " p"+res + " - Print found strings.\n"
	iMenu += mag + " z"+res + " - Find strings.\n"
	iMenu += mag + " r"+res + " - Reset found strings.\n"
	iMenu += mag + " x"+res + " - Exit.\n"
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
	text += "\t{}      [{}]\n".format(cya + "  s"+res+" -"+yel+"  Find strings in shellcode"+ res, cya + strTogg + res)
	text += "\t{}     [{}]\n".format(cya + "  d"+res+" -"+yel+"  Use deobfuscated shellcode"+ res, cya + deobfTogg + res)
	text += "\t{} [{}]\n".format(cya + "  p"+res+" -"+yel+"  Find all shellcode insructions"+ res, cya + findshellTogg+ res)
	text += "\t{} [{}]\n".format(cya + "  c"+res+" -"+yel+"  Enable comments in disassembly"+ res, cya + commentsTogg+ res)

	print(text)
  	# s - Find strings in shellcode      [{}]
  	# d - Use deobfuscated shellcode     [{}]
  	# p - Find all shellcode insructions [{}]
  	# c - Enable comments in disassembly [{}]

	# """.format(cya + strTogg + res, cya + deobfTogg + res, cya + findshellTogg + res, cya + commentsTogg + res)

	# print (text)
	


def disassembleUiMenu(shellEntry):
	
	# leave this here
	#    {}:		Modify shellcode range. (Not functional)
	menu = """
  ......................
   Disassembly Options
  ......................

   {}:		Display options.
   {}:		Toggle selections.
   {}:		Output raw shellcode to Json format.
   {}:		Change entry point ({})
   {}:		Use md5 hash as shellcode filename.
   {}:		Generate disassembly.
   {}:		Return to main menu.
 
	""".format(gre +"h"+res, gre+"g"+res, gre+"j"+res, gre+"e"+res, cya + hex(shellEntry) + res, gre+"u"+res, gre+"D"+res, gre+"x"+res)

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