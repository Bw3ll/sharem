# -32 or 64 bit mode
# -Option to ignore syscall
# -Option for each of the types
#     -FSTENV
#     -Callpop
#     -PebSequences
#     -Pushret
#     -PushStrings
#     -Stringsonsections
#     -getDLLs
#	  -get Peb walk start
#     -getSyscall
#     -get Egghunters
#     -get heaven
# -Different registers
# -Options 
import sys
def showOptions():
	options = "\nOptions:\n"
	options +="s: Discover and Print Shellcode Instructions\n"
	options +="b: Change Bit Mode\n"
	options +="h: Show Current Options\n"
	options += "x: Exit\n"
	print(options)
def bitMode():
	bitMenu = "\nChange Bit Mode:\n"
	bitMenu +="Enter 32 or 64: "
	print(bitMenu)
def instructionssMenu(bList):
	bPushRet = bList[0]
	bFstenv = bList[1]
	bCallPop = bList[2]
	sMenu = "\nSet/Unset:\n"
	sMenu +="\n\nEnter T or F for each instruction set, delimitied by a space.\n"
	sMenu +="\tPUSHRET  FSTENV  CALLPOP\n"
	sMenu +="\teg: F T F\n\n"
	sMenu +="x to exit\n\n"
	print(sMenu)

