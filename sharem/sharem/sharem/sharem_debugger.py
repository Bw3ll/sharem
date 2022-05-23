from colorama import Fore, Style
from unicorn.x86_const import *

def prompt():
    print(f"{Fore.RED}SHAREMDebug>{Style.RESET_ALL}", end=' ')
    command = input().split(' ')
    if len(command) == 1:
        command = command[0]

    return command

def set_reg(uc, command):
    reg = command[1]
    val = command[2]
    if '0x' in val:
        val = int(val, 16)
    else:
        val = int(val)

    if reg == 'eax':
        uc.reg_write(UC_X86_REG_EAX, val)
    elif reg == 'ebx':
        uc.reg_write(UC_X86_REG_EBX, val)
    elif reg == 'ecx':
        uc.reg_write(UC_X86_REG_ECX, val)
    elif reg == 'edx':
        uc.reg_write(UC_X86_REG_EDX, val)
    elif reg == 'edi':
        uc.reg_write(UC_X86_REG_EDI, val)
    elif reg == 'esi':
        uc.reg_write(UC_X86_REG_ESI, val)
    elif reg == 'ebp':
        uc.reg_write(UC_X86_REG_EBP, val)
    elif reg == 'esp':
        uc.reg_write(UC_X86_REG_ESP, val)
    else:
        print("Syntax error. Usage: setreg <reg> <val>")

def debugger(uc, em):
    while True:
        command = prompt()

        if command == 'h' or command == 'help':
            print("OPTIONS: ")
            print("\t setreg <reg> <val>\tChange register value")
            print("\t n | next\t \tNext Instriction")
            print("\t h | help\t \tPrint the help menu")
            print("\t e | end\t \tExit debugger and skip to end of emulation")
            print("\t q | quit\t \tStop emulation of the shellcode")
        elif type(command) == list:
            if command[0] == 'setreg':
                set_reg(uc, command)
        elif command == 'n' or command == 'next':
            break
        elif command == 'e' or command == 'end':
            em.debug = False
            break
        elif command == 'q' or command == 'quit':
            uc.emu_stop()
            break
        else:
            break

    return em