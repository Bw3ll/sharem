#include <stdio.h>
#include <windows.h>


int main(int argc, char argv[], char envp[]) {

	DWORD dwKernel32Base = 0;
	DWORD exports = 0;
	DWORD aoFunc = 0;

	__asm
	{
		nop
		nop
		nop
		nop
		nop
		nop
		mov    eax,0x26
		call   DWORD PTR fs:0xc0
		nop
		nop
		nop
		nop
		nop
		nop
		mov    ebx,0xc0
		mov    eax,0x26
		call   DWORD PTR fs:[ebx] 
		nop
		nop
		nop
		nop
	
	}
}