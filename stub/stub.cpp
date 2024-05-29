#include <Windows.h>

#include "brieflz.h"
#include "GlobalExternVariables.h"

#pragma data_seg(".A$A")
__declspec(allocate(".A$A")) extern struct GlobalExternVariables genv = {};
#pragma data_seg()

#pragma comment(linker, "/MERGE:.rdata=.A")
#pragma comment(linker, "/MERGE:.data=.A")
#pragma comment(linker, "/MERGE:.bss=.A")

unsigned long long load_address = 0;
#pragma comment(lib, "kernel32.lib")
// compiler directive that allows me
// to instruct the linker to set this symbol StubEntryPoint to serve as an entry point function
// thus the program should start executing from the StubEntryPoint() function
#pragma comment ( linker, "/entry:\"StubEntryPoint\"")
// __declspec (naked) directive informs the compiler that it should not generate any epilogue or prologue for
// the affordmentioned function, it is a Microsoft directive
// this allows me to write assembly code directly into the function body
//
void __declspec(noinline) StubEntryPoint() {
    HMODULE hModule = GetModuleHandle(NULL);
    
    HANDLE dump = CreateFile("dump_by_stub", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    long unsigned int bytes = 0;
    WriteFile(dump, hModule, sizeof(HMODULE), &bytes, NULL);
}

