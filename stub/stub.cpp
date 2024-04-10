#include <Windows.h>
#include "GlobalExternVariables.h"

// compiler directive that allows me
// to instruct the linker to set this symbol StubEntryPoint to serve as an entry point function 
// thus the program should start executing from the StubEntryPoint() function
#pragma comment ( linker, "/entry:\"StubEntryPoint\"")
// __declspec (naked) directive informs the compiler that it should not generate any epilogue or prologue for 
// the affordmentioned function, it is a Microsoft directive
// this allows me to write assembly code directly into the function body
void __declspec(noinline) StubEntryPoint() {
} 

#pragma data_seg(".A$A")
__declspec(allocate(".A$A")) extern struct GlobalExternVariables genv = {

};
#pragma data_seg()

#pragma comment(linker, "/MERGE:.rdata=.A")
#pragma comment(linker, "/MERGE:.data=.A")
#pragma comment(linker, "/MERGE:.bss=.A")
