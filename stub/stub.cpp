#include <Windows.h>

#include "lz4.h"
#include "GlobalExternVariables.h"

#pragma data_seg(".A$A")
__declspec(allocate(".A$A")) extern struct GlobalExternVariables genv = {};
#pragma data_seg()

#pragma comment(linker, "/MERGE:.rdata=.A")
#pragma comment(linker, "/MERGE:.data=.A")
#pragma comment(linker, "/MERGE:.bss=.A")

unsigned long long load_address = 0;
/*
struct section_header {
    unsigned int RVA_to_section;
    unsigned int size;
};
IMAGE_DATA_DIRECTORY original_data_directory;
//IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
*/

// compiler directive that allows me
// to instruct the linker to set this symbol StubEntryPoint to serve as an entry point function
// thus the program should start executing from the StubEntryPoint() function
#pragma comment ( linker, "/entry:\"StubEntryPoint\"")
// __declspec (naked) directive informs the compiler that it should not generate any epilogue or prologue for
// the affordmentioned function, it is a Microsoft directive
// this allows me to write assembly code directly into the function body
//
// decompressor class
void __declspec(noinline) StubEntryPoint() {
    load_address = (unsigned long long) StubEntryPoint - genv.RVA_to_stub_entry_point;
    // first the stub needs to locate the compressed data
    // thus, it needs to find the offsets to the sections of
    // the executable it is currently injecting itself into
    //

    /*
    // starting from the load address it needs to get to the e_lfanew offset
    unsigned long long * offset = load_address;
    offset += 0x3C;

    // now thw offset needs to jump to the address written here
    offset += *offset;

    // finally, in order to get to the packed data, it needs to find the sections
    // in order to manage that, i find the size of optional header and jump over it
    offset += 0x14; // current offset = size of optional header
    offset += *offset + 0x2; // current offset = section headers

    // the stub reached the start of the compressed data
    // i need the size of the sections
    //
    */

}

