#include <Windows.h>

#include "GlobalExternVariables.h"

#pragma data_seg(".A$A")
//__declspec(allocate(".A$A")) extern struct GlobalExternVariables genv = {};
#pragma data_seg()

#pragma comment(linker, "/MERGE:.rdata=.A")
#pragma comment(linker, "/MERGE:.data=.A")
#pragma comment(linker, "/MERGE:.bss=.A")

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

    HMODULE brieflzDLL = LoadLibrary("brieflz.dll");
    HMODULE msvcrtDLL = LoadLibrary("msvcrt.dll");

    typedef void* (*MallocFunction)(size_t);
    MallocFunction malloc = (MallocFunction) GetProcAddress(msvcrtDLL, "malloc");
    typedef void* (__cdecl *MemcpyFunction)(void*, const void*, size_t);
    MemcpyFunction memcpy = (MemcpyFunction) GetProcAddress(msvcrtDLL, "memcpy");

    // get the parent executable base address
    HMODULE load_address = GetModuleHandle(NULL);
    if(!load_address) {
        return;
    }

    // get to the section header
    unsigned int off = sizeof(DWORD);
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((BYTE*)load_address + off);
    unsigned long long BA = pNt->OptionalHeader.ImageBase;

    DWORD nSec = pNt->FileHeader.NumberOfSections;
    off += sizeof(IMAGE_NT_HEADERS64) + nSec * sizeof(IMAGE_SECTION_HEADER);

    PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((BYTE*) load_address + off);
    unsigned long long VS = pSec->SizeOfRawData;
    unsigned long long VA = pSec->PointerToRawData;

    // get data into a buffer and decompress using brieflz
    unsigned long origS = pSec->PointerToRelocations;

    BYTE* dec = (BYTE*) malloc(origS * sizeof(BYTE));
    BYTE* com = (BYTE*) malloc(VS * sizeof(BYTE));
    memcpy(com, ((BYTE*) load_address + VA), VS);

    //typedef unsigned long (*BLZ_DEPACK_FUNCTION)(const void *src, void *dst, unsigned long depacked_size);
    typedef unsigned long (*BLZ_DEPACK_FUNCTION)(const void *src, unsigned long src_size, void *dst, unsigned long depacked_size);
    BLZ_DEPACK_FUNCTION blz_depack_safe = (BLZ_DEPACK_FUNCTION)GetProcAddress(brieflzDLL, "blz_depack_safe");
    //BLZ_DEPACK_FUNCTION blz_depack = (BLZ_DEPACK_FUNCTION)GetProcAddress(brieflzDLL, "blz_depack");

    unsigned long size = blz_depack_safe(com, VS, dec, origS);
    //unsigned long size = blz_depack(com, dec, origS);

    HANDLE dump = CreateFile("dump_by_stub", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    long unsigned int bytes = 0;
    WriteFile(dump, dec, origS, &bytes, NULL);
    CloseHandle(dump);
}

