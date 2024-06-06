#include <Windows.h>
#include <stdio.h>

#include "GlobalExternVariables.h"
#include <process.h>

#pragma data_seg(".A$A")
__declspec(dllexport)__declspec(allocate(".A$A")) extern struct GlobalExternVariables genv = {};
#pragma data_seg()

#pragma comment(linker, "/MERGE:.rdata=.A")
#pragma comment(linker, "/MERGE:.data=.A")
#pragma comment(linker, "/MERGE:.bss=.A")

#pragma comment(lib, "kernel32.lib")
#pragma comment ( linker, "/entry:\"StubEntryPoint\"")

unsigned long long GetDLLLoadAddress() {
    HMODULE hModule;
    if (!GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCTSTR) &GetDLLLoadAddress, // Pass any address within the DLL
                           &hModule)) {
        return 0; // Failed to get the module handle
    }
    return (unsigned long long)hModule;
}

void __declspec(noinline) StubEntryPoint() {

    HANDLE hLog = CreateFile("log.txt", FILE_APPEND_DATA, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    long unsigned int bytes = 0;
    unsigned long long stub_load_address = GetDLLLoadAddress();
    WriteFile(hLog, &stub_load_address, 8, &bytes, NULL);

    HMODULE brieflzDLL = LoadLibraryA("brieflz.dll");
    HMODULE msvcrtDLL = LoadLibraryA("msvcrt.dll");

    if (!brieflzDLL || !msvcrtDLL) {
        return;
    }

    typedef void* (*MallocFunction)(size_t);
    MallocFunction malloc = (MallocFunction)GetProcAddress(msvcrtDLL, "malloc");
    typedef void* (__cdecl *MemcpyFunction)(void*, const void*, size_t);
    MemcpyFunction memcpy = (MemcpyFunction)GetProcAddress(msvcrtDLL, "memcpy");
    typedef void* (__cdecl *MemsetFunction)(void*, int, size_t);
    MemsetFunction memset = (MemsetFunction)GetProcAddress(msvcrtDLL, "memset");
    typedef unsigned long (*BLZ_DEPACK_FUNCTION)(const void* src, unsigned long src_size, void* dst, unsigned long depacked_size);
    BLZ_DEPACK_FUNCTION blz_depack_safe = (BLZ_DEPACK_FUNCTION)GetProcAddress(brieflzDLL, "blz_depack_safe");
    typedef unsigned long (*strlenFunction)(const void* buffer);
    strlenFunction strlen = (strlenFunction)GetProcAddress(msvcrtDLL, "strlen");

    if(!malloc || !memcpy || !blz_depack_safe) {
        return;
    }

    HMODULE load_address = GetModuleHandle(NULL);
    if (!load_address) {
        return;
    }
    PIMAGE_NT_HEADERS64 pNt = (PIMAGE_NT_HEADERS64)((BYTE*)load_address + sizeof(DWORD));
    PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((BYTE*)load_address + sizeof(DWORD) +
            sizeof(IMAGE_NT_HEADERS64) + pNt->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
    PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfig_main = (PIMAGE_LOAD_CONFIG_DIRECTORY)((BYTE*)load_address + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);

    LPVOID lpOrigLoadAddress = VirtualAlloc(NULL, pSec->PointerToRelocations, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!lpOrigLoadAddress) {
        return;
    }
    unsigned long size = blz_depack_safe(((BYTE*)load_address + pSec->PointerToRawData), pSec->SizeOfRawData, ((BYTE*)lpOrigLoadAddress), pSec->PointerToRelocations);
    if (!size) {
        return;
    }
    HANDLE hDump1 = CreateFile("dump_by_stub1.exe", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hDump1, (BYTE*)lpOrigLoadAddress, pSec->PointerToRelocations, &bytes, NULL);
    // move pNt to the NT_HEADERS of the original executable
    pNt = (PIMAGE_NT_HEADERS64)((BYTE*)lpOrigLoadAddress + ((PIMAGE_DOS_HEADER)lpOrigLoadAddress)->e_lfanew);
    // begin loader's job
    // fill IAT table
    LPCSTR functionID = NULL;
    LPCSTR dllName = NULL;
    FARPROC functionAddress = NULL;
_import:
    PIMAGE_DATA_DIRECTORY importDirectory = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDirectory->Size) {
        goto _bound;
    }
    // interate through import descriptors
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)lpOrigLoadAddress + importDirectory->VirtualAddress);
    if (!importDescriptor) {
        return;
    }
    // solve each dll
    while (importDescriptor->OriginalFirstThunk) {
        dllName = (LPCSTR)((BYTE*)lpOrigLoadAddress + importDescriptor->Name);
        //debug
        WriteFile(hLog, dllName, strlen(dllName), &bytes, NULL);
        WriteFile(hLog, "\n\n", 2, &bytes, NULL);
        //debug
        HMODULE hModuleDLL = LoadLibraryA(dllName);
        if (!hModuleDLL) {
            return;
        }
        PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)((BYTE*)lpOrigLoadAddress + importDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((BYTE*)lpOrigLoadAddress + importDescriptor->FirstThunk);
        while (pINT->u1.AddressOfData) {
            //debug
            //WriteFile(hLog, &origThunk->u1.AddressOfData, 8, &bytes, NULL);
            //WriteFile(hLog, "\n", 2, &bytes, NULL);
            //debug
            functionID = NULL;
            if (pINT->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                // import by ordinal
                functionID = (LPCSTR)(pINT->u1.Ordinal & 0xFFFF);
            } else {
                // import by name
                functionID = (LPCSTR)((PIMAGE_IMPORT_BY_NAME)((BYTE*)lpOrigLoadAddress + pINT->u1.AddressOfData))->Name;
            //debug
            WriteFile(hLog, functionID, 16, &bytes, NULL);
            WriteFile(hLog, "\n", 2, &bytes, NULL);
            //debug
            }
            functionAddress = GetProcAddress(hModuleDLL, functionID);
            if (!functionAddress) {
                return;
            }
            (pIAT++)->u1.Function = (ULONGLONG)functionAddress;
            pINT += 1;
        }
        importDescriptor += 1;
    }
_bound:
    PIMAGE_DATA_DIRECTORY boundDirectory = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    if (!boundDirectory->Size) {
        goto _delayed;
    }

    PIMAGE_BOUND_IMPORT_DESCRIPTOR boundDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)((BYTE*)lpOrigLoadAddress + boundDirectory->VirtualAddress);
    while (boundDescriptor->TimeDateStamp) {
        LPCSTR dllName = (LPCSTR)((BYTE*)lpOrigLoadAddress + boundDescriptor->OffsetModuleName);
        HMODULE hModule = LoadLibraryA(dllName);
        if (!hModule) {
            return;
        }
        if (!boundDescriptor->NumberOfModuleForwarderRefs) {
            boundDescriptor += 1;
            continue;
        }

        PIMAGE_BOUND_FORWARDER_REF forwarderRef = (PIMAGE_BOUND_FORWARDER_REF)(boundDescriptor + 1);
        for (unsigned int i = 0; i < boundDescriptor->NumberOfModuleForwarderRefs; i++) {
            LPCSTR forwarderDLLName = (LPCSTR)((BYTE*)lpOrigLoadAddress + forwarderRef->OffsetModuleName);
            HMODULE hForwarderModule = LoadLibraryA(forwarderDLLName);
            if (!hForwarderModule) {
                return;
            }
            forwarderRef += 1;
        }
        boundDescriptor = (PIMAGE_BOUND_IMPORT_DESCRIPTOR)forwarderRef;
    }
_delayed:
    PIMAGE_DATA_DIRECTORY delayedDirectory = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (!delayedDirectory->Size) {
        goto _reloc;
    }

    PIMAGE_DELAYLOAD_DESCRIPTOR delayloadDescriptor = (PIMAGE_DELAYLOAD_DESCRIPTOR)((BYTE*)lpOrigLoadAddress + delayedDirectory->VirtualAddress);
    while (delayloadDescriptor->DllNameRVA) {
        LPCSTR dllName = (LPCSTR)((BYTE*)lpOrigLoadAddress + delayloadDescriptor->DllNameRVA);
        HMODULE hDelayModule = LoadLibraryA(dllName);
        if (!hDelayModule) {
            return;
        }

        PIMAGE_THUNK_DATA delayedINT = (PIMAGE_THUNK_DATA)((BYTE*)lpOrigLoadAddress + delayloadDescriptor->ImportNameTableRVA);
        PIMAGE_THUNK_DATA delayedIAT = (PIMAGE_THUNK_DATA)((BYTE*)lpOrigLoadAddress + delayloadDescriptor->ImportAddressTableRVA);
        while (delayedIAT->u1.AddressOfData) {
            FARPROC delayedFunction = NULL;
            if (delayedINT->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                delayedFunction = GetProcAddress(hDelayModule, (LPCSTR)(delayedINT->u1.Ordinal & 0xFFFF));
            } else {
                delayedFunction = GetProcAddress(hDelayModule, ((PIMAGE_IMPORT_BY_NAME)((BYTE*)lpOrigLoadAddress + delayedINT->u1.AddressOfData))->Name);
            }
            if (!delayedFunction) {
                return;
            }
            (delayedIAT++)->u1.Function = (ULONGLONG)delayedFunction;
            delayedINT += 1;
        }
        delayloadDescriptor += 1;
    }
_reloc:
    //ULONGLONG delta = (ULONGLONG)((ULONGLONG)lpOrigLoadAddress + (ULONGLONG)stub_load_address - pNt->OptionalHeader.ImageBase);
    ULONGLONG delta = (ULONGLONG)((ULONGLONG)stub_load_address - pNt->OptionalHeader.ImageBase);
    PIMAGE_DATA_DIRECTORY relocationDirectory = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!relocationDirectory->Size) {
       // goto _exception;
        goto _run;
    }

    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)lpOrigLoadAddress + relocationDirectory->VirtualAddress);
    //debug
    //WriteFile(hLog, relocation, relocation->SizeOfBlock, &bytes, NULL);
    //WriteFile(hLog, "\n", 2, &bytes, NULL);
    //debug

    while (relocation->VirtualAddress) {
        BYTE* relocationBase = (BYTE*)lpOrigLoadAddress + relocation->VirtualAddress;

        unsigned long long numEntries = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            //debug
            WriteFile(hLog, &numEntries, 8, &bytes, NULL);
            WriteFile(hLog, "\n\n\n\n", 4, &bytes, NULL);
            //debug
        PWORD relocationEntry = reinterpret_cast<PWORD>((BYTE*)(relocation + 1));
        for (unsigned int i = 0; i < numEntries; i++) {
            WORD type = *relocationEntry >> 12;
            WORD offset = *relocationEntry & 0x0FFF;
            //debug
            WriteFile(hLog, relocationEntry, 8, &bytes, NULL);
            WriteFile(hLog, "\n", 1, &bytes, NULL);
            //debug
            if(type == IMAGE_REL_BASED_DIR64) {
                //*(ULONGLONG*)(relocationBase + offset) += (ULONGLONG)stub_load_address + (ULONGLONG) lpOrigLoadAddress;
                *(ULONGLONG*)(relocationBase + offset) += (ULONGLONG)stub_load_address;
                //ULONGLONG* fixup = (ULONGLONG*)(relocationBase + offset);
                //debug
                //WriteFile(hLog, (relocationBase + offset), 8, &bytes, NULL);
                //WriteFile(hLog, "\n", 1, &bytes, NULL);
                //debug
                *(ULONGLONG*)(relocationBase + offset) -= (ULONGLONG) pNt->OptionalHeader.ImageBase;
                //*fixup += delta;
            }
            //debug
            WriteFile(hLog, (relocationBase + offset), 8, &bytes, NULL);
            WriteFile(hLog, "\n\n", 1, &bytes, NULL);
            //debug
            relocationEntry += 1;
        }
        relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
    }
   //Sleep(30000); -> debug
_exception:
    PIMAGE_DATA_DIRECTORY exceptionDirectory = &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (!exceptionDirectory->Size) {
        goto _run;
    }
    PIMAGE_RUNTIME_FUNCTION_ENTRY functionEntries = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((BYTE*)lpOrigLoadAddress + exceptionDirectory->VirtualAddress);
    DWORD numEntries = exceptionDirectory->Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);

    for (DWORD i = 0; i < numEntries; ++i) {
        functionEntries[i].BeginAddress += delta;
        functionEntries[i].EndAddress += delta;
        functionEntries[i].UnwindData += delta;
    }
_run:
    //PIMAGE_LOAD_CONFIG_DIRECTORY pLoadConfig_guest = (PIMAGE_LOAD_CONFIG_DIRECTORY)((BYTE*)lpOrigLoadAddress + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
    //memcpy(pLoadConfig_guest, pLoadConfig_main, sizeof(IMAGE_LOAD_CONFIG_DIRECTORY));
    //memset(pLoadConfig_guest, 0, sizeof(IMAGE_LOAD_CONFIG_DIRECTORY));
    //
    HANDLE hDump = CreateFile("dump_by_stub.exe", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hDump, (BYTE*)lpOrigLoadAddress, pSec->PointerToRelocations, &bytes, NULL);

    //pNt->OptionalHeader.ImageBase = (ULONGLONG)stub_load_address + (ULONGLONG)lpOrigLoadAddress;
    pNt->OptionalHeader.ImageBase = (ULONGLONG)stub_load_address;
    //BYTE* entryPoint = (BYTE*)stub_load_address + (ULONGLONG)lpOrigLoadAddress + pNt->OptionalHeader.AddressOfEntryPoint;
    BYTE* entryPoint = (BYTE*)lpOrigLoadAddress + pNt->OptionalHeader.AddressOfEntryPoint;

    DWORD oldProtect;
    if (!VirtualProtect(lpOrigLoadAddress, pSec->PointerToRelocations, PAGE_EXECUTE_READ, &oldProtect)) {
        return;
    }
    ((void(*)())entryPoint)();
}

