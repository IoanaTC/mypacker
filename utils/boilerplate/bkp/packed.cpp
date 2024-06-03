#include <windows.h>
#include <iostream>
using namespace std;
#define IDR_STUBDLL 101

__attribute__((force_align_arg_pointer))
void _start() {

    HMODULE hModule = GetModuleHandle(NULL);
    if(!hModule) return;

    long unsigned int stubSize = 0;
    HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(IDR_STUBDLL), RT_RCDATA);
    if(!hResource) return;

    HGLOBAL hResData = LoadResource(hModule, hResource);
    if(!hResData) return;
    
    stubSize = SizeofResource(hModule, hResource);
    if(!stubSize) return;

    void* stubData = LockResource(hResData);
    if(!stubData) return;

    HANDLE hTempDll = CreateFileA("stub.dll", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hTempDll == INVALID_HANDLE_VALUE) return;

    long unsigned int bytesWritten = 0;
    if(!WriteFile(hTempDll, stubData, stubSize, &bytesWritten, NULL)) return;
    if(!CloseHandle(hTempDll)) return;

    HMODULE hStubDll = LoadLibraryA("stub.dll");
    // delete, free
    return;
}
