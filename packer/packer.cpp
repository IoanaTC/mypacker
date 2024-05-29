#include <iostream>
#include <windows.h>
#include "packer.h"
#include "compressor.h"
#include "parser.h"
using namespace std;

PACKER::PACKER() {
    throw PACKER_EXCEPTION("[!] Error: There is no file handle given to the constructor\n");
}
PACKER::PACKER(HANDLE hFile) {
    this->hFile = hFile;
    // get hFile ssize
    unsigned int filesize = GetFileSize(hFile, /* lpFileSizeHigh = */ NULL);
    if(filesize == INVALID_FILE_SIZE) {
        throw PACKER_EXCEPTION("[!] Error: Could not compute handle file size\n");
    }
    this->hFileSize = filesize;
}
PACKER::~PACKER() {
   printf("[+] PACKER: destructor has been called\n"); 
}
bool PACKER::packfile() {
    printf("[+] Hello\n");
    HANDLE hMapping = CreateFileMapping(hFile, 0, PAGE_READWRITE, 0, 0, NULL);
    if(!hMapping) {
        cout<<GetLastError()<<endl;
        printf("[!] Error: PACKED: Cannot create file mapping from given input\n");
        return false;
    }
    printf("a ajuns aici %p\n", hMapping);
    char* mappedImage = (char*) MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if(!mappedImage) {
        printf("[!] Error: PACKED: Cannot get map view of input file\n");
        return false;
    }
    if(!CloseHandle(hMapping)) {
        printf("[!] Error: Cannot close hMapping handle\n");
        return false;
    }
    // initialize the chosen compressor, use the wrapper
    // initialize compressor, type = 0 ( could be variable in the future )
    COMPRESSOR compressor(0);
    COMPRESSED* out = NULL;
    try {
        out = compressor.call_method(mappedImage, hFileSize);
        if(!out->size) {
            throw PACKER_EXCEPTION("[!] Error: Compression method could not be called properly\n");
        }
        // debugging
        printf("compressed size = %ld\n", out->size);
        printf("original size = %d\n", hFileSize);
        // get boilerplate PE and insert the compressed data into the data section
        // TODO: parse PE, get only the necessary information
        //
        // get this PE form from this exes own resource section
        HMODULE hModule = GetModuleHandle(NULL);
        if(!hModule) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get this process current loaded module\n");
        }
        long unsigned int resource_size = 0;
        HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(IDR_RES), RT_RCDATA);
        if(!hResource)  {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get current module's requested resource\n");
        }
        HGLOBAL hResData = LoadResource(hModule, hResource);
        if(!hResData) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not load requested resource\n");
        }
        resource_size = SizeofResource(hModule, hResource);
        if(!resource_size) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get resource size\n");
        }
        unsigned char* resource_data = (unsigned char *) LockResource(hResData);
        if(!resource_data) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get resource data\n");
        }

        HANDLE hDump = CreateFile("dump.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hDump == INVALID_HANDLE_VALUE) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not create packed file dump handle\n");
        }
        long unsigned int bytes = 0;
        if(!WriteFile(hDump, resource_data, resource_size, &bytes, NULL)) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not dump adjusted tinyPE\n");
        }
        if(!WriteFile(hDump, out->content, out->size, &bytes, NULL)) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not append the compressed data to the end of tinyPE\n");
        }
        // append decompressing stub

    } catch(const PACKER_EXCEPTION &e) {
        printf("[!] Error: PACKED: An exception has occurred durng file compression: \n%s", e.what());
        DELETE_DATA(mappedImage);
        DELETE_DATA(out);

        return false;
    }
    printf("a ajuns aici 3\n");
    return true;
}
