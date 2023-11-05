#include "parser.h"
#include <windows.h>
#include <cstdio>
#include <cstdint>

// define parser's constructor
// it sets up the executable file for parsing
//
static const int pointerSize = sizeof(void*);

static uint16_t getWordLE(const void *pData, int index) {     
    const unsigned char *pdata = static_cast<const unsigned char *>(pData);

    //printf("pData = %X\n", pdata[10]);
    
    if(index > pointerSize - 2) {
        printf("[!] Error: Index must be smaller than %d\n", pointerSize);
        return 0;
    }
    return pdata[index + 0] | (unsigned (pdata[index + 1]) << 8); 
}  

static uint32_t getDwordLE(const void *pData, int index) {     
    const unsigned char *pdata = static_cast<const unsigned char *>(pData);

    if(index > pointerSize - 3) {
        printf("[!] Error: Index must be smaller than %d\n", pointerSize);
        return 0;
    }
    return pdata[index + 0] | (unsigned (pdata[index + 1]) << 8) | (unsigned (pdata[index + 2]) << 16) | (unsigned (pdata[index + 3]) << 24); 
}

static uint64_t getQwordLE(const void *pData, int index) {
    const unsigned char *pdata = static_cast<const unsigned char *>(pData);

    if(index > pointerSize - 4) { 
        printf("[!] Error: Index must be smaller than %d\n", pointerSize);
        return 0;
    }
    return pdata[index + 0] | (QWORD (pdata[index + 1]) << 8) | (QWORD (pdata[index + 2]) << 16) | (QWORD (pdata[index + 3]) << 24) | (QWORD (pdata[index + 4]) << 32) | (QWORD (pdata[index + 5]) << 40) | (QWORD (pdata[index + 6]) << 48) | (QWORD (pdata[index + 7]) << 56);
}

PEparser::PEparser(HANDLE inputFile) {
    this->inputFile = inputFile;
}

bool PEparser::readDosHeader() {

    DWORD bytesRead = 0;

    if(!ReadFile(inputFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL)) {
        printf("[!] Error: Could not read DOS Header.\n");
        return false;
    }

    if(bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        printf("[!] Error: Could not read DOS Header entirely.\n");
        return false;
    }
    
    // DOS Header - successfully read
    //
    // get DOS magic - MZ
    if(getWordLE(&dosHeader.e_magic, 0) != 0x5A4D){
        
        // file does not have the MZ header
        printf("[!] Error: Current file does not have the MZ header.\n");
        return false;
    }
    // check other dos values
    //
    if(!getDwordLE(&dosHeader.e_lfanew, 0)) {

        printf("[!] Error: Could not correctly read file address to new executable file.\n");
        return false;
    }

    printf("[-] Data correctly extracted from DOS Header.\n");
    printf("[^] dosHeader.e_lfanew : %04X\n", dosHeader.e_lfanew);
    return true;
}

bool PEparser::parsePE() {

    printf("[-] Parsing PE ...\n");
    if(!readDosHeader()) {
        printf("[!] Error: Could not read DOS Header.\n");
        return false;
    }
    
    printf("[-] Successfully read DOS Header\n");
    return true;
}

PEparser::~PEparser() {
    
}
