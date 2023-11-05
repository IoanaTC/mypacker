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
    //printf("from getwordle: %04X\n", (pdata[index + 0]<<8 | (unsigned (pdata[index + 1]))));
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


// parser's constructor 
PEparser::PEparser(HANDLE inputFile) {
    this->inputFile = inputFile;

    // initialized values
    dosHeader.e_magic = 0;
    dosHeader.e_lfanew = 0;

    dosStub = NULL;
}

// parser for DOS HEADER
bool PEparser::readDosHeader() {

    printf("[-] Reading DOS Header ...\n");

    DWORD bytesRead = 0;

    if(!ReadFile(inputFile, &dosHeader, sizeof(IMAGE_DOS_HEADER), &bytesRead, NULL)) {
        printf("[!] Error: Could not read DOS Header.\n");
        return false;
    }
    /*
    for(int i=0; i<63; i+=2){

        printf("%08X\n", *((uint16_t*)(&dosHeader) + i));
    }*/

    if(bytesRead != sizeof(IMAGE_DOS_HEADER)) {
        printf("[!] Error: Could not read DOS Header entirely.\n");
        return false;
    }
    
    // DOS Header - successfully read
    //
    // get DOS magic - MZ

    //printf("%04X, %04X\n", getWordLE(&dosHeader.e_magic, 0), dosHeader.e_magic);

    unsigned char* magic = reinterpret_cast<unsigned char*>(&dosHeader.e_magic);
    printf("%c %c\n", magic[0], magic[1]);

    uint16_t magicValue =  getWordLE(&dosHeader.e_magic, 0);
    unsigned char* magic2 = reinterpret_cast<unsigned char*>(&magicValue);
    printf("%c %c\n", magic2[0], magic2[1]);

    //printf("%08X, %08X\n", getDwordLE(&dosHeader.e_lfanew, 0), dosHeader.e_lfanew);
    if(getWordLE(&dosHeader.e_magic, 0) != MZ_HEADER){
        // file does not have the MZ header
        printf("[!] Error: Current file does not have the MZ header.\n");
        return false;
    }

    // TODO: check other dos values
    //
    if(!getDwordLE(&dosHeader.e_lfanew, 0)) {

        printf("[!] Error: Could not correctly read file address to new executable file.\n");
        return false;
    }

    printf("[-] Data correctly extracted from DOS Header.\n");
    printf("[^] dosHeader.e_lfanew : %04X\n", dosHeader.e_lfanew);
    return true;
}

//parser for DOS STUB
bool PEparser::readDosStub() {
    // get size of DOS STUB
    
    printf("[-] Reading DOS Stub ...\n");

    if(!dosHeader.e_lfanew) {

        // dosHeader.e_lfanew is necessary, 
        // there starts new executable file address

        printf("[!] Error: Could not read DOS Stub, as DOS Header was not read successfully.\n");
        return false;
    }

    if(SetFilePointer(inputFile, sizeof(IMAGE_DOS_HEADER), NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {

        printf("[!] Error: Could not move file pointer to DOS Stub.\n");
        return false;
    }

    DWORD bytesRead = 0;
    DWORD sizeofDosStub = static_cast<uint32_t>(dosHeader.e_lfanew - sizeof(IMAGE_DOS_HEADER));

    printf("[^] sizeofDosStub: %04X\n", sizeofDosStub);
    dosStub = static_cast<BYTES*>(malloc(sizeofDosStub));

    if(!dosStub) {
        printf("[!] Error: Could not allocate memory for DOS Stub.\n");

        free(dosStub);
        dosStub = NULL;

        return false;
    }


    if(!ReadFile(inputFile, dosStub, sizeofDosStub, &bytesRead, NULL)) {
        printf("[!] Error: Could not read DOS Stub.\n");

        free(dosStub);
        dosStub = NULL;

        return false;
    }

    if(bytesRead != sizeofDosStub) {
        printf("[-] Error: Could not read DOS Stub entirely. \n");

        free(dosStub);
        dosStub = NULL;

        return false;
    }

    printf("[-] DOS Stub successfully read.\n");
    printf("[^] DOS Stub: \n", *dosStub);

    for (DWORD i = 0; i < sizeofDosStub; i++) {     
        printf("%02X ", dosStub[i]); } 
    printf("\n");

    return true;
}
bool PEparser::readNTHeaders(){
   
    printf("[-] Reading NT Headers ...");
    
    if(!dosHeader.e_lfanew) {
        printf("[!] Error: Could not read NT Headers, as DOS Header was not read successfully.\n");
        return false;
    }

    if(SetFilePointer(inputFile, dosHeader.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {

        printf("[!] Error: Could not move file pointer to NT Headers.\n");
        return false;
    }

    // read PE - Signature

}

/*
static void coutDOSheader(PEparser *parser) {

    printf("e_magic: %02X\n", (parser->dosHeader).e_magic);
    printf("e_cblp: %02X\n", (parser->dosHeader).e_cblp);
    printf("e_cp: %02X\n", (parser->dosHeader).e_cp);
    printf("e_crlc: %02X\n", (parser->dosHeader).e_crlc);
    printf("e_cparhdr: %02X\n", (parser->dosHeader).e_cparhdr);
    printf("e_minalloc: %02X\n", (parser->dosHeader).e_minalloc);
    printf("e_maxalloc: %02X\n", (parser->dosHeader).e_maxalloc);
    printf("e_ss: %02X\n", (parser->dosHeader).e_ss);
    printf("e_sp: %02X\n", (parser->dosHeader).e_sp);
    printf("e_csum: %02X\n", (parser->dosHeader).e_csum);
    printf("e_ip: %02X\n", (parser->dosHeader).e_ip);
    printf("e_cs: %02X\n", (parser->dosHeader).e_cs);
    printf("e_lfarlc: %02X\n", (parser->dosHeader).e_lfarlc);
    printf("e_ovno: %02X\n", (parser->dosHeader).e_ovno);
    printf("e_res: %08X\n", (parser->dosHeader).e_res);
    printf("e_oemid: %02X\n", (parser->dosHeader).e_oemid);
    printf("e_oeminfo: %02X\n", (parser->dosHeader).e_oeminfo);
    printf("e_res2: %012X\n", (parser->dosHeader).e_res2);
    printf("e_lfanew: %04X\n", (parser->dosHeader).e_lfanew);
}
*/
// main parser
bool PEparser::parsePE() {

    printf("[-] Parsing PE ...\n");
    if(!readDosHeader()) {
        printf("[!] Error: Could not read DOS Header.\n");
        return false;
    }
    
    printf("[-] Successfully read DOS Header.\n");

    if(!readDosStub()) {
        printf("[!] Error: Could not read DOS Stub.\n");
        return false;
    }
    printf("[-] Successfully read DOS Stub.\n");

    return true;
}

PEparser::~PEparser() {
    if(dosStub) {
        free(dosStub);
        dosStub = NULL;
    }
}
