#include "parser.h"
#include <windows.h>
#include <cstdio>
#include <cstdint>

WORD PE_PARSER::getWordLE(const void *pData, int index) {     
    const unsigned char *pdata = static_cast<const unsigned char *>(pData);
    return pdata[index + 0] | (unsigned (pdata[index + 1]) << 8); 
}  

DWORD PE_PARSER::getDwordLE(const void *pData, int index) {     
    const unsigned char *pdata = static_cast<const unsigned char *>(pData);
    return pdata[index + 0] | (unsigned (pdata[index + 1]) << 8) | (unsigned (pdata[index + 2]) << 16) | (unsigned (pdata[index + 3]) << 24); 
}

QWORD PE_PARSER::getQwordLE(const void *pData, int index) {
    const unsigned char *pdata = static_cast<const unsigned char *>(pData);
    return pdata[index + 0] | (QWORD (pdata[index + 1]) << 8) | (QWORD (pdata[index + 2]) << 16) | (QWORD (pdata[index + 3]) << 24) |
        (QWORD (pdata[index + 4]) << 32) | (QWORD (pdata[index + 5]) << 40) | (QWORD (pdata[index + 6]) << 48) | (QWORD (pdata[index + 7]) << 56);
}
//
// constructor
//
PE_PARSER::PE_PARSER(HANDLE inputFile) {
    this->inputFile = inputFile;

    DOS_HEADER.e_magic = 0;
    DOS_HEADER.e_lfanew = 0;

    DOS_STUB = NULL;
    NT_HEADERS = NULL;
}
//
// parser for DOS HEADER
//
BOOL PE_PARSER::parseDosHeader() {
    printf("[+] Reading DOS Header ...\n");

    DWORD bytesRead = 0;
    if(!ReadFile(inputFile, &DOS_HEADER, sizeof(___IMAGE_DOS_HEADER), &bytesRead, NULL)) {
        throw PARSER_EXCEPTION("[-] Error: Could not read DOS Header.\n");
    }
    if(bytesRead != sizeof(___IMAGE_DOS_HEADER)) {
        throw PARSER_EXCEPTION("[-] Error: Could not read DOS Header entirely.\n");
    }
    if(getWordLE(&DOS_HEADER.e_magic, 0) != _IMAGE_MZ_SIGNATURE){
        // file does not have the MZ header
        throw PARSER_EXCEPTION("[-] Error: Current file does not have the MZ header.\n");
    }
    // TODO: check other dos values (in trecut) :)))) (azi)
    DOS_HEADER.e_lfanew = getDwordLE(&DOS_HEADER.e_lfanew, 0);

    printf("[+] Data correctly extracted from DOS Header.\n");
    return true;
}
//
//parser for DOS STUB
//
BOOL PE_PARSER::parseDosStub() {
    // temporary call treat compiler errors TODO
    getQwordLE(&DOS_HEADER, 0);
    //
    printf("[+] Reading DOS Stub ...\n");
    if(!DOS_HEADER.e_lfanew) {
        //
        // DOS_HEADER.e_lfanew is necessary 
        //
        throw PARSER_EXCEPTION("[-] Error: Could not read DOS Stub, as DOS Header was not read successfully.\n");
    }
    if(SetFilePointer(inputFile, sizeof(___IMAGE_DOS_HEADER), NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        throw PARSER_EXCEPTION("[-] Error: Could not move file pointer to DOS Stub.\n");
    }
    //
    DWORD sizeofDosStub = (DWORD)(DOS_HEADER.e_lfanew - sizeof(___IMAGE_DOS_HEADER));
    if(!sizeofDosStub){
        throw PARSER_EXCEPTION("[-] Error: There is no DOS stub ( size 0 detected )\n");
    }
    DOS_STUB = (__IMAGE_DOS_STUB)(malloc(sizeofDosStub));
    if(!DOS_STUB) {
        throw PARSER_EXCEPTION("[-] Error: Could not allocate memory for DOS Stub.\n");
    }
    //
    DWORD bytesRead = 0;
    if(!ReadFile(inputFile, DOS_STUB, sizeofDosStub, &bytesRead, NULL)) {
        free(DOS_STUB);
        DOS_STUB = NULL;

        throw PARSER_EXCEPTION("[-] Error: Could not read DOS Stub.\n");
    }
    if(bytesRead != sizeofDosStub) {
        free(DOS_STUB);
        DOS_STUB = NULL;

        throw PARSER_EXCEPTION("[-] Error: Could not read DOS Stub entirely. \n");
    }
    //
    printf("[+] DOS Stub successfully read.\n");
    return true;
}
//
// parser for NT Headers
//
BOOL PE_PARSER::parseNTHeaders(){
    printf("[+] Reading NT Headers ...\n");
    // 
    if(!DOS_HEADER.e_lfanew) {
        throw PARSER_EXCEPTION("[-] Error: Could not read NT Headers, as DOS Header was not read successfully.\n");
    }
    //
    // first, check optional header signature -> PE32 or PE32+
    //
    DWORD bytesRead = 0;
    if(SetFilePointer(inputFile,
                DOS_HEADER.e_lfanew + sizeof(DWORD) + sizeof(___IMAGE_FILE_HEADER),
                NULL,
                FILE_BEGIN) == INVALID_SET_FILE_POINTER) {

        throw PARSER_EXCEPTION("[-] Error: Could not find Optional Header Magic\n");
    }
    //
    WORD optionalMagic = 0;
    if(!ReadFile(inputFile, &optionalMagic, sizeof(WORD), &bytesRead, NULL)) {
        throw PARSER_EXCEPTION("[-] Error: Could not read Optional Header magic\n");
    }
    optionalMagic = getWordLE(&optionalMagic, 0);
    //
    // return
    //
    if(SetFilePointer(inputFile, DOS_HEADER.e_lfanew, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        throw PARSER_EXCEPTION("[-] Error: Could not move file pointer to NT Headers.\n");
    }
    bytesRead = 0;
    if(optionalMagic == _IMAGE_NT_HDR32_MAGIC) {
        // 32 bit PE
        //
        this->NT_HEADERS = &NT_HEADERS32;
        if(!ReadFile(inputFile, &NT_HEADERS32, sizeof(IMAGE_NT_HEADERS32), &bytesRead, NULL)) {
            throw PARSER_EXCEPTION("[-] Error: Could not read NT Headers\n"); 
        }
    }
    else if(optionalMagic == _IMAGE_NT_HDR64_MAGIC) {
        // 64 bit PE
        //
        this->NT_HEADERS = &NT_HEADERS64;
        if(!ReadFile(inputFile, &NT_HEADERS64, sizeof(IMAGE_NT_HEADERS64), &bytesRead, NULL)) {
            throw PARSER_EXCEPTION("[-] Error: Could not read NT Headers\n"); 
        }
    }
    printf("[+] NT Headers successfully read.\n");
    return true;
}
//
// main parser
//
BOOL PE_PARSER::parsePE() {
    printf("[+] Parsing PE ...\n");
    //
    try {
        parseDosHeader();
        parseDosStub();
        parseNTHeaders();
        //
    } catch (const PARSER_EXCEPTION &e) {
        printf(e.what());
        return false;
    }
    return true;
}
//
// destructor
//
PE_PARSER::~PE_PARSER() {

    if(DOS_STUB) {
        free(DOS_STUB);
        DOS_STUB = NULL;
    }
    if(NT_HEADERS) {
        free(NT_HEADERS);
        NT_HEADERS = NULL;
    }
}
