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
    // initialize the chosen compressor, use the wrapper
    char * in = (char*) malloc(hFileSize * sizeof(char));
    if(!in) {
        printf("[!] Error: PACKER: Could not allocate input buffer\n");
        return false;
    }
    long unsigned int bytesRead = 0;
    if(!ReadFile(hFile, in, hFileSize, &bytesRead, NULL) || bytesRead != hFileSize) {
        printf("[!] Error: PACKER: Could not read input file content properly\n");

        DELETE_DATA(in);
        return false;
    }
    // initialize compressor, type = 0 ( could be variable in the future )
    COMPRESSOR compressor(0);
    COMPRESSED* out = NULL;
    try {
        out = compressor.call_method(in, hFileSize);
        if(!out->size) {
            throw PACKER_EXCEPTION("[!] Error: Compression method could not be called properly\n");
        }
        // debugging
        /* 
           HANDLE hDump = CreateFile("dump", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
           long unsigned int bytes = 0;
           WriteFile(hDump, out->content, out->size, &bytes, NULL);
           */
        printf("compressed size = %ld\n", out->size);
        printf("original size = %d\n", hFileSize);
        // get boilerplate PE and insert the compressed data into the data section
        // TODO: parse PE, get only the necessary information
        //
        // initialize a PE_PARSER
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        PE_PARSER p_in(hFile);

        p_in.parseDosHeader();
        p_in.parseNTHeaders();
        p_in.parseSectionHeader();
        p_in.getSections();
        //
        HANDLE hBoilerplate = CreateFile(BOILERPLATE, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hBoilerplate == INVALID_HANDLE_VALUE) {
            throw PACKER_EXCEPTION("[!] ERROR: PACKED: Could not access boilerplate PE\n");
        }

        unsigned int bsize = GetFileSize(hBoilerplate, NULL);
        if(bsize == INVALID_FILE_SIZE) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get boilerplate filesize\n");
        }
        char * boilerplate = (char*) malloc(bsize * sizeof(char));
        if(!boilerplate) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get boilerplate data\n");
        }

        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        bytesRead = 0;

        if(!ReadFile(hBoilerplate, boilerplate, bsize, &bytesRead, NULL) || bytesRead != bsize) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not read boilerplate info\n");
        }
    } catch(const PACKER_EXCEPTION &e) {
        printf("[!] Error: PACKED: An exception has occurred durng file compression: \n%s\n", e.what());
        DELETE_DATA(in);
        DELETE_DATA(out);

        return false;
    }
        printf("a ajuns aici\n");
    return true;
    // initialize compressor
    // parse PE
    // compress PE
    // get boilerplate
    // insert data in data section
}
