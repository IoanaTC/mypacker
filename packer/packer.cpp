#include <iostream>
#include <windows.h>
#include "packer.h"
#include "compressor.h"
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
            DELETE_DATA(in);
            DELETE_DATA(out);
            return false;
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

    } catch(const COMPRESSOR_EXCEPTION &e) {
        printf("[!] Error: PACKED: An exception has occurred durng file compression: \n%s\n", e.what());
        DELETE_DATA(in);
        DELETE_DATA(out);

        return false;
    }
    return true;
    // initialize compressor
    // parse PE
    // compress PE
    // get boilerplate
    // insert data in data section
}
