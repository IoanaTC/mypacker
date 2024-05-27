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
        return false;
    }
    long unsigned int bytesRead = 0;
    if(!ReadFile(hFile, in, hFileSize, &bytesRead, NULL)) {
        return false;
    }

    printf("%c\n", *(in + 1));

    COMPRESSOR compressor(0);
    char* out = NULL;
    long unsigned int compressed_size = compressor.call_method(in, hFileSize, out);
    printf("compressed size = %ld\n", compressed_size);
    printf("original size = %d\n", hFileSize);
    if(!compressed_size) {
        throw PACKER_EXCEPTION("[!] Error: Compression method could not be called properly\n");
        return false;
    }
    return true;
    // initialize compressor
    // parse PE
    // compress PE
    // get boilerplate
    // insert data in data section
}
