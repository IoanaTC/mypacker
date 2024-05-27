#include <iostream>
#include <windows.h>
#include "packer.h"
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
    return true;
    // initialize compressor
    // parse PE
    // compress PE
    // get boilerplate
    // insert data in data section
}
