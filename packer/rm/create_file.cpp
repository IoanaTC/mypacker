#include <iostream>
#include "peformat.h"
#include "create_file.h"
using namespace std;

#define DELETE_DATA(x) do { if (x) { free(x); x = NULL; } } while(0)

bool CREATE_FILE::fillPackedFile() {
    unsigned int offset = 0;
    // create DOS header + DOS stub 
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*) malloc(sizeof(IMAGE_DOS_HEADER));
    if(!dos_header) {
        printf("[-] Error: allocation of dos_header has failed\n");
        return EXIT_FAILURE;
    }
    dos_header->e_magic = 0x4d5A;
    //for(uint8_t i = 0; i < sizeof(IMAGE_DOS_HEADER); i ++) {
    //    dos_header->e_magic + i = 0;
    //}
    dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER); 
    memcpy(this->content + offset, dos_header, sizeof(IMAGE_DOS_HEADER));

    DELETE_DATA(dos_header);
    // create pe header
    offset += sizeof(IMAGE_DOS_HEADER);
         
    return true;
} 
