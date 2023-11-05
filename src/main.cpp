#include <windows.h>
#include "parser.h"
#include <cstdio>

int main(int argc, char ** argv) {

    HANDLE executableFile = CreateFileA(argv[1], GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(executableFile == INVALID_HANDLE_VALUE) {

        printf("[!] Error: Could not open file, invalid.\n");
        return -1;
    }

    PEparser PEparser(executableFile);
    if(!PEparser.parsePE()) {
        printf("[!] Error : Could not parse PE.\n");
        return -1;
    }

    return 0;
}
