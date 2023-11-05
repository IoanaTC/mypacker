#ifndef PE_PARSER_H
#define PE_PARSER_H

#include "peformat.h"
#include <windows.h>


class PEparser
{
    public:
        IMAGE_DOS_HEADER dosHeader;
        BYTES* dosStub;

        HANDLE inputFile;

        PEparser(HANDLE inputFile);
        bool parsePE();


        ~PEparser();

    private:

        bool readDosHeader();
        bool readDosStub();

};

#endif
