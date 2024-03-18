#ifndef PE_PARSER_H
#define PE_PARSER_H

#include "peformat.h"
#include <stdexcept>
#include <windows.h>
#include <string>

class ParserPE
{
    public:
        IMAGE_DOS_HEADER dosHeader;
        BYTE* dosStub;

        void* ntHeaders;
        IMAGE_NT_HEADERS32 ntHeaders32;
        IMAGE_NT_HEADERS64 ntHeaders64;

        HANDLE inputFile;

        ParserPE(HANDLE inputFile);
        bool parsePE();

        ~ParserPE();

    private:

        bool readDosHeader();
        bool readDosStub();

        bool readNTHeaders();
        bool readSectionHeader();
};

typedef class _PARSER_EXCEPTION : public std::exception 
{
    private:

        std::string errorMessage;

    public:
        explicit _PARSER_EXCEPTION(const char* error) : errorMessage(error) {} 
        _PARSER_EXCEPTION()=delete;

        virtual ~_PARSER_EXCEPTION() noexcept = default;

        const char* what() const noexcept override {
            // .data -> returns content of string
            // doea not guarantee null-termination
            return errorMessage.c_str();
        }
}PARSER_EXCEPTION;

#endif
