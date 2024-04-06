#ifndef PE_PARSER_H
#define PE_PARSER_H

#include "peformat.h"
#include <stdexcept>
#include <windows.h>
#include <string>

class PE_PARSER
{
    private:
        __IMAGE_DOS_HEADER  DOS_HEADER;
        __IMAGE_DOS_STUB    DOS_STUB;

        VOID*               NT_HEADERS;                 // currently it represents both 32 and 64 versions of the header
        IMAGE_NT_HEADERS32  NT_HEADERS32;
        IMAGE_NT_HEADERS64  NT_HEADERS64;

        HANDLE inputFile;

    public:
        PE_PARSER(HANDLE inputFile);
        ~PE_PARSER();

        static WORD getWordLE(const void* pData, int index);
        static DWORD getDwordLE(const void* pData, int index);
        static QWORD getQwordLE(const void* pData, int index);

        BOOL parsePE();

        BOOL parseDosHeader();
        BOOL parseDosStub();

        BOOL parseNTHeaders();
        //BOOL parseSectionHeader();
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
            return errorMessage.c_str();
        }
}PARSER_EXCEPTION;

#endif
