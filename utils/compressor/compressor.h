#pragma once
#include "brieflz.h"

#define NUMBER_OF_COMPRESSORS 1

class COMPRESSOR {
    public:
        COMPRESSOR();
        COMPRESSOR(unsigned int type);
        ~COMPRESSOR();

        bool call_method(HANDLE hFile, unsigned int hFileSize) const; 
    private:
        static bool const compress_with_brieflz(HANDLE hFile, unsigned int hFileSize);

        unsigned int type;
        using COMPRESSION_METHODS = const bool (*)(HANDLE, unsigned int);
        static constexpr COMPRESSION_METHODS methods[1] = { compress_with_brieflz };
};


typedef class _COMPRESSOR_EXCEPTION : public std::exception 
{
    private:

        std::string errorMessage;

    public:
        explicit _COMPRESSOR_EXCEPTION(const char* error) : errorMessage(error) {} 
        _COMPRESSOR_EXCEPTION()=delete;

        virtual ~_COMPRESSOR_EXCEPTION() noexcept = default;

        const char* what() const noexcept override {
            return errorMessage.c_str();
        }
}COMPRESSOR_EXCEPTION;
