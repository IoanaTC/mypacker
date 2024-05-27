#pragma once
#include "brieflz.h"

#define NUMBER_OF_COMPRESSORS 1
#define BRIEFL_COMPRESSION_LEVEL 10

class COMPRESSOR {
    public:
        COMPRESSOR();
        COMPRESSOR(unsigned int type);
        ~COMPRESSOR();

        long unsigned int call_method(char* in, unsigned int hFileSize, char* out) const; 
    private:
        static long unsigned int const compress_with_brieflz(char* in, unsigned int hFileSize, char* out);

        unsigned int type;
        using COMPRESSION_METHODS = const long unsigned int (*)(char*, unsigned int, char*);
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
