#pragma once
#include "brieflz.h"

#define NUMBER_OF_COMPRESSORS 1
#define BRIEFL_COMPRESSION_LEVEL 10

#define DELETE_DATA(x) do { if (x) { free(x); x = NULL; } } while(0)

typedef struct _COMPRESSED {
    char* content;
    long unsigned int size;
} COMPRESSED;


class COMPRESSOR {
    public:
        COMPRESSOR();
        COMPRESSOR(unsigned int type);
        ~COMPRESSOR();

         COMPRESSED* call_method(char* in, unsigned int hFileSize) const; 
    private:
        static COMPRESSED* const compress_with_brieflz(char* in, unsigned int hFileSize);

        unsigned int type;
        using COMPRESSION_METHODS = COMPRESSED* const (*)(char*, unsigned int);
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
