#pragma once

#define BOILERPLATE "utils/boilerplate/boilerplate"
#define DATA_DIRECTORY_OFFSET_TINY_PE 0x8C
#define COMPRESSED_DATA_DIRECTORY 0x8
#define STUB_DATA_DIRECTORY 0x8
#define STUB_SIZE 0x10

class PACKER {
    public:
        PACKER();
        PACKER(HANDLE hFile);
        ~PACKER();

        bool packfile();
    private:
        HANDLE hFile;
        unsigned int hFileSize;
};

typedef class _PACKER_EXCEPTION : public std::exception 
{
    private:

        std::string errorMessage;

    public:
        explicit _PACKER_EXCEPTION(const char* error) : errorMessage(error) {} 
        _PACKER_EXCEPTION()=delete;

        virtual ~_PACKER_EXCEPTION() noexcept = default;

        const char* what() const noexcept override {
            return errorMessage.c_str();
        }
}PACKER_EXCEPTION;
