#pragma once

#define IDR_RES 102
#define MZ_HEADER 0x00005A4D
#define IMAGE_SCN_MEM_READ 0x40000000

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
