#pragma once

#define DELETE_DATA(x) do { if (x) { free(x); x = NULL; } } while(0)

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
