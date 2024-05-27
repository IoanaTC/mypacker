#pragma once
#define GENERIC_FILENAME "packed"
#define MINIMUM_FILESIZE 0x170 // calculate programatically

class CREATE_FILE {
    public:
        CREATE_FILE(): filename(NULL), filesize(0), content(NULL) {};
        ~CREATE_FILE();

        bool fillPackedFile();
        static constexpr const char generic_filename[8] = GENERIC_FILENAME;
        static constexpr unsigned int minimum_filesize = MINIMUM_FILESIZE;
    private:
        char* filename;
        unsigned int filesize;
        char* content;
};
