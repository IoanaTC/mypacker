#include <iostream>
#include <windows.h>
#include "packer.h"
#include "compressor.h"
#include "parser.h"
using namespace std;

PACKER::PACKER() {
    throw PACKER_EXCEPTION("[!] Error: There is no file handle given to the constructor\n");
}
PACKER::PACKER(HANDLE hFile) {
    this->hFile = hFile;
    // get hFile ssize
    unsigned int filesize = GetFileSize(hFile, /* lpFileSizeHigh = */ NULL);
    if(filesize == INVALID_FILE_SIZE) {
        throw PACKER_EXCEPTION("[!] Error: Could not compute handle file size\n");
    }
    this->hFileSize = filesize;
}
PACKER::~PACKER() {
   printf("[+] PACKER: destructor has been called\n"); 
}
bool PACKER::packfile() {
    printf("[+] Hello\n");
    HANDLE hMapping = CreateFileMapping(hFile, 0, PAGE_READWRITE, 0, 0, NULL);
    if(!hMapping) {
        cout<<GetLastError()<<endl;
        printf("[!] Error: PACKED: Cannot create file mapping from given input\n");
        return false;
    }
    char* mappedImage = (char*) MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if(!mappedImage) {
        printf("[!] Error: PACKED: Cannot get map view of input file\n");
        return false;
    }
    // get mapped size TODO
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(mappedImage, &mbi, sizeof(mbi))) {
        printf("[!] Error: PACKED: Cannot get map view of input file size\n");
        return false;
    }
    if(!CloseHandle(hMapping)) {
        printf("[!] Error: Cannot close hMapping handle\n");
        return false;
    }
    // initialize the chosen compressor, use the wrapper
    // initialize compressor, type = 0 ( could be variable in the future )
    COMPRESSOR compressor(0);
    COMPRESSED* out = NULL;
    try {
        out = compressor.call_method(mappedImage, mbi.RegionSize);
        char* src = (char*) malloc(hFileSize * sizeof(char));
        unsigned long size = blz_depack_safe(out->content, out->size, src, hFileSize);
        printf("%ld\n", size);

        if(!out->size) {
            throw PACKER_EXCEPTION("[!] Error: Compression method could not be called properly\n");
        }
        // debugging
        printf("compressed size = %ld\n", out->size);
        printf("original size = %d\n", hFileSize);
        // get boilerplate PE and insert the compressed data into the data section
        // TODO: parse PE, get only the necessary information
        //
        // get this PE form from this exes own resource section
        HMODULE hModule = GetModuleHandle(NULL);
        if(!hModule) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get this process current loaded module\n");
        }
        long unsigned int resource_size = 0;
        HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(IDR_RES), RT_RCDATA);
        if(!hResource)  {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get current module's requested resource\n");
        }
        HGLOBAL hResData = LoadResource(hModule, hResource);
        if(!hResData) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not load requested resource\n");
        }
        resource_size = SizeofResource(hModule, hResource);
        if(!resource_size) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get resource size\n");
        }
        unsigned char* resource_data = (unsigned char *) LockResource(hResData);
        if(!resource_data) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not get resource data\n");
        }

        HANDLE hDump = CreateFile("dump.exe", GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if(hDump == INVALID_HANDLE_VALUE) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not create packed file dump handle\n");
        }
        // append decompressing stub
        long unsigned int bytes = 0;
        if(!WriteFile(hDump, resource_data, resource_size, &bytes, NULL)) {
            if(!CloseHandle(hDump)) {
                printf("[!] Error: Could not close hDump handle\n");
            }
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not dump adjusted tinyPE\n");
        }
        // make sure data is written on disk
        FlushFileBuffers(hDump);
        // move the file pointer to the beginning of the file
        SetFilePointer(hDump, 0, NULL, FILE_BEGIN);

        // insert new section with compressed data within resource data (packedfile)
        // modify sectionheader
        // add section
        PE_PARSER* parser = new PE_PARSER(hDump);
        if(!parser) {
            if(!CloseHandle(hDump)) {
                printf("[!] Error: Could not close hDump handle\n");
            }
            throw PACKER_EXCEPTION("[!] Error: PACKED Could not allocate PE parser instance\n");
        }
        if(!parser->parsePE()) {
            if(!CloseHandle(hDump)) {
                printf("[!] Error: Could not close hDump handle\n");
            }
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not parse resource pe\n");
        }
        // the parser extracted all the useful information from the boilerplate executable
        //
        // get the overlay position, either use the ACT (Attribute Certificate Table) or the filesize
        unsigned int act_offset = parser->NT_HEADERS64.OptionalHeader.DataDirectory[_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress; 
        if(!act_offset) {
            act_offset = GetFileSize(hDump, NULL);
            if(act_offset == INVALID_FILE_SIZE) {
                throw PACKER_EXCEPTION("[!] Error: PACKED: could not get packed file filesize\n");
            }
        }
        // get size of entire content, up to the beginning of the overlay
        unsigned int sections_size = act_offset - parser->sections_offset;
        // get number of sections
        unsigned int numberofSections_old = parser->NT_HEADERS64.FileHeader.NumberOfSections;
        unsigned int i = 0, j = 0, sections_used = 0;
        // set file alignment on disk and in-memoru alignment to suit the concept of tinyPE
        // sectionalign is equal with to e_lfanew due to mz header collapsing
        // and filealign must be minimum sectionalign
        unsigned int fileAlignment = 4;
        unsigned int sectionAlignment = 4;
        // set file alignment on disk and in-memory section alignment
        parser->NT_HEADERS64.OptionalHeader.FileAlignment = fileAlignment;
        parser->NT_HEADERS64.OptionalHeader.SectionAlignment = sectionAlignment;
        // check if all sections are being used, and store away the coresponding virtual addresses
        // adjust sections offsets according to the new alignment
        unsigned int fa_old[numberofSections_old] = {0};
        unsigned int va_old[numberofSections_old] = {0};
        for(; i < numberofSections_old; i++) {
            fa_old[i] = parser->SECTIONS[i].PointerToRawData;
            va_old[i] = parser->SECTIONS[i].VirtualAddress;

            if(!parser->SECTIONS[i].PointerToRawData) continue;

            parser->SECTIONS[i].PointerToRawData = ((fa_old[i] + (fileAlignment - 1)) / fileAlignment) * fileAlignment;
            parser->SECTIONS[i].VirtualAddress = ((va_old[i] + (sectionAlignment - 1)) / sectionAlignment) * sectionAlignment;
            sections_used += 1;
        }
        // adjust the section number to resemble the sections currently in use, and the one added by the packer
        parser->NT_HEADERS64.FileHeader.NumberOfSections = sections_used;
        // adjust the size of image as well
        //int sections_delta = sections_used + 1 - numberofSections_old;
        //parser->NT_HEADERS64.OptionalHeader.SizeOfImage += ((sections_delta > 0) ? sections_delta : - sections_delta) * sizeof(__IMAGE_SECTION_HEADER);

        // get offset and virtual address of new section
        ___IMAGE_SECTION_HEADER* lastSectionHeader = &parser->SECTIONS[sections_used - 1];
        unsigned int newSectionOffset = lastSectionHeader->PointerToRawData + lastSectionHeader->SizeOfRawData;
        printf("newSectionOffset %016X\n",newSectionOffset);

        unsigned int newSectionVirtualAddress = lastSectionHeader->VirtualAddress + lastSectionHeader->Misc.VirtualSize;
        // round-up the offsets to support alignment
        newSectionOffset = ((newSectionOffset + (fileAlignment - 1)) / fileAlignment) * fileAlignment;
        printf("newSectionOffset aligned %016X\n",newSectionOffset);
        newSectionVirtualAddress = ((newSectionVirtualAddress + (sectionAlignment - 1)) / sectionAlignment) * sectionAlignment;

        // create new section header
        ___IMAGE_SECTION_HEADER newSectionHeader = {0};
        char sectionName[IMAGE_SIZEOF_SHORT_NAME] = ".enigma";
        strncpy((char*)newSectionHeader.Name, sectionName, IMAGE_SIZEOF_SHORT_NAME - 1);
        newSectionHeader.Misc.VirtualSize = out->size;
        newSectionHeader.VirtualAddress = newSectionVirtualAddress;
        newSectionHeader.SizeOfRawData = out->size;
        newSectionHeader.PointerToRawData = newSectionOffset;
        newSectionHeader.PointerToRelocations = out->original_size /*mbi.RegionSize*/ /* hFileSize */ ;
        newSectionHeader.Characteristics = IMAGE_SCN_MEM_READ;

        printf("%s\n", newSectionHeader.Name);
        printf("%016lX\n", newSectionHeader.Misc.VirtualSize);
        printf("%016lX\n", newSectionHeader.VirtualAddress);
        printf("%016lX\n", newSectionHeader.SizeOfRawData);
        printf("%016lX\n", newSectionHeader.PointerToRawData);
        printf("%016lX\n", newSectionHeader.Characteristics);
        
        // alloc and memset 0 buffer for packed file reorganized content
        /*
        unsigned int packedSize = sizeof(MZ_HEADER) + sizeof(___IMAGE_NT_HEADERS64) + 
                    + (sections_used + 1) * sizeof(___IMAGE_SECTION_HEADER)
                    + sections_size
                    + out->size
                    + 0x100;
        */
        unsigned int packedSize = newSectionVirtualAddress + out->size + 0x10 /*sizeof(___IMAGE_SECTION_HEADER)*/;
        parser->NT_HEADERS64.OptionalHeader.SizeOfImage = newSectionVirtualAddress + out->size + 0x10 /*sizeof(___IMAGE_SECTION_HEADER)*/;

        char* packedFile = (char*) calloc(packedSize, sizeof(char));
        if(!packedFile) {
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not allocate packed file content bbuffer\n");
        }
        printf("act: %d, sec_size: %d, sec_off:%ld\n", act_offset, sections_size, parser->sections_offset);

        // populate the packed file
        FlushFileBuffers(hDump);
        // move the file pointer to the beginning of the file
        SetFilePointer(hDump, 0, NULL, FILE_BEGIN);

        unsigned int offset = 0;
        // place MZ header + null dword
        *(DWORD*) (packedFile) = MZ_HEADER;
        // place NT_header
        memcpy((packedFile + sizeof(DWORD)), &(parser->NT_HEADERS64), sizeof(___IMAGE_NT_HEADERS64));
        offset = sizeof(DWORD) + sizeof(___IMAGE_NT_HEADERS64);

        i = 0;
        for(; i < numberofSections_old; i++) {
            if(!parser->SECTIONS[i].SizeOfRawData) {
                continue;
            }
            memcpy((packedFile + offset + j * sizeof(___IMAGE_SECTION_HEADER)), &(parser->SECTIONS[i]), sizeof(___IMAGE_SECTION_HEADER));
            j++;
        }
        memcpy((packedFile + offset + j * sizeof(___IMAGE_SECTION_HEADER)), &newSectionHeader, sizeof(___IMAGE_SECTION_HEADER));

        offset = offset + j * sizeof(___IMAGE_SECTION_HEADER);

        for(unsigned int i = 0; i < numberofSections_old; i++) {
            if(!parser->SECTIONS[i].SizeOfRawData) continue;
            printf("pointerraw: %ld, pointerraw2: %d, size3: %ld\n",parser->SECTIONS[i].PointerToRawData, fa_old[i], parser->SECTIONS[i].SizeOfRawData );
            memcpy((packedFile + parser->SECTIONS[i].PointerToRawData), 
                    (parser->content + (fa_old[i] - parser->sections_offset)),
                    parser->SECTIONS[i].SizeOfRawData); //VirtualSize
        }
        printf("newsectionva: %d\n", newSectionOffset);
        memcpy((packedFile + newSectionOffset), out->content, out->size);

        // move the file pointer to the beginning of the file
        SetFilePointer(hDump, 0, NULL, FILE_BEGIN);

        if(!WriteFile(hDump, packedFile, packedSize, &bytes, NULL)) {
            if(!CloseHandle(hDump)) {
                printf("[!] Error: Could not close hDump handle\n");
            }
            throw PACKER_EXCEPTION("[!] Error: PACKED: Could not dump adjusted tinyPE\n");
        }
        printf("packed_size: %d\n", packedSize);
        
    } catch(const PACKER_EXCEPTION &e) {
        printf("[!] Error: PACKED: An exception has occurred durng file compression: \n%s", e.what());
        DELETE_DATA(mappedImage);
        DELETE_DATA(out);

        return false;
    }
    printf("a ajuns aici 3\n");
    return true;
}
