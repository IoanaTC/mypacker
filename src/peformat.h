#ifndef PE_FILE_FORMAT_H
#define PE_FILE_FORMAT_H
//
//types library
//
#include <cstdint>
#include <windows.h>
//
// format definitions
//
typedef uint64_t QWORD;
//
#define _IMAGE_MZ_SIGNATURE 0x5A4D
#define _IMAGE_PE_SIGNATURE 0x4550
#define _IMAGE_NT_HDR32_MAGIC 0x10B
#define _IMAGE_NT_HDR64_MAGIC 0x20B
//
#define _IMAGE_DATA_DIRECTORY_NUMBEROF_ENTRIES 16
//
#define _IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define _IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define _IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define _IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define _IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define _IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define _IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define _IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define _IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define _IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define _IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define _IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define _IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define _IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define _IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
//
// PE file format structure - define components
//
// DOS header
//
typedef struct __IMAGE_DOS_HEADER 
{
    WORD e_magic;       // dos file magic: MZ
                        //
    WORD e_cblp;        // count bytes last page
    WORD e_cp;          // count pages
    WORD e_crlc;        // count relocations
    WORD e_cparhdr;     // count paragraphs in header
    WORD e_minalloc;    // minimum extra paragraphs needed
    WORD e_maxalloc;    // maximum extra paragraphs needed
    WORD e_ss;          // SS value (stack segment)
    WORD e_sp;          // SP value (stack pointer)
    WORD e_csum;        // checksum
    WORD e_ip;          // IP value (instruction pointer)
    WORD e_cs;          // CS value 
    WORD e_lfarlc;      // file address relocation table
    WORD e_ovno;        // overlay number
    WORD e_res[4];      // reserved words
    WORD e_oemid;       // OEM identifier
    WORD e_oeminfo;     // OEM information
    WORD e_res2[10];    // reserved words
                        //
    LONG e_lfanew;      // file address of new exe header

}___IMAGE_DOS_HEADER, *___PIMAGE_DOS_HEADER;
//
// DOS STUB
//
#define __IMAGE_DOS_STUB BYTE*
//
//
// IMAGE_FILE_HEADER
//
typedef struct __IMAGE_FILE_HEADER {     

    WORD    Machine;     
    WORD    NumberOfSections;     
    DWORD   TimeDateStamp;     
    DWORD   PointerToSymbolTable;     
    DWORD   NumberOfSymbols;     
    WORD    SizeOfOptionalHeader;     
    WORD    Characteristics; 

} ___IMAGE_FILE_HEADER, *___PIMAGE_FILE_HEADER;
//
//
// IMAGE DATA DIRECTORY
//
typedef struct __IMAGE_DATA_DIRECTORY {

    DWORD   VirtualAddress;
    DWORD   Size;

} ___IMAGE_DATA_DIRECTORY, *___PIMAGE_DATA_DIRECTORY;
//
//
// IMAGE OPTIONAL HEADER 32
//
typedef struct __IMAGE_OPTIONAL_HEADER32 {

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;

    ___IMAGE_DATA_DIRECTORY DataDirectory[_IMAGE_DATA_DIRECTORY_NUMBEROF_ENTRIES];

} ___IMAGE_OPTIONAL_HEADER32, *___PIMAGE_OPTIONAL_HEADER32;
//
// IMAGE OPTIONAL HEADER 64
//
typedef struct __IMAGE_OPTIONAL_HEADER64 {

    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;

    ___IMAGE_DATA_DIRECTORY DataDirectory[_IMAGE_DATA_DIRECTORY_NUMBEROF_ENTRIES];

} ___IMAGE_OPTIONAL_HEADER64, *___PIMAGE_OPTIONAL_HEADER64;
//
//
// NT Headers
//
typedef struct __IMAGE_NT_HEADERS 
{
    DWORD Signature;
    ___IMAGE_FILE_HEADER FileHeader;
    ___IMAGE_OPTIONAL_HEADER32 OptionalHeader;

}___IMAGE_NT_HEADERS32, *___PIMAGE_NT_HEADERS32;
//
typedef struct __IMAGE_NT_HEADERS64 
{
    DWORD Signature;
    ___IMAGE_FILE_HEADER FileHeader;
    ___IMAGE_OPTIONAL_HEADER64 OptionalHeader;

} ___IMAGE_NT_HEADERS64, *___PIMAGE_NT_HEADERS64;
//
//
// Section Header
//
#define ___IMAGE_SIZEOF_SHORT_NAME 8
//
typedef struct __IMAGE_SECTION_HEADER {

    BYTE    Name[___IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD   PhysicalAddress;
        DWORD   VirtualSize;
    } Misc;

    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;

} ___IMAGE_SECTION_HEADER, * ___PIMAGE_SECTION_HEADER;     
#endif
