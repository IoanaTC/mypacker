#ifndef PE_FILE_FORMAT_H
#define PE_FILE_FORMAT_H

//types library
#include <cstdint>
#include <windows.h>

typedef uint8_t BYTES;
typedef uint16_t WORD;
typedef uint64_t QWORD;

#define MZ_HEADER 0x5A4D

//PE file format structure - define components
//
//DOS header
/*
typedef struct _IMAGE_DOS_HEADER 
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
    
// LONG -> signed type, DWOD -> unsigned type (4 bytes)
// 
    LONG e_lfanew;      // file address of new exe header

}IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
*/
#endif