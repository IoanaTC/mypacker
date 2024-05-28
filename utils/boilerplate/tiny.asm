; tiny.asm
BITS 64
;
; MZ HEADER
;
; 16bit architecture
; The only two fields that matter are e_magic and e_lfanew
mzhdr:
    dw "MZ"            ; e_magic -> magic number 0x4D5A
    dw 0               ; e_cblp UNUSED -> bytes on the last page of file
;
; I collapsed the MZ header, and set the section alignmet to be 4, because there will the e_lfanew value located inside the optional header
; Section alignment needs to be minimum 4, for the loader to execute it, though the docs stated the header to be 8-byte aligned
;
; The DOS Stub has been removed as it is not being used
;
; PE Signature
;
pesig:
    dd "PE"
;
; PE File Header
;
IMAGE_FILE_MACHINE_AMD64 equ 0x8664
;
csections equ 3
;
IMAGE_FILE_32BIT_MACHINE equ 0x0100
RESERVED_FLAG equ 0x0040
;
IMAGE_FILE_DEBUG_STRIPPED equ 0x0200
IMAGE_FILE_LARGE_ADDRESS_AWARE equ 0x0020
IMAGE_FILE_EXECUTABLE_IMAGE equ 0x0002
;
characteristics equ IMAGE_FILE_DEBUG_STRIPPED | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_EXECUTABLE_IMAGE
;
pehdr:
    dw IMAGE_FILE_MACHINE_AMD64
    dw csections      ; NumberofSections
    dd 0x3CF2F4A0     ; TimeDateStamp UNUSED 
    dd 0              ; PointerTOSymbolTable UNUSED
    dd 0              ; NumberOfSymbols UNUSED
    dw opthdrsize     ; SizeOfOptionalHeader (either 32b -> 31 fileds, or 64b -> 30 fields)
    dw characteristics; Characteristics filed of the file header
;
; PE Optional Header
;
filealign equ 4 ; it needs to be 4, because it has to be minimum the page size
sectionalign equ 4 ; it needs to be 4, in order to have e_lfanew detected as 4
;
%define round(n, r) (((n+(r-1))/r)*r) ; the biggest multiple of r smaller than n
;
PE64 equ 0x20b
PE32 equ 0x10b
;
IMAGE_PREFERRED_BASE equ 0x400000
;
MAJOR_SUBSYSTEM_VERSION_NT equ 4
IMAGE_SUBSYSTEM_WINDOWS_GUI equ 2
;
opthdr:
    dw PE64 
    db 0            ; MajorLinkerVersion UNUSED
    db 0            ; MinorLinkerVersion UNUSED
    dd round(codesize, filealign); SizeOfCode UNUSED
    dd 0            ; SizeOfInitializedData UNUSED
    dd 0            ; SizeOfUninitializedData UNUSED
    dd entry_point  ; AddressOfEntryPoint
    dd code         ; BaseOfCode UNUSED
;    dd round(filesize, sectionalign); BaseOfData UNUSED -> only on 32bit executables
    dq IMAGE_PREFERRED_BASE
;
    dd sectionalign ; e_lfanew   ; SectionAlignment (in memory, usually the size of a page 4KB)
;
    dd filealign    ; FileAlignment (sections alignment on disk, usually a disk sector 512B)  
    dw 0            ; MajorOperatingSystemVersion UNSUED
    dw 0            ; MinorOperatingSystemVersion UNUSED
    dw 0            ; MajorImageVersion UNUSED
    dw 0            ; MinorIMageVersion UNUSED
    dw MAJOR_SUBSYSTEM_VERSION_NT
    dw 0            ; MinorSubsytemVersion UNUSED
    dd 0            ; Win32VersionValue UNUSED
    dd round(filesize, sectionalign) ; SizeOfImage
    dd round(hdrsize, filealign)  ; SizeOfHeaders
    dd 0            ; Checksum UNUSED
    dw IMAGE_SUBSYSTEM_WINDOWS_GUI
    dw 0            ; DllCharacteristics UNUSED
    dq 0x100000     ; SizeOfStackReserve UNUSED
    dq 0x10000      ; SizeOfStackCommit 
    dq 0x100000     ; SizeOfHeapReserve
    dq 0x10000      ; SizeOfHeapCommit UNUSED
    dd 0            ; LoaderFlags UNUSED
    dd 0            ; NumberOfRvaAndSizes UNUSED -> number of data directories (there are 16 of them)
;
; Data Directories
;
    times 16 dd 0, 0
opthdrsize equ $ - opthdr
;
; Section Header
;
; PE code section
;
text:
    db ".text", 0, 0, 0
    dd codesize    ; VirtualSize
    dd round(hdrsize, sectionalign) ; VirtualAddress
    dd round(codesize, filealign); SizeOfRawData
    dd code                      ; PointerToRelocations UNSUED
    dd 0                         ; PointerToRawData UNUSED
    dd 0                         ; PointerToLineNmbers UNUSED (for debugging)
    dw 0                         ; NumberOfRelocations UNUSED
    dw 0                         ; NumberOfLineNumbers UNUSED
    dd 0x60000020                ; Characteristics UNUSED (code, execute, read)
;
data:
    db ".comp", 0, 0, 0        ; Section Name
    dd 0 ; VirtualSize
    dd round(hdrsize, sectionalign) + round(codesize, filealign) ; VirtualAddress
    dd 0 ;SizeOfRawData
    dd round(hdrsize, sectionalign) + round(codesize, filealign)  ; PointerToRawData
    dd 0                       ; PointerToRelocations
    dd 0                       ; PointerToLinenumbers
    dw 0                       ; NumberOfRelocations
    dw 0                       ; NumberOfLinenumbers
    dd 0xC0000040              ; Characteristics (initialized data, read, write)
;
rsrc:
    db ".stub", 0, 0, 0        ; Section Name
    dd 0                       ; VirtualSize
    dd round(hdrsize, sectionalign) + round(codesize, filealign) ; VirtualAddress
    dd 0                       ; SizeOfRawData
    dd 0                       ; PointerToRawData
    dd 0                       ; PointerToRelocations
    dd 0                       ; PointerToLinenumbers
    dw 0                       ; NumberOfRelocations
    dw 0                       ; NumberOfLinenumbers
    dd 0x40000040              ; Characteristics (initialized data, read)
;
hdrsize equ $ - $$
;
; Pe code section data
;
align filealign, db 0
;
code:
entry_point:
    push byte 42
    pop rax
    ret
;
codesize equ $ - code
filesize equ $ - $$

