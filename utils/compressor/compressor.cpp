#include <iostream>
#include <windows.h>
#include "compressor.h"
using namespace std;

COMPRESSOR::COMPRESSOR() {
    throw COMPRESSOR_EXCEPTION("[!] Error: A type must be specified in order to use the compressor\n");
}
COMPRESSOR::COMPRESSOR(unsigned int type){
    if(type >= NUMBER_OF_COMPRESSORS) {
        throw COMPRESSOR_EXCEPTION("[!] Error: Compressor type must be within accepted range\n");
    }
    this->type = type;
}
COMPRESSOR::~COMPRESSOR() {

}
long unsigned int COMPRESSOR::call_method(char* in, unsigned int hFileSize, char* out) const {
    return (methods[type])(in, hFileSize, out);
}
// accepted methods implemented so far
long unsigned int const COMPRESSOR::compress_with_brieflz(char* in, unsigned int hFileSize, char* out) {
    printf("[+] Hello from compressor method\n");
    // compress data using brieflz
    //
    // get bound on compressed data size
    long unsigned int max_packed_size = blz_max_packed_size(hFileSize);
    printf("%ld\n", max_packed_size);
    if(!max_packed_size) {
        throw COMPRESSOR_EXCEPTION("[!] Error: brieflz: Maximum packed size is invalid\n");
    }
    out = (char*) malloc(max_packed_size * sizeof(char));
    if(!out) {
        throw COMPRESSOR_EXCEPTION("[!] Error: brieflz: Could not allocate output buffer\n");
    }
    //get required size for temporary buffer 'workmem'
    long unsigned int workmem_size_level = blz_workmem_size_level(hFileSize, BRIEFL_COMPRESSION_LEVEL);
    if(!workmem_size_level) {
        throw COMPRESSOR_EXCEPTION("[!] Error: brieflz: Workmem size buffer is invalid\n");
    }
    char* workmem = (char*) malloc(workmem_size_level * sizeof(char));
    if(!workmem) {
        throw COMPRESSOR_EXCEPTION("[!] Error: briefl: Could not allocate workmem buffer\n");
    }
    // compress data
    long unsigned int compressed_size = blz_pack_level(in, out, hFileSize, workmem, BRIEFL_COMPRESSION_LEVEL);
    return compressed_size;
}

