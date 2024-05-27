#include <iostream>
#include <windows.h>
#include "compressor.h"
using namespace std;

COMPRESSOR::COMPRESSOR() {
    throw COMPRESSOR_EXCEPTION("[!] Error: A type must be specified in order to use the compressor\n");
}
COMPRESSOR::COMPRESSOR(unsigned int type){
    if(!type || type >= NUMBER_OF_COMPRESSORS) {
        throw COMPRESSOR_EXCEPTION("[!] Error: Compressor type must be within accepted range\n");
    }
    this->type = type;
}
COMPRESSOR::~COMPRESSOR() {

}
bool COMPRESSOR::call_method(HANDLE hFile, unsigned int hFileSize) const {
    return (this->methods[type])(hFile, hFileSize);
}
// accepted methods implemented so far
bool const COMPRESSOR::compress_with_brieflz(HANDLE hFile, unsigned int hFileSize) {
    return true;
}

