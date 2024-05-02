#include <windows.h>
#include <stdexcept>
#include <iostream>
#include <cstdio>
// cli parser external library
#include <cxxopts.hpp>
// project based imports
#include "packer.h"

using namespace std;

void displayLogo() {
   cout << R"(
            _                       
           (_)                      
  ___ _ __  _  __ _ _ __ ___   __ _ 
 / _ \ '_ \| |/ _` | '_ ` _ \ / _` |
|  __/ | | | | (_| | | | | | | (_| |
 \___|_| |_|_|\__, |_| |_| |_|\__,_|
               __/ |                
              |___/ )" << endl << endl;
}

int main(int argc, char ** argv) {
    
    const char* outputFile = "packed.exe";
    char * inputFile = NULL;

    try {
        cxxopts::Options options("enigma", "Simple packer for executables");                     

        options.add_options()                                                               
            ("h,help", "Display this help")                                                         
            ("in,input", "Choose an executable file to pack", cxxopts::value<string>())
            ("out,output", "Choose a suitable output for your packed file", cxxopts::value<string>()) 
            ;                                                                               

        auto result = options.parse(argc, argv); 

        if(result.count("help")) {
            displayLogo();

            cout<<options.help()<<endl;
            return EXIT_SUCCESS;
        }

        if(result.count("input")){

            string tempBuffer;
            tempBuffer = result["input"].as<string>();

            if(tempBuffer.empty()) {
                printf("[-] No input file was provided\n");
                return EXIT_FAILURE;
            }

            inputFile = (char*) malloc(tempBuffer.length() * sizeof(char));
            if (!inputFile) {
                printf("[-] Error: memory for input file could not be allocated\n");
                return EXIT_FAILURE;
            }

            memcpy(inputFile, tempBuffer.c_str(), tempBuffer.length()); 
            inputFile[tempBuffer.length()] = 0;

            printf("[+] Input file provided successfully: %s\n", inputFile);

        } else {

            printf("[-] No input file was provided\n");
            return EXIT_FAILURE;
        }

        if(result.count("output")){

            string tempBuffer;
            tempBuffer = result["output"].as<string>();

            if(tempBuffer.empty()) {
                printf("[-] No output file was provided, a default one will be created automatically\n");

                printf("[+] Outputfile created successfully\n");

            } else {
                
                outputFile = new char[tempBuffer.length()];

                if(!outputFile) {
                    printf("[-] Error: memory for output file culd not pe allocated\n");

                    if(inputFile) {
                        free(inputFile);
                        inputFile = NULL;
                    }
                    return EXIT_FAILURE;
                }
                strcpy(const_cast<char*>(outputFile), tempBuffer.c_str());

                printf("[+] Output file provided successfully\n");
            }

        } else {
            printf("[-] No output file was provided, a default one will be created automatically\n");

            printf("[+] Outputfile created successfully\n");
        }
    
        // packer call
        /*
        HANDLE executableFile = CreateFileA(inputFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if(executableFile == INVALID_HANDLE_VALUE) {

            printf("[!] Error: Could not open file, invalid.\n");

            if(inputFile) {
                free(inputFile);
                inputFile = NULL;
            }
            if(outputFile) {
                delete[] outputFile;
                outputFile = NULL;
            }
            return EXIT_FAILURE;
        }

        PE_PARSER PE_PARSER(executableFile);
        if(!PE_PARSER.parsePE()) {

            printf("[!] Error : Could not parse PE.\n");

            if(inputFile) {
                free(inputFile);
                inputFile = NULL;
            }
            if(outputFile) {
                delete[] outputFile;
                outputFile = NULL;
            }
            return EXIT_FAILURE;
        }
    */
    } catch (const exception& e) {
        printf("[-] Error: there was an exception registered during computation: %s\n", e.what());

        if(inputFile) {
            free(inputFile);
            inputFile = NULL;
        }
        if(outputFile) {
            delete[] outputFile;
            outputFile = NULL;
        }
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
