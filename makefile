CC = g++
CFLAGS = -m64 -g -std=c++17 -pthread -c -Wall -Werror
LDFLAGS = -static

EFLAGS = $(foreach dir,$(EXTERN_DIRS),-I$(dir))
EXTERN_DIRS = extern/brieflz/include extern/cxxopts/include
BRIEFL_LIB = extern/brieflz/build/Release/brieflz.lib

SOURCE_DIR = src
PACKER_DIR = packer
COMPRESSOR_DIR = utils/compressor
UTILS_DIR_PE = utils/pe

OBJ_CLEAN = main.o parser.o packer.o compressor.o
OBJ = main.o packer.o compressor.o parser.o

enigma : $(OBJ)
		@echo "Building final executable file..."
		$(CC) $(LDFLAGS) $(OBJ) $(BRIEFL_LIB) -I$(UTILS_DIR_PE) -o enigma
		rm -rf $(OBJ_CLEAN)

main.o : packer.o parser.o compressor.o
		@echo "Compiling main.cpp..."
		$(CC) $(CFLAGS) $(EFLAGS) -I$(PACKER_DIR) -I$(COMPRESSOR_DIR) -I$(UTILS_DIR_PE) $(SOURCE_DIR)/main.cpp -o main.o

packer.o : parser.o compressor.o
		@echo "Compiling the packer..."
		$(CC) $(CFLAGS) $(EFLAGS) -I$(COMPRESSOR_DIR) -I$(UTILS_DIR_PE) $(PACKER_DIR)/packer.cpp -o packer.o

compressor.o :
		@echo "Compiling the compressor..."
		$(CC) $(CFLAGS) $(EFLAGS) -I$(UTILS_DIR_PE) $(COMPRESSOR_DIR)/compressor.cpp -o compressor.o

parser.o : 
		@echo "Compiling the parser..."
		$(CC) $(CFLAGS) $(UTILS_DIR_PE)/parser.cpp -o parser.o

clean :
		@echo "Cleaning object files..."
		rm -rf $(OBJ_CLEAN) enigma


