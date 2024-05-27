CC = g++
CFLAGS = -m64 -g -std=c++11 -pthread -c -Wall -Werror
LDFLAGS = 

EFLAGS = $(foreach dir,$(EXTERN_DIRS),-I$(dir))
EXTERN_DIRS = extern/brieflz/include extern/cxxopts/include

SOURCE_DIR = src
PACKER_DIR = packer
UTILS_DIR_PE = utils/pe

OBJ_CLEAN = main.o parser.o packer.o
OBJ = main.o packer.o

enigma : $(OBJ)
		@echo "Building final executable file..."
		$(CC) $(LDFLAGS) $(OBJ) -o enigma
		rm -rf $(OBJ_CLEAN)

main.o : 
		@echo "Compiling main.cpp..."
		$(CC) $(CFLAGS) $(EFLAGS) -I$(PACKER_DIR) $(SOURCE_DIR)/main.cpp -o main.o

packer.o : parser.o
		@echo "Compiling the packer..."
		$(CC) $(CFLAGS) $(EFLAGS) $(PACKER_DIR)/packer.cpp -o packer.o

parser.o : 
		@echo "Compiling the parser..."
		$(CC) $(CFLAGS) $(UTILS_DIR_PE)/parser.cpp -o parser.o

clean :
		@echo "Cleaning object files..."
		rm -rf $(OBJ_CLEAN) enigma


