CC = g++
CFLAGS = -m64 -g -std=c++11 -pthread -c -Wall -Werror
LDFLAGS = 

EFLAGS = -I$(EXTERN_DIR)
EXTERN_DIR = extern/lz4/lib
SOURCE_DIR = 

OBJ = packer.o createFile.o

enigma : $(OBJ)
		$(CC) $(LDFLAGS) $(OBJ) -o enigma

packer.o : 
		$(CC) $(CFLAGS) $(EFLAGS) $(SOURCE_DIR)packer.cpp -o packer.o

createFile.o : 
		$(CC) $(CFLAGS) $(SOURCE_DIR)createFile.cpp -o createFile.o

clean :
		rm -rf $(OBJ) enigma

