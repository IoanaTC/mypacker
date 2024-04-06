CC = g++
CFLAGS = -m64 -g -std=c++11 -pthread -c -Wall -Werror
LDFLAGS = 

EFLAGS = -I$(EXTERN_DIR)
EXTERN_DIR = extern/cxxopts/include
SOURCE_DIR = src/

OBJ = main.o parser.o

enigma : $(OBJ)
		$(CC) $(LDFLAGS) $(OBJ) -o enigma

main.o : 
		$(CC) $(CFLAGS) $(EFLAGS) $(SOURCE_DIR)main.cpp -o main.o

parser.o : 
		$(CC) $(CFLAGS) $(SOURCE_DIR)parser.cpp -o parser.o

clean :
		rm -rf $(OBJ) enigma

