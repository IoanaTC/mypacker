CC = cl
LINK = link

LISTING_FILES = saved_listing_file
MAP_FILE = map_file

# compiler and linker flags
CFLAGS = /DDEFINE_MACRO /FAcs /Fa$(LISTING_FILES) /MT /GR- /EHs-c- 
LFLAGS = kernel32.lib /NODEFAULTLIB /MAP:$(MAP_FILE) /INCREMENTAL:NO /ALIGN:0x10 /FILEALIGN:0x10

# source files
SRCS = stub.cpp
OBJS = $(SRCS:.cpp=.obj)

# output DLL
DLL = stub.dll

# default target
all: $(DLL)

# build rule for object files
%.obj: %.cpp
	$(CC) /c $(CFLAGS) $<

# link rule for building the DLL
$(DLL): $(OBJS)
	$(LINK) /DLL $(LFLAGS) /OUT:$(DLL) $(OBJS)

clean:
	rm *.obj $(DLL)
