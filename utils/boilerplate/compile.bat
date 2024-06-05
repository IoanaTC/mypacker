@echo off
g++ -o packed.exe packed.cpp ..\..\stub\stub.res -s -nostdlib -nodefaultlibs -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables -Wl,--section-alignment,0x10 -Wl,--file-alignment,0x10 -Os -Wl,--subsystem=console -lkernel32

windres packed.rc -O coff packed.res
