@echo off
rm dump.exe compressed.exe decompressed.exe enigma.exe stub.dll 
make
enigma.exe --in samples\calc.exe
dump.exe
