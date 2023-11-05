@echo off

g++ -c parser.cpp -o parser
g++ -c main.cpp -o main
g++ parser main -o packer

packer.exe ..\..\..\work\setup-lightshot.exe
