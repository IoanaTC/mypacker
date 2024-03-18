@echo off

g++ -c src/parser.cpp -o parser
g++ -c src/main.cpp -Iextern/cxxopts/include -o main 
g++ parser main -o enigma 

