#include <iostream>
#include <fstream>
#include <vector>
#include <string>

#include "engine.h"
#include <cstdio>

typedef unsigned char BYTE;

std::vector<BYTE> readFile(char *filename)
{
    std::ifstream file(filename, std::ios::binary);

    return std::vector<BYTE>((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
}



int main(int argc, char *argv[])
{
    Engine engine("/Users/emilchess/evosec_code");
    for (int i = 1; i < argc; i++) {
        std::vector<BYTE> inputFile = readFile(argv[i]);
        std::string verdict = engine.Check(inputFile);
        std::cout << argv[i] << " " << verdict << "\n";
    }
    return 0;
}
