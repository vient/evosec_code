#include <iostream>
#include <fstream>
#include <vector>

#include "engine.h"
#include <cstdio>

typedef unsigned char BYTE;

std::vector<BYTE> readFile(const char* filename)
{
    std::ifstream file(filename, std::ios::binary);

    return std::vector<BYTE>((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
}

using namespace std;

int main()
{
    char* filename = "malware.exe";
    vector<BYTE> input = readFile(filename);
    Engine e("/Users/emilchess/evosec_code");
    string res = e.Check(input);
    cout << res;
    return 0;
}
