#ifndef MD5_H
#define MD5_H

#include <string>
#include <vector>
#include <openssl/md5.h>

std::string md5(const std::vector<unsigned char> &file) {
    unsigned char digest[MD5_DIGEST_LENGTH];

    MD5((unsigned char*)file.data(), file.size(), (unsigned char*)&digest);
    char mdString[32];
    for (int i = 0; i < 16; i++)
        sprintf(&mdString[i*2], "%02x", (unsigned int)digest[i]);
    return std::string(mdString);
}

#endif
