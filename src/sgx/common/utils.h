//
// Created by fanz on 9/20/17.
//

#ifndef PROJECT_UTILS_H
#define PROJECT_UTILS_H

#include <stdlib.h>
#include <string>
#include <vector>

void byte_swap(unsigned char *data, int len);

void hd(const char *title, void const *data, size_t len);

std::string bin2hex(const unsigned char *bin, size_t len);
void hex2bin(unsigned char *dest, const char *src);
std::vector<unsigned char> hex2bin(const char *src);

#endif //PROJECT_UTILS_H
