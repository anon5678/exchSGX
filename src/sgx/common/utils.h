//
// Created by fanz on 9/20/17.
//

#ifndef PROJECT_UTILS_H
#define PROJECT_UTILS_H

#include <stdlib.h>
#include <string>

int char2int(char c);
void hex2bin(unsigned char *dest, const char *src);
void byte_swap(unsigned char *data, int len);
void hd(const char *title, void const *data, size_t len);
std::string bin2hex(const unsigned char *bin, size_t len);

#endif //PROJECT_UTILS_H
