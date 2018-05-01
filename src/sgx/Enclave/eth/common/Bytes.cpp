//
// Created by lilione on 2017/8/31.
//

#include <string>

#include "Bytes.h"

Bytes::Bytes(uint8_t value) {
    data.push_back(value);
}

Bytes Bytes::operator+ (const Bytes& other) {
    Bytes ret;
    for (int i = 0; i < this->data.size(); i++) {
        ret.data.push_back(this->data[i]);
    }
    for (int i = 0; i < other.data.size(); i++) {
        ret.data.push_back(other.data[i]);
    }
    return ret;
}

bool Bytes::operator== (const Bytes& other) {
    if (this->data.size() != other.data.size()) return 0;
    for (int i = 0; i < this->data.size(); i++) {
        if (this->data[i] != other.data[i]) return 0;
    }
    return 1;
}

bool Bytes::operator!= (const Bytes& other) {
    if (this->data.size() != other.data.size()) return 1;
    for (int i = 0; i < this->data.size(); i++) {
        if (this->data[i] != other.data[i]) return 1;
    }
    return 0;
}

void Bytes::operator= (const Bytes& other) {
    this->data = other.data;
}

Bytes Bytes::substr(int start, int end) {
    Bytes ret;
    for (int i = start; i < end; i++) {
        ret.data.push_back(data[i]);
    }
    return ret;
}

Bytes Bytes::substr(int start) {
    Bytes ret;
    for (int i = start; i < data.size(); i++) {
        ret.data.push_back(data[i]);
    }
    return ret;
}

/*void Bytes::output(Bytes byteArray) {
    for (int i = 0; i < byteArray.data.size(); i++) {
        printf("%d ", byteArray.data[i]);
    }
    printf("\n");
}*/

/*void Bytes::outputHex(Bytes byteArray) {
    for (int i = 0; i < byteArray.data.size(); i++) {
        printf("%02x", byteArray.data[i]);
    }
    printf("\n");
}*/