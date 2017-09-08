//
// Created by vytautas on 7/26/17.
//

#ifndef SGX_NETTING_UTIL_H
#define SGX_NETTING_UTIL_H

#ifdef ENCLAVE
#include "outside.h"
#else
#include <stdint.h>
#include <stdio.h>
#endif

inline void print_key(const char* tag, uint8_t* key)
{
    printf(tag);
    for(int i=0;i<32;i++){
        printf("%02x", key[i]);
    }
    printf("\n");
}

inline void print_raw(const void* data_, uint32_t data_size)
{
    const uint8_t* data = (uint8_t*)data_;
    for(int i=0;i<data_size;i+=16) {
        printf(" 0x%03x | ", i);
        for (int j = 0; j < 16 && i + j < data_size; j++) {
            printf("%02x ", data[i + j]);
        }
        printf("\n");
    }

}

#ifndef ENCLAVE
#include <iostream>
inline ostream& operator <<(ostream& os, const ClearedTrade& t){
    return os << t.party->scheme << '~' << t.party->value << " "
              << t.counter_party->scheme << '~' << t.counter_party->value << " "
              << t.value;
}

template<class T>
inline ostream& operator <<(ostream& os, const vector<T>& vec){
    for (int i = 0; i < vec.size(); ++i) {
        os << i << " - " << vec[i] << "\n";
    }
    return os;
}

#include <sstream>
template<typename Out>
inline void split(const std::string &s, char delim, Out result) {
    std::stringstream ss;
    ss.str(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
        *(result++) = item;
    }
}


inline std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}
#endif

#endif //SGX_NETTING_UTIL_H
