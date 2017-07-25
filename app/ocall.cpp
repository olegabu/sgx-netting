//
// Created by vytautas on 7/27/17.
//

#include <cstdio>
#include "enclave_u.h"

void* ocall_malloc(uint32_t size)
{
    return malloc(size);
}
int ocall_print_string(const char *str)
{
    return (int)fwrite(str, 1, strlen(str), stdout);
}