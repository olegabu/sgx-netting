//
// Created by vytautas on 7/26/17.
//
/*
 * Functions related to state outside of enclave
 * ocalls here.
 */

#include "outside.h"

#include "enclave_t.h"
#include <sgx_trts.h>
#include <stdio.h>

void *out_malloc(uint32_t size) {
    void* ptr;
    sgx_status_t ret = ocall_malloc(&ptr, size);
    if(ret != SGX_SUCCESS || !sgx_is_outside_enclave(ptr, size))
        return 0;
    return ptr;
}

int printf(const char *fmt, ...) {
    int ret;
    va_list ap;
    char buf[BUFSIZ] = {'\0'};
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);

    ocall_print_string(&ret, buf);
    return ret;
}