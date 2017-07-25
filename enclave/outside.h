//
// Created by vytautas on 7/26/17.
//
/*
 * Functions related to state outside of enclave
 * ocalls here.
 */

#ifndef SGX_NETTING_OUTSIDE_H
#define SGX_NETTING_OUTSIDE_H

#include <stdint.h>

void* out_malloc(uint32_t size);
int printf(const char *fmt, ...);

#endif //SGX_NETTING_OUTSIDE_H
