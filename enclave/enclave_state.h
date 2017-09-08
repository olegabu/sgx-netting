//
// Created by vytautas on 7/23/17.
//

#ifndef SGX_NETTING_ENCLAVE_STATE_H
#define SGX_NETTING_ENCLAVE_STATE_H

#include <sgx_tcrypto.h>

enum GState {
    NONE, INIT, CLOSED
};

extern GState g_state;

extern struct GData {
    // sgx_sealed_data_t takes 112 bytes
    sgx_ec256_private_t key_trades;
    sgx_ec256_public_t pub_key_trades;

    sgx_ec256_dh_shared_t sk_key;

    sgx_rsa3072_private_key_t key_trades_rsa3072;
    sgx_rsa3072_public_key_t  pub_key_trades_rsa3072;
} g_data;

#endif //SGX_NETTING_ENCLAVE_STATE_H
