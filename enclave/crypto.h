//
// Created by vytautas on 7/26/17.
//

#ifndef SGX_NETTING_CRYPTO_H
#define SGX_NETTING_CRYPTO_H


#include <sgx_tcrypto.h>

sgx_status_t rsa3072_create_key_pair(sgx_rsa3072_private_key_t * p_private,
                                     sgx_rsa3072_public_key_t * p_public);

sgx_status_t rsa3072_decrypt(sgx_rsa3072_private_key_t * p_private,
                             const uint8_t* data, uint32_t data_size, uint8_t* out_data);
sgx_status_t rsa3072_encrypt(sgx_rsa3072_public_key_t * p_public,
                             const uint8_t* data, uint32_t data_size, uint8_t* out_data);

#endif //SGX_NETTING_CRYPTO_H
