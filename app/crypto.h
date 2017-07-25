//
// Created by vytautas on 7/27/17.
//

#ifndef SGX_NETTING_CRYPTO_H
#define SGX_NETTING_CRYPTO_H

#include <sgx_tcrypto.h>
#include <openssl/ec.h>

EC_KEY* to_ec_key(sgx_ec256_private_t* prv_key);
EC_KEY* to_ec_key(sgx_ec256_public_t* pub_key);
void gen_key(sgx_ec256_private_t* prv_key, sgx_ec256_public_t* pub_key);
uint8_t* get_shared_dhkey(sgx_ec256_private_t* prv_key, sgx_ec256_public_t* peer_key);
void decrypt(uint8_t* key, uint8_t* data, uint32_t data_size, uint8_t* mac, uint8_t* out_data);
void encrypt(uint8_t* key, const uint8_t* data, uint32_t data_size, uint8_t* out_data, uint8_t* out_mac);
bool check_point(sgx_ec256_public_t* pub_key);


#endif //SGX_NETTING_CRYPTO_H
