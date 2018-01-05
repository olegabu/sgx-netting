//
// Created by vytautas on 10/4/17.
//

#ifndef SGX_NETTING_CRYPTO_H
#define SGX_NETTING_CRYPTO_H

#include <stdint.h>
#include <sgx_tcrypto.h>
#include "buffer.h"

typedef uint8_t gcm_tag_t[16];
typedef struct{
    uint8_t b[32];
} ec256_dhkey_t;
typedef uint8_t aes128_key_t[16];

struct AES_GCM_msg {
    sgx_ec256_public_t peer_key;
    buffer data;
    gcm_tag_t tag;
};

inline buffer& operator <<(buffer& buf, const AES_GCM_msg& rhs){
    buf.write(&rhs.peer_key, sizeof(rhs.peer_key));
    buf << rhs.data;
    buf.write(&rhs.tag, sizeof(rhs.tag));
    return buf;
}

inline buffer& operator >>(buffer& buf, AES_GCM_msg& rhs){
    buf.read(&rhs.peer_key, sizeof(rhs.peer_key));
    buf >> rhs.data;
    buf.read(&rhs.tag, sizeof(rhs.tag));
    return buf;
}


#ifndef ENCLAVE
// App-only

#include <openssl/ec.h>

EC_KEY* to_ec_key(sgx_ec256_private_t* prv_key);
EC_KEY* to_ec_key(sgx_ec256_public_t* pub_key);

void ec256_gen_key(sgx_ec256_private_t *prv_key, sgx_ec256_public_t *pub_key);
bool ec256_check_point(sgx_ec256_public_t *pub_key);

void aes128_decrypt(uint8_t *key, uint8_t *data, uint32_t data_size, gcm_tag_t *mac, uint8_t *out_data);
void aes128_encrypt(uint8_t *key, const uint8_t *data, uint32_t data_size, uint8_t *out_data, gcm_tag_t *out_mac);
#endif // !ENCLAVE

ec256_dhkey_t get_shared_dhkey(sgx_ec256_private_t* prv_key, sgx_ec256_public_t* peer_key);
AES_GCM_msg ec256_encrypt_msg(sgx_ec256_public_t* pub_key, ec256_dhkey_t* sk_key, const buffer& msg_data);
buffer ec256_decrypt_msg(sgx_ec256_private_t* prv_key, AES_GCM_msg& msg_data);



#endif //SGX_NETTING_CRYPTO_H
