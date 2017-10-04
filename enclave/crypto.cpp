//
// Created by vytautas on 7/26/17.
//

#include "crypto.h"

#include "enclave_state.h"
#include "enclave_t.h"

#include <sgx_trts.h>
#include <string.h>
#include <crypto.h>
#include "util.h"

#include <cassert>

sgx_status_t e_get_pub_key(sgx_ec256_public_t* pub_key)
{
    if(g_state != INIT)
        return SGX_ERROR_INVALID_ENCLAVE;

    if(!sgx_is_outside_enclave(pub_key, sizeof(sgx_ec256_public_t)))
    {
        //print("Incorrect input parameter(s).\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memcpy(pub_key, &g_data.pub_key_trades, sizeof(sgx_ec256_public_t));

    return SGX_SUCCESS;
}

ec256_dhkey_t get_shared_dhkey(sgx_ec256_private_t* prv_key, sgx_ec256_public_t* peer_key)
{
    sgx_ecc_state_handle_t ecc;
    sgx_ecc256_open_context(&ecc);
    ec256_dhkey_t sk_key;

    //int ok;
    //assert(SGX_SUCCESS == sgx_ecc256_check_point(peer_key, ecc, &ok) && ok == 1);
    sgx_status_t ret = sgx_ecc256_compute_shared_dhkey(prv_key, peer_key, (sgx_ec256_dh_shared_t*)&sk_key, ecc);

    if(ret != SGX_SUCCESS)
        throw std::runtime_error("Get shared dh key failed: "+dec(ret));

    sgx_ecc256_close_context(ecc);

    return sk_key;
}

void aes128_encrypt(aes128_key_t *key, const uint8_t *data, uint32_t data_size, uint8_t *out_data, gcm_tag_t *out_mac)
{
    uint8_t iv[12] = {0};
    sgx_status_t ret;

    ret = sgx_rijndael128GCM_encrypt(
            (sgx_aes_gcm_128bit_key_t *)key, data, data_size, out_data,
            iv, 12, 0, 0,
            (sgx_aes_gcm_128bit_tag_t *)out_mac);

    if(ret != SGX_SUCCESS)
        throw std::runtime_error("Encrypt failed: ");
}
void aes128_decrypt(aes128_key_t *key, uint8_t *data, uint32_t data_size, gcm_tag_t *mac, uint8_t *out_data)
{
    uint8_t iv[12] = {0};
    sgx_status_t ret;

    ret = sgx_rijndael128GCM_decrypt(
            (sgx_aes_gcm_128bit_key_t *)key, data, data_size, out_data,
            iv, 12, 0, 0,
            (sgx_aes_gcm_128bit_tag_t *)mac);

    if(ret != SGX_SUCCESS)
        throw std::runtime_error("Decrypt failed: ");
}


AES_GCM_msg ec256_encrypt_msg(sgx_ec256_public_t* pub_key, ec256_dhkey_t* sk_key, const buffer& msg_data)
{
    AES_GCM_msg msg;
    msg.peer_key = *pub_key;

    msg.data.size(msg_data.size());

    aes128_encrypt((aes128_key_t*)sk_key, msg_data.data(), msg_data.size(), msg.data.data(), &msg.tag);

    return msg;
}
buffer ec256_decrypt_msg(sgx_ec256_private_t* prv_key, AES_GCM_msg& msg)
{
    buffer out;
    out.size(msg.data.size());

    ec256_dhkey_t sk_key = get_shared_dhkey(prv_key, &msg.peer_key);

    aes128_decrypt((aes128_key_t*)&sk_key, msg.data.data(), msg.data.size(), &msg.tag, out.data());

    return out;
}
