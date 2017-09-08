//
// Created by vytautas on 7/26/17.
//

#include "crypto.h"

#include "enclave_state.h"
#include "enclave_t.h"

#include <sgx_trts.h>
#include <string.h>
#include "util.h"

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
sgx_status_t e_exchange_keys(sgx_ec256_public_t* client_pub_key_in,
                             sgx_ec256_public_t* enclave_pub_key_out)
{
    if(g_state != INIT)
        return SGX_ERROR_INVALID_ENCLAVE;

    if(!sgx_is_outside_enclave(enclave_pub_key_out, sizeof(sgx_ec256_public_t)) ||
       !sgx_is_outside_enclave(client_pub_key_in, sizeof(sgx_ec256_public_t)))
    {
        //print("Incorrect input parameter(s).\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memcpy(enclave_pub_key_out, &g_data.pub_key_trades, sizeof(sgx_ec256_public_t));

    sgx_ecc_state_handle_t ecc;// = g_data.ecc_state;
    sgx_status_t ret = sgx_ecc256_open_context(&ecc);
    if(ret != SGX_SUCCESS)
        return ret;

    ret = sgx_ecc256_compute_shared_dhkey(&g_data.key_trades, client_pub_key_in, &g_data.sk_key, ecc);
    if(ret != SGX_SUCCESS)
        return ret;

//    print_key("en key:", (uint8_t*)&g_data.key_trades);
//    print_key("en pub:", (uint8_t*)client_pub_key_in);
//    print_key("en secret:", (uint8_t*)&g_data.sk_key);
    return SGX_SUCCESS;
}
sgx_status_t e_encrypt_trades(uint8_t* trades, uint32_t trades_size,
                              uint8_t* out_data, uint8_t* gcm_mac)
{}