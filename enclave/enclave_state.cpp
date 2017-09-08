//
// Created by vytautas on 7/23/17.
//

#include "enclave_state.h"
#include "enclave_t.h"

#include <sgx_tseal.h>
#include <sgx_trts.h>
#include <util.h>

#include "crypto.h"

GState g_state = NONE;
GData  g_data = {0};

sgx_status_t enclave_init(uint8_t* e_sealed) {
    sgx_status_t ret;
    if(e_sealed == 0) {
        // First initialization
        sgx_ecc_state_handle_t ecc;// = g_data.ecc_state;
        sgx_ecc256_open_context(&ecc);

        ret = sgx_ecc256_create_key_pair(&g_data.key_trades, &g_data.pub_key_trades, ecc);
        if(ret != SGX_SUCCESS)
            return ret;

        sgx_ecc256_close_context(ecc);

        ret = rsa3072_create_key_pair(&g_data.key_trades_rsa3072, &g_data.pub_key_trades_rsa3072);
        if(ret != SGX_SUCCESS)
            return ret;

        //print_raw(&g_data.pub_key_trades_rsa3072, sizeof(sgx_rsa3072_public_key_t));

        g_state = INIT;
        return SGX_SUCCESS;
    }

    uint32_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(g_data);
    //Check the sealed_buf length and check the outside pointers deeply
    if(!sgx_is_outside_enclave(e_sealed, sealed_size))
    {
        //print("Incorrect input parameter(s).\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    ret = sgx_unseal_data((sgx_sealed_data_t*)e_sealed, 0, 0, (uint8_t*)&g_data, &sealed_size);
    if (ret != SGX_SUCCESS)
        return ret;

    g_state = INIT;
    return ret;
}

sgx_status_t enclave_close(uint8_t* e_sealed)
{
    uint32_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(g_data);
    if(!sgx_is_outside_enclave(e_sealed, sealed_size))
    {
        //print("Incorrect input parameter(s).\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }
    sgx_status_t ret = sgx_seal_data(0,0,
                                     sizeof(g_data), (uint8_t*)&g_data,
                                     sealed_size, (sgx_sealed_data_t *)e_sealed);

    g_state = CLOSED;
    return ret;
}