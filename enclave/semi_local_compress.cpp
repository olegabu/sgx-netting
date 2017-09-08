//
// Created by vytautas on 7/26/17.
//

#include <sgx.h>
#include <sgx_tcrypto.h>
#include <stdlib.h>
#include <sgx_ecp_types.h>

#include "util.h"
#include "enclave_state.h"
#include "serial_trades.h"
#include "enclave_t.h"
#include "SemiLocalAlgorithm.h"

sgx_status_t
semi_local_compress(
        uint8_t* e_trades, uint32_t e_trades_size, uint8_t* trades_mac,
        uint8_t** e_out_data, uint32_t* e_out_data_size, uint8_t* e_out_mac)
{
    sgx_status_t ret = SGX_SUCCESS;

    //ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    //if(SGX_SUCCESS != ret)
    //    return ret;

    uint8_t* trade_data = (uint8_t*)malloc(e_trades_size);

    uint8_t aes_gcm_iv[12] = {0};
    ret = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t *)&g_data.sk_key,
            e_trades,
            e_trades_size,
            trade_data,
            aes_gcm_iv, 12, NULL, 0,
            (const sgx_aes_gcm_128bit_tag_t *)(trades_mac));

    printf("[enclave] decrypted:\n");
    if(ret != SGX_SUCCESS)
        return ret;
    print_raw(trade_data, e_trades_size);

    NotionalMatrix mat;
    vector<ClearedTrade> trades;
    try {
        trades = read_trades(trade_data, e_trades_size);

        mat.add(trades);
    } catch (exception& e) {
        printf(e.what());
    }

    printf("\n[enclave] n_trades: %d %d\n", trades.size(), mat.n_trade_pairs());


    SemiLocalAlgorithm algo;

    NotionalMatrix newmat = algo.compress(mat);

    vector<ClearedTrade> newtrades = newmat.to_list();
    buffer buf = write_trades(newtrades);

    *e_out_data_size = buf.size();
    *e_out_data = (uint8_t*)out_malloc(buf.size());

    ret = sgx_rijndael128GCM_encrypt(
            (const sgx_ec_key_128bit_t*)&g_data.sk_key,
            buf.data(), buf.size(),
            *e_out_data,
            aes_gcm_iv, 12, NULL, 0,
            (sgx_aes_gcm_128bit_tag_t *)(e_out_mac));


    if(ret != SGX_SUCCESS)
        return ret;
    return ret;
}

#include "crypto.h"

sgx_status_t
semi_local_compress_rsa(
        uint8_t* e_trades, uint32_t e_trades_size, uint8_t* trades_mac,
        uint8_t** e_out_data, uint32_t* e_out_data_size, uint8_t* e_out_mac,
        sgx_rsa3072_public_key_t* pub_key)
{
    sgx_status_t ret = SGX_SUCCESS;
    uint8_t* trade_data = (uint8_t*)malloc(e_trades_size);

    printf("[enclave] e_trades:\n");
    print_raw(&g_data.key_trades_rsa3072, e_trades_size);
    print_raw(e_trades, e_trades_size);

    ret = rsa3072_decrypt(&g_data.key_trades_rsa3072,
        e_trades, e_trades_size, trade_data);

    printf("[enclave] decrypt:\n");
    if(ret != SGX_SUCCESS)
        return ret;
    print_raw(trade_data, e_trades_size);
    NotionalMatrix mat;
    vector<ClearedTrade> trades;
    try {
        trades = read_trades(trade_data, e_trades_size);

        mat.add(trades);
    } catch (exception& e) {
        printf(e.what());
    }

    printf("n_trades: %d %d\n", trades.size(), mat.n_trade_pairs());

    SemiLocalAlgorithm algo;

    NotionalMatrix newmat = algo.compress(mat);

    vector<ClearedTrade> newtrades = newmat.sub(mat);
    buffer buf = write_trades(newtrades);

    *e_out_data_size = 384;
    *e_out_data = (uint8_t*)out_malloc(384);

    print_raw(pub_key->exp, 4);
    ret = rsa3072_encrypt(
            pub_key, buf.data(), buf.size(), *e_out_data
    );


    if(ret != SGX_SUCCESS)
        return ret;
    return ret;
}