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
        sgx_ec256_public_t* peer_key,
        uint8_t* e_trades, uint32_t e_trades_size, uint8_t* trades_mac,
        uint8_t** e_out_data, uint32_t* e_out_data_size, uint8_t* e_out_mac)
{
    sgx_status_t ret = SGX_SUCCESS;

    //ret = sgx_ra_get_keys(context, SGX_RA_KEY_SK, &sk_key);
    //if(SGX_SUCCESS != ret)
    //    return ret;

    uint8_t* trade_data = (uint8_t*)malloc(e_trades_size);

    sgx_ec256_dh_shared_t sk_key;
    sgx_ecc_state_handle_t ecc;
    sgx_ecc256_open_context(&ecc);
    sgx_ecc256_compute_shared_dhkey(&g_data.key_trades, peer_key, &sk_key, ecc);
    sgx_ecc256_close_context(ecc);

    uint8_t aes_gcm_iv[12] = {0};
    ret = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t *)&sk_key,
            e_trades,
            e_trades_size,
            trade_data,
            aes_gcm_iv, 12, NULL, 0,
            (const sgx_aes_gcm_128bit_tag_t *)(trades_mac));

    if(ret != SGX_SUCCESS)
        return ret;
    printf("[enclave] decrypted:\n");
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
            (const sgx_ec_key_128bit_t*)&sk_key,
            buf.data(), buf.size(),
            *e_out_data,
            aes_gcm_iv, 12, NULL, 0,
            (sgx_aes_gcm_128bit_tag_t *)(e_out_mac));


    if(ret != SGX_SUCCESS)
        return ret;
    return ret;
}