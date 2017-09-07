//
// Created by vytautas on 7/23/17.
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sgx.h>
#include <cstdio>

#include <vector>
#include <map>
#include <serial_trades.h>


#include <sgx_urts.h>
#include <iostream>
#include <cstring>

#include "enclave_u.h"
#include "SemiLocalAlgorithm.h"
#include "util.h"
#include "crypto.h"

#include <openssl/ssl.h>

int main(int argc, char* argv[])
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
    sgx_status_t ret;
    sgx_enclave_id_t enclave_id;
    int launch_token_update = 0;
    sgx_launch_token_t launch_token = {0};
    ret = sgx_create_enclave("enclave.so",
                             SGX_DEBUG_FLAG,
                             &launch_token,
                             &launch_token_update,
                             &enclave_id, NULL);
    if(SGX_SUCCESS != ret)
    {
        printf("\nError, call sgx_create_enclave fail [%d].", ret);
        return -1;
    }

    sgx_status_t sret;
    sret = enclave_init(enclave_id, &ret, 0);
    if(sret != SGX_SUCCESS || ret != SGX_SUCCESS) {
        printf("\nError at %d, %d, 0x%x." , __LINE__, sret, ret);
        return -1;
    }

    FILE* trades_f = fopen("trades.txt","rw");

    if(!trades_f) {
        printf("Failed to open trades.txt");
        return -1;
    }
    vector<ClearedTrade> trades;
    map<string, shared_ptr<StandardId>> ps_to_p;
    while(true) {
        char sid1[64],sid2[64];
        int64_t value;
        if(feof(trades_f))
            break;
        char line[128];
        fgets(line,128,trades_f);
        int r = sscanf(line, "%s %s %ld n",
            sid1,sid2, &value);
        if(r < 3)
            break;

        party_id_t p_a;
        party_id_t p_b;

        auto k_a = string(sid1);
        auto v_a = split(k_a, '~');
        auto it_a = ps_to_p.find(k_a);
        if(it_a == ps_to_p.end()) {
            ps_to_p[k_a] = p_a = party_id_t(new StandardId(v_a[0],v_a[1]));
        } else
            p_a = it_a->second;


        auto k_b = string(sid2);
        auto v_b = split(k_b, '~');
        auto it_b = ps_to_p.find(k_b);
        if(it_b == ps_to_p.end()) {
            ps_to_p[k_b] = p_b = party_id_t(new StandardId(v_b[0],v_b[1]));
        } else
            p_b = it_b->second;

        ClearedTrade t;
        t.party = p_a;
        t.counter_party = p_b;
        t.value = value;

        trades.push_back(t);
    }

    NotionalMatrix mat;
    mat.add(trades);
    printf("n_trades: %d %d\n", trades.size(), mat.n_trade_pairs());
    SemiLocalAlgorithm algo;
    NotionalMatrix newmat = algo.compress(mat);

    cout << newmat.sub(mat) << endl;
    buffer buf = write_trades(trades);

    print_raw(buf.data(), buf.size());

    uint8_t* enc_trades = (uint8_t*)malloc(buf.size());

    sgx_ec256_private_t prv_key;
    sgx_ec256_public_t pub_key;
    sgx_ec256_public_t e_pub_key;
    memset(&prv_key, 0, sizeof(sgx_ec256_public_t));
    memset(&pub_key, 0, sizeof(sgx_ec256_public_t));
    memset(&e_pub_key, 0, sizeof(sgx_ec256_public_t));
    gen_key(&prv_key, &pub_key);

    //assert(check_point(&pub_key));

    sret = e_exchange_keys(enclave_id, &ret, &pub_key, &e_pub_key);
    //sret = e_encrypt_trades(enclave_id, &ret, (uint8_t*)buf.data(), buf.size(), enc_trades, t_mac);

    assert(check_point(&e_pub_key));
    if(sret != SGX_SUCCESS || ret != SGX_SUCCESS) {
        printf("\nError at %d, %d, %d." , __LINE__, sret, (int32_t)ret);
        return -1;
    }

    uint8_t* secret = get_shared_dhkey(&prv_key, &e_pub_key);
    uint8_t t_mac[16];
    encrypt(secret, buf.data(), buf.size(), enc_trades, t_mac);

    uint8_t* new_trades = 0;
    uint32_t new_trades_n = 0;
    uint8_t new_mac[16];
    //uint8_t pub_key[16];



    sret = semi_local_compress(enclave_id, &ret,
        enc_trades, buf.size(), t_mac,
        &new_trades, &new_trades_n, new_mac);

    if(sret != SGX_SUCCESS || ret != SGX_SUCCESS) {
        printf("\nError, %d, %d.", sret, ret);
        return -1;
    }

    uint8_t* dec_new_trades = (uint8_t*) malloc(new_trades_n);
    decrypt(secret, new_trades, new_trades_n, new_mac, dec_new_trades);

    vector<ClearedTrade> n_trades = read_trades(dec_new_trades,new_trades_n);

    cout << n_trades << endl;
}
