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
#include <openssl/ssl.h>
#include <algorithm>

#include "enclave_u.h"
#include "SemiLocalAlgorithm.h"
#include "util.h"
#include "crypto.h"

#include "app.h"
AppGData G = {0};

vector<ClearedTrade> load_trades() {
    FILE* trades_f = fopen("trades.txt","rw");

    if(!trades_f) {
        throw runtime_error("Failed to open trades.txt");
    }
    vector<ClearedTrade> trades;
    map<string, party_id_t> ps_to_p;
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
            //ps_to_p[k_a] = p_a = party_id_t(new StandardId(v_a[0],v_a[1]));
            ps_to_p[k_a] = p_a = v_a[0] + "~" + v_a[1];
        } else
            p_a = it_a->second;


        auto k_b = string(sid2);
        auto v_b = split(k_b, '~');
        auto it_b = ps_to_p.find(k_b);
        if(it_b == ps_to_p.end()) {
            //ps_to_p[k_b] = p_b = party_id_t(new StandardId(v_b[0],v_b[1]));
            ps_to_p[k_b] = p_b = v_b[0] + "~" + v_b[1];
        } else
            p_b = it_b->second;

        ClearedTrade t;
        t.party = p_a;
        t.counter_party = p_b;
        t.value = value;

        trades.push_back(t);
    }
    fclose(trades_f);

    return trades;
}


int algo_ec256(sgx_enclave_id_t enclave_id, buffer &trade_data) {
    sgx_status_t sret, ret;
    sgx_ec256_private_t prv_key;
    sgx_ec256_public_t pub_key;
    sgx_ec256_public_t e_pub_key;
    memset(&prv_key, 0, sizeof(sgx_ec256_public_t));
    memset(&pub_key, 0, sizeof(sgx_ec256_public_t));
    memset(&e_pub_key, 0, sizeof(sgx_ec256_public_t));
    ec256_gen_key(&prv_key, &pub_key);

    //assert(check_point(&pub_key));

    sret = e_get_pub_key(enclave_id, &ret, &e_pub_key);
    assert(ec256_check_point(&e_pub_key));
    if(sret != SGX_SUCCESS || ret != SGX_SUCCESS) {
        printf("\nError at %d, %d, %d." , __LINE__, sret, (int32_t)ret);
        return -1;
    }
    uint8_t* enc_trades = (uint8_t*)malloc(trade_data.size());

    uint8_t* secret = (uint8_t*)get_shared_dhkey(&prv_key, &e_pub_key);
    gcm_tag_t t_mac;
    aes128_encrypt(secret, trade_data.data(), trade_data.size(), enc_trades, &t_mac);

    uint8_t* new_trades = 0;
    uint32_t new_trades_n = 0;
    gcm_tag_t new_mac;

    sret = semi_local_compress(enclave_id, &ret,
                               &pub_key,
                               enc_trades, trade_data.size(), (uint8_t*)&t_mac,
                               &new_trades, &new_trades_n, (uint8_t*)&new_mac);

    if(sret != SGX_SUCCESS || ret != SGX_SUCCESS) {
        printf("\nError, %d, %x.", sret, ret);
        return -1;
    }

    uint8_t* dec_new_trades = (uint8_t*) malloc(new_trades_n);
    aes128_decrypt(secret, new_trades, new_trades_n, &new_mac, dec_new_trades);

    vector<ClearedTrade> new_trades_list = read_trades(dec_new_trades,new_trades_n);

    cout << "\n[app] Compressed notional matrix:\n";
    cout << new_trades_list << endl;
}

#define SGX_CHECK \
    if(sret != SGX_SUCCESS || ret != SGX_SUCCESS) { \
        printf("\nError at %d, %d, %d." , __LINE__, sret, (int32_t)ret);\
        return -1;\
    }

#define SEALED_SIZE 1024

void app_init(bool& enclave_changed) {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    OPENSSL_add_all_algorithms_noconf();
    SSL_load_error_strings();
    ERR_load_CRYPTO_strings();
#else
    OPENSSL_init_ssl(0, NULL);
#endif
    uint8_t sealed_data[SEALED_SIZE] = {0};

    FILE* tokf = fopen("enclave.state", "r+b");

    if(tokf){
        if(fread(&G.launch_token, 1, sizeof(sgx_launch_token_t), tokf) != 1024
            || fread(sealed_data, 1, SEALED_SIZE, tokf) != SEALED_SIZE )
            throw runtime_error("enclave.state : Unexpected EOF");
        fclose(tokf);
    }

    sgx_status_t ret;
    int launch_token_update = 0;
    ret = sgx_create_enclave("enclave.so",
                             SGX_DEBUG_FLAG,
                             &G.launch_token,
                             &launch_token_update,
                             &G.enclave_id, NULL);
    if(SGX_SUCCESS != ret)
    {
        errorf("\nError, call sgx_create_enclave fail [%x].", ret);
    }

    if(launch_token_update == 1)
        enclave_changed = true;

    sgx_status_t sret;
    sret = enclave_init(G.enclave_id, &ret, tokf ? sealed_data : 0);
    if(sret != SGX_SUCCESS || ret != SGX_SUCCESS) {
        errorf("\nError at %d, %d, 0x%x." , __LINE__, sret, ret);
    }
}

void app_close()
{
    sgx_status_t sret, ret;

    uint8_t sealed_data[SEALED_SIZE] = {0};
    sret = enclave_close(G.enclave_id, &ret, sealed_data);

    FILE* tokf = fopen("enclave.state", "wb");

    if(!tokf)
        throw runtime_error("Cannot open enclave.state");

    fwrite(&G.launch_token, 1, 1024, tokf);
    fwrite(sealed_data, 1, SEALED_SIZE, tokf);

    fclose(tokf);

    sgx_destroy_enclave(G.enclave_id);
    if(sret != SGX_SUCCESS || ret != SGX_SUCCESS) {
        errorf("\nError at %d, %d, 0x%x." , __LINE__, sret, ret);
    }
}