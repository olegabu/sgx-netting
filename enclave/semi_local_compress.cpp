//
// Created by vytautas on 7/26/17.
//

#include <sgx.h>
#include <sgx_tcrypto.h>
#include <stdlib.h>
#include <sgx_ecp_types.h>
#include <sgx_trts.h>

#include "util.h"
#include "enclave_state.h"
#include "serial_trades.h"
#include "enclave_t.h"
#include "SemiLocalAlgorithm.h"

#include "crypto.h"
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
    buffer buf;
    write_trades(newtrades, buf);

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

sgx_status_t compress_slv1_vector(
uint8_t* in_inputs, uint32_t in_inputs_size,
uint8_t** out_trades, uint32_t* out_trades_size) {


    try {
        if (g_state != INIT)
            return SGX_ERROR_INVALID_ENCLAVE;

        if (!sgx_is_outside_enclave(in_inputs, in_inputs_size)) {
            //print("Incorrect input parameter(s).\n");
            return SGX_ERROR_INVALID_PARAMETER;
        }

        // Deserialize input list
        vector<AES_GCM_msg> inputs;
        {
            buffer buf;
            buf.write(in_inputs, in_inputs_size);

            buf >> inputs;
        }

        // Decrypt inputs
        vector<ClearedTrade> all_trades;
        map<string, sgx_ec256_public_t> party_keys;
        for (AES_GCM_msg &msg : inputs) {
            buffer data = ec256_decrypt_msg(&g_data.key_trades, msg);

            string p_id;
            data >> p_id;

            party_keys[p_id] = msg.peer_key;

            vector<ClearedTrade> trades = read_trades(data.read_ptr(), data.size());
            for (ClearedTrade &t : trades) {
                all_trades.push_back(t);
            }
        }

        // === Run algorithm ===
        SemiLocalAlgorithm algo;

        NotionalMatrix mat;
        mat.add(all_trades);
        NotionalMatrix newmat = algo.compress(mat);

        vector<ClearedTrade> newtrades = newmat.to_list();

        // Prepare output for each party
        vector<string> output_parties;
        vector<AES_GCM_msg> outputs;


        for (const party_id_t &p_id : newmat.members_set) {

                       printf("Party: %s\n", p_id);

            vector<ClearedTrade> p_trades;
            map<party_id_t, vector<ClearedTrade>> partyCounterparty_trades;
            for (ClearedTrade &t : newtrades) {

//                party_id_t counterParty = t.party == p_id ? t.counter_party : t.party;

                if (t.party == p_id) {
                    p_trades.push_back(t);
                    partyCounterparty_trades[t.counter_party].push_back(t);
                }
            }

            if (p_trades.size() == 0)
                continue;


            for (const auto pCpPair : partyCounterparty_trades) {
                       printf("pCpPair: %s\n", pCpPair.first);

                vector<ClearedTrade> pairTrades=pCpPair.second;
                for(const auto ptrade: pairTrades) {
                   printf("\tTrade: %s-%s:%i\n", ptrade.party, ptrade.counter_party, ptrade.value);
                }

				string partyPair = p_id + ":" + pCpPair.first;

				buffer buf;
				buf << p_id;
				write_trades(pairTrades, buf);
                sgx_ec256_public_t* peer_key;

                auto it = party_keys.find(p_id);
                peer_key = (it != party_keys.end()) ? &it->second : 0;

                // Skip party if we do not have a public key
                if(peer_key == 0)
                    continue;

            //    vector<string> pair_parties;
            //    pair_parties.push_back(p_id);
            //    pair_parties.push_back(pCpPair.first);

                output_parties.push_back(partyPair);
                ec256_dhkey_t sk_key = get_shared_dhkey(&g_data.key_trades, peer_key);
                AES_GCM_msg msg = ec256_encrypt_msg(&g_data.pub_key_trades, &sk_key, buf);

                outputs.push_back(msg);

            }
        }

        buffer out_buf;

        out_buf << output_parties;
        out_buf << outputs;

        ocall_malloc((void **) out_trades, out_buf.size());
        memcpy(*out_trades, out_buf.data(), out_buf.size());
        *out_trades_size = out_buf.size();
    }catch (std::exception& e){
        printf("exc: %s", e.what());
        return SGX_ERROR_INVALID_PARAMETER;
    }
    return SGX_SUCCESS;
}
