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

sgx_status_t e_rsa3072_getPub(sgx_rsa3072_public_key_t* pub_key,  sgx_rsa3072_private_key_t* prv_key)
{
    if(g_state != INIT)
        return SGX_ERROR_INVALID_ENCLAVE;

    if(!sgx_is_outside_enclave(pub_key, sizeof(sgx_rsa3072_public_key_t)))
    {
        //print("Incorrect input parameter(s).\n");
        return SGX_ERROR_INVALID_PARAMETER;
    }

    memcpy(pub_key, &g_data.pub_key_trades_rsa3072, sizeof(sgx_rsa3072_public_key_t));
    memcpy(prv_key, &g_data.key_trades_rsa3072, sizeof(sgx_rsa3072_private_key_t));

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

// RSA functions

#include "ipp/ippcore.h"
#include "ipp/ippcp.h"

#ifndef ERROR_BREAK
#define ERROR_BREAK(x)  if(x != ippStsNoErr){printf("ERROR AT %s:%d\n", __FILE__, __LINE__); break;}
#endif
#ifndef SAFE_FREE
#define SAFE_FREE(ptr) {if (NULL != (ptr)) {free(ptr); (ptr)=NULL;}}
#endif

IppStatus sgx_ipp_newBN(const Ipp32u *p_data, int size_in_bytes, IppsBigNumState **p_new_BN);
void sgx_ipp_secure_free_BN(IppsBigNumState *pBN, int size_in_bytes);
IppStatus __STDCALL sgx_ipp_DRNGen(Ipp32u* pRandBNU, int nBits, void* pCtx);

IppsBigNumState* createBigNumState(int len, const Ipp32u* pData)  {
    int size;
    ippsBigNumGetSize(len, &size);
    IppsBigNumState* pBN = (IppsBigNumState*) ippMalloc(size);;
    ippsBigNumInit(len, pBN);
    if (pData != NULL) {
        ippsSet_BN(IppsBigNumPOS, len, pData, pBN);
    }
    return pBN;
}

sgx_status_t rsa3072_create_key_pair(sgx_rsa3072_private_key_t * p_private,
                                     sgx_rsa3072_public_key_t * p_public) {
    int bitsRSA = 3072;
    IppStatus ipp_ret = ippStsNoErr;

    // Security parameter specified for the
    // Miller-Rabin test for probable primality.
    int nTrials = 10;
    // Number of bits of the exponent
    int bitsExp = 24;

    int sizeOfPrimeGen = -1;
    int sizeOfRandomGen = -1;
    int sizeOfPublicKey = -1;
    int sizeOfPrivateKey = -1;
    int sizeOfScratchBuffer = -1;

    IppsPrimeState *primeGen = NULL;
    IppsPRNGState *randomGen = NULL;
    IppsRSAPublicKeyState *publicKey = NULL;
    IppsRSAPrivateKeyState *privateKey = NULL;
    Ipp8u *scratchBuffer = NULL;

    Ipp32u E = 65537;
    IppsBigNumState *pSrcPublicExp = createBigNumState(1, &E);
    IppsBigNumState *pModulus = createBigNumState(bitsRSA / 32, NULL);
    IppsBigNumState *pPublicExp = createBigNumState(bitsRSA / 32, NULL);
    IppsBigNumState *pPrivateExp = createBigNumState(bitsRSA / 32, NULL);

    do {
        // Prime Number Generator
        ippsPrimeGetSize(bitsRSA, &sizeOfPrimeGen);
        primeGen = (IppsPrimeState *) ippMalloc(sizeOfPrimeGen);
        ippsPrimeInit(bitsRSA, primeGen);

        // Pseudo Random Generator (default settings)
        ippsPRNGGetSize(&sizeOfRandomGen);
        randomGen = (IppsPRNGState *) ippMalloc(sizeOfRandomGen);
        ippsPRNGInit(160, randomGen);

        // Initialize the Public Key State
        ippsRSA_GetSizePublicKey(bitsRSA, bitsExp, &sizeOfPublicKey);
        publicKey = (IppsRSAPublicKeyState *) ippMalloc(sizeOfPublicKey);
        ippsRSA_InitPublicKey(bitsRSA, bitsExp, publicKey, sizeOfPublicKey);

        // Initialize the Private Key State
        int bitsP = (bitsRSA + 1) / 2;
        int bitsQ = bitsRSA - bitsP;
        ippsRSA_GetSizePrivateKeyType2(bitsP, bitsQ, &sizeOfPrivateKey);
        privateKey = (IppsRSAPrivateKeyState *) ippMalloc(sizeOfPrivateKey);
        //printf("%d, %p\n", sizeOfPrivateKey,privateKey);
        ippsRSA_InitPrivateKeyType2(bitsP, bitsQ, privateKey, sizeOfPrivateKey);

        // Initialize scratch buffer
        ippsRSA_GetBufferSizePrivateKey(&sizeOfScratchBuffer, privateKey);
        scratchBuffer = (Ipp8u *) ippMalloc(sizeOfScratchBuffer);

        //printf("%p\n", privateKey);
        ipp_ret = ippsRSA_GenerateKeys(
                pSrcPublicExp,
                pModulus, pPublicExp, pPrivateExp,
                privateKey, scratchBuffer, nTrials,
                primeGen, ippsPRNGen, randomGen
        );
//        printf("%p, %p, %p, %p, %p, %p, %p, %p\n",
//               pSrcPublicExp, pModulus, pPublicExp, pPrivateExp,
//            privateKey, primeGen, ippsPRNGen, randomGen);
        ERROR_BREAK(ipp_ret);

        int bn_bsize;
        Ipp32u * pdata = NULL;
        ipp_ret = ippsRef_BN(0, &bn_bsize, &pdata, pModulus);
        ERROR_BREAK(ipp_ret);

        printf("%d\n",bn_bsize/8);
        //print_raw(pdata, 384);
        memcpy(p_private->mod, pdata, 384);
        memcpy(p_public->mod, pdata, 384);

        ipp_ret = ippsRef_BN(0, &bn_bsize, &pdata, pPrivateExp);
        ERROR_BREAK(ipp_ret);

        printf("%d\n",bn_bsize/8);
        memcpy(p_private->exp, pdata, 384);

        ipp_ret = ippsRef_BN(0, &bn_bsize, &pdata, pPublicExp);
        ERROR_BREAK(ipp_ret);

        printf("%d\n",bn_bsize/8);
        memset(p_public->exp, 0, 4);
        memcpy(p_public->exp, pdata, 2);
    } while (0);

    ippFree(pSrcPublicExp);
    ippFree(pModulus);
    ippFree(pPublicExp);
    ippFree(pPrivateExp);
    ippFree(primeGen);
    ippFree(randomGen);
    ippFree(publicKey);
    ippFree(privateKey);
    ippFree(scratchBuffer);

    printf(ippGetStatusString(ipp_ret));
    printf("\n");
    return (sgx_status_t)ipp_ret;
}

sgx_status_t rsa3072_decrypt(sgx_rsa3072_private_key_t * p_private,
                             const uint8_t* data, uint32_t data_size, uint8_t* out_data)
{
    IppStatus ipp_ret = ippStsNoErr;
    IppHashAlgId hash_alg = ippHashAlg_SHA256;

    IppsRSAPrivateKeyState* rsa_key_ctx = NULL;
    Ipp8u *temp_buff = NULL;

    IppsBigNumState* p_prikey_mod_bn = NULL;
    IppsBigNumState* p_prikey_exp_bn = NULL;

    IppsBigNumState* ct_bn = NULL;
    IppsBigNumState* pt_bn = NULL;

    int private_key_ctx_size = 0;

    do {
        // Initializa IPP BN from the private key
        ipp_ret = sgx_ipp_newBN((const Ipp32u *)p_private->mod, sizeof(p_private->mod), &p_prikey_mod_bn);
        ERROR_BREAK(ipp_ret);

        ipp_ret = sgx_ipp_newBN((const Ipp32u *)p_private->exp, sizeof(p_private->exp), &p_prikey_exp_bn);
        ERROR_BREAK(ipp_ret);

        // allocate private key context

        ipp_ret = ippsRSA_GetSizePrivateKeyType1(SGX_RSA3072_KEY_SIZE * 8, SGX_RSA3072_PRI_EXP_SIZE * 8,
                                                 &private_key_ctx_size);
        ERROR_BREAK(ipp_ret);

        rsa_key_ctx = (IppsRSAPrivateKeyState*)malloc(private_key_ctx_size);
        if (!rsa_key_ctx) {
            ipp_ret = ippStsMemAllocErr;
            break;
        }

        // initialize the private key context
        ipp_ret = ippsRSA_InitPrivateKeyType1(SGX_RSA3072_KEY_SIZE * 8, SGX_RSA3072_PRI_EXP_SIZE * 8,
                                              rsa_key_ctx, private_key_ctx_size);
        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsRSA_SetPrivateKeyType1(p_prikey_mod_bn, p_prikey_exp_bn, rsa_key_ctx);
        ERROR_BREAK(ipp_ret);

        // allocate temp buffer for RSA calculation
        int private_key_buffer_size = 0;

        ipp_ret = ippsRSA_GetBufferSizePrivateKey(&private_key_buffer_size, rsa_key_ctx);
        ERROR_BREAK(ipp_ret);

        temp_buff = (Ipp8u*)malloc(private_key_buffer_size);
        if (!temp_buff) {
            ipp_ret = ippStsMemAllocErr;
            break;
        }

//        ipp_ret = sgx_ipp_newBN((const Ipp32u *)data, data_size, &ct_bn);
//        ERROR_BREAK(ipp_ret);
//
//        ipp_ret = sgx_ipp_newBN(0, data_size, &pt_bn);
//        ERROR_BREAK(ipp_ret);

        int dst_len = data_size;
        ipp_ret = ippsRSADecrypt_PKCSv15(data, out_data, &dst_len, rsa_key_ctx, temp_buff);
        ERROR_BREAK(ipp_ret);
//
//        Ipp32u * pdata = NULL;
//        ipp_ret = ippsRef_BN(0, 0, &pdata, pt_bn);
//        ERROR_BREAK(ipp_ret);
//        memcpy(out_data, pdata, data_size);
//        ERROR_BREAK(ipp_ret);
    } while (0);


//    sgx_ipp_secure_free_BN(ct_bn, data_size);
//    sgx_ipp_secure_free_BN(pt_bn, data_size);

    // remove sensitive data
    ippsRSA_InitPrivateKeyType1(SGX_RSA3072_KEY_SIZE * 8, SGX_RSA3072_PRI_EXP_SIZE * 8,
                                          rsa_key_ctx, private_key_ctx_size);

    sgx_ipp_secure_free_BN(p_prikey_mod_bn, sizeof(p_private->mod));
    sgx_ipp_secure_free_BN(p_prikey_exp_bn, sizeof(p_private->exp));
    SAFE_FREE(rsa_key_ctx);
    SAFE_FREE(temp_buff);

    printf(ippGetStatusString(ipp_ret));
    printf("\n");
    return (sgx_status_t)ipp_ret;
}


sgx_status_t rsa3072_encrypt(sgx_rsa3072_public_key_t * p_public,
                             const uint8_t* data, uint32_t data_size, uint8_t* out_data)
{
    IppStatus ipp_ret = ippStsNoErr;
    IppHashAlgId hash_alg = ippHashAlg_SHA256;

    IppsRSAPublicKeyState* rsa_key_ctx = NULL;
    Ipp8u *temp_buff = NULL;

    IppsBigNumState* p_prikey_mod_bn = NULL;
    IppsBigNumState* p_prikey_exp_bn = NULL;
//
//    IppsBigNumState* ct_bn = NULL;
//    IppsBigNumState* pt_bn = NULL;

    int public_key_ctx_size = 0;

    do {
        // Initializa IPP BN from the private key
        ipp_ret = sgx_ipp_newBN((const Ipp32u *)p_public->mod, sizeof(p_public->mod), &p_prikey_mod_bn);
        ERROR_BREAK(ipp_ret);

        ipp_ret = sgx_ipp_newBN((const Ipp32u *)p_public->exp, sizeof(p_public->exp), &p_prikey_exp_bn);
        ERROR_BREAK(ipp_ret);

        // allocate private key context

        ipp_ret = ippsRSA_GetSizePublicKey(SGX_RSA3072_KEY_SIZE * 8, SGX_RSA3072_PUB_EXP_SIZE * 8,
                                           &public_key_ctx_size);
        ERROR_BREAK(ipp_ret);

        rsa_key_ctx = (IppsRSAPublicKeyState*)malloc(public_key_ctx_size);
        if (!rsa_key_ctx) {
            ipp_ret = ippStsMemAllocErr;
            break;
        }

        // initialize the private key context
        ipp_ret = ippsRSA_InitPublicKey(SGX_RSA3072_KEY_SIZE * 8, SGX_RSA3072_PUB_EXP_SIZE * 8,
                                        rsa_key_ctx, public_key_ctx_size);
        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsRSA_SetPublicKey(p_prikey_mod_bn, p_prikey_exp_bn, rsa_key_ctx);
        ERROR_BREAK(ipp_ret);

        // allocate temp buffer for RSA calculation
        int public_key_buffer_size = 0;

        ipp_ret = ippsRSA_GetBufferSizePublicKey(&public_key_buffer_size, rsa_key_ctx);
        ERROR_BREAK(ipp_ret);

        temp_buff = (Ipp8u*)malloc(public_key_buffer_size);
        if (!temp_buff) {
            ipp_ret = ippStsMemAllocErr;
            break;
        }

//        ipp_ret = sgx_ipp_newBN((const Ipp32u *)data, data_size, &pt_bn);
//        ERROR_BREAK(ipp_ret);
//
//        ipp_ret = sgx_ipp_newBN(0, data_size, &ct_bn);
//        ERROR_BREAK(ipp_ret);

        ipp_ret = ippsRSAEncrypt_PKCSv15(data, data_size,
                                         0, out_data, rsa_key_ctx, temp_buff);
        ERROR_BREAK(ipp_ret);
//
//        Ipp32u * pdata = NULL;
//        ipp_ret = ippsRef_BN(0, 0, &pdata, pt_bn);
//        ERROR_BREAK(ipp_ret);
//        memcpy(out_data, pdata, data_size);
//        ERROR_BREAK(ipp_ret);
    } while (0);

//
//    sgx_ipp_secure_free_BN(ct_bn, data_size);
//    sgx_ipp_secure_free_BN(pt_bn, data_size);

    sgx_ipp_secure_free_BN(p_prikey_mod_bn, sizeof(p_public->mod));
    sgx_ipp_secure_free_BN(p_prikey_exp_bn, sizeof(p_public->exp));
    SAFE_FREE(rsa_key_ctx);
    SAFE_FREE(temp_buff);

    printf(ippGetStatusString(ipp_ret));
    printf("\n");
    return (sgx_status_t)ipp_ret;
}