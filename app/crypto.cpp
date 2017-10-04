//
// Created by vytautas on 7/27/17.
//

#include "crypto.h"


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sgx.h>
#include <cstdio>

#include <vector>
#include <map>

#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/engine.h>

#include <iostream>
#include <algorithm>
#include <cstring>
#include <exception>
#include <sgx_tcrypto.h>

using namespace std;


#if OPENSSL_VERSION_NUMBER < 0x10100000L
static BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    uint8_t buf[len];
    memcpy(buf, s, len);
    reverse(buf, buf+len);

    return BN_bin2bn(buf, len, ret);
}

static int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    memset(to, 0, tolen);
    BN_bn2bin(a, to);
    reverse(to, to+tolen);
}


static int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    /* If the fields n and e in r are NULL, the corresponding input
     * parameters MUST be non-NULL for n and e.  d may be
     * left NULL (in case only the public key is used).
     */
    if ((r->n == NULL && n == NULL)
        || (r->e == NULL && e == NULL))
        return 0;

    if (n != NULL) {
        BN_free(r->n);
        r->n = n;
    }
    if (e != NULL) {
        BN_free(r->e);
        r->e = e;
    }
    if (d != NULL) {
        BN_free(r->d);
        r->d = d;
    }

    return 1;
}

static void RSA_get0_key(const RSA *r,
                         const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    if (n != NULL)
        *n = r->n;
    if (e != NULL)
        *e = r->e;
    if (d != NULL)
        *d = r->d;
}
#endif

#define SSL_CHECK(X) \
    if(!(X)){ \
        ERR_print_errors_fp(stdout);    \
        throw runtime_error("SSL error");        \
    }
EC_KEY* to_ec_key(sgx_ec256_private_t* prv_key)
{
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM *bn_prv_r = BN_lebin2bn(prv_key->r, 32, 0);
    SSL_CHECK(1 == EC_KEY_set_private_key(ec_key, bn_prv_r));

    return ec_key;
}
EC_KEY* to_ec_key(sgx_ec256_public_t* pub_key)
{
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    EC_POINT *pub = EC_POINT_new(curve);

    BIGNUM *bn_pub_x = BN_lebin2bn(pub_key->gx, 32, 0);
    BIGNUM *bn_pub_y = BN_lebin2bn(pub_key->gy, 32, 0);

    SSL_CHECK(1 == EC_POINT_set_affine_coordinates_GFp(curve, pub, bn_pub_x, bn_pub_y, 0));

    SSL_CHECK(1 == EC_KEY_set_public_key(ec_key, pub));

    EC_GROUP_free(curve);
    return ec_key;
}

void ec256_gen_key(sgx_ec256_private_t *prv_key, sgx_ec256_public_t *pub_key) {
    EC_GROUP *curve;

    SSL_CHECK(NULL != (curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1)));

    EC_KEY *key;

    SSL_CHECK(NULL != (key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)));

    SSL_CHECK(1 == EC_KEY_generate_key(key));

    BIGNUM *prv = (BIGNUM*)EC_KEY_get0_private_key(key);
    BIGNUM *pub_x = BN_new();
    BIGNUM *pub_y = BN_new();

    const EC_POINT* pub_p = EC_KEY_get0_public_key(key);

    SSL_CHECK(1 == EC_POINT_get_affine_coordinates_GFp(curve, pub_p, pub_x, pub_y, 0));

    BN_bn2lebinpad(prv, (uint8_t*)prv_key, 32);
    BN_bn2lebinpad(pub_x, (uint8_t*)pub_key->gx, 32);
    BN_bn2lebinpad(pub_y, (uint8_t*)pub_key->gy, 32);

    EC_GROUP_free(curve);
    EC_KEY_free(key);
    BN_free(pub_x);
    BN_free(pub_y);
}

ec256_dhkey* get_shared_dhkey(sgx_ec256_private_t* prv_key, sgx_ec256_public_t* peer_key)
{
    EC_KEY *ec_key = to_ec_key(prv_key);
    EC_KEY *ec_peer = to_ec_key(peer_key);

    int secret_len = 32;
    uint8_t* secret = (uint8_t*)malloc(32);

    /* Derive the shared secret */
    secret_len = ECDH_compute_key(
            secret, secret_len, EC_KEY_get0_public_key(ec_peer), ec_key, NULL);

    /* Clean up */
    EC_KEY_free(ec_key);
    EC_KEY_free(ec_peer);

    // Big endian -> little endian, so that shared secrets match in app and enclave
    reverse(secret,secret+secret_len);
    return (ec256_dhkey*)secret;
}
void aes128_decrypt(uint8_t *key, uint8_t *data, uint32_t data_size, gcm_tag_t *mac, uint8_t *out_data)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t iv[12] = {0};
    EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv);

    int n_processed = 0;

    //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL); // default: 12
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, mac);

    // Additional Authenticated Data (AAD)
    // EVP_DecryptUpdate(ctx, NULL, &n_processed, 0, 0);

    // decrypting data
    EVP_DecryptUpdate(ctx, out_data, &n_processed, data,
                      data_size);

    // authentication step
    SSL_CHECK(1 == EVP_DecryptFinal(ctx, out_data+n_processed, &n_processed));
    EVP_CIPHER_CTX_free(ctx);
}

void aes128_encrypt(uint8_t *key, const uint8_t *data, uint32_t data_size, uint8_t *out_data, gcm_tag_t *out_mac) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    uint8_t iv[12] = {0};

    int n_processed = 0;

    /* Initialise the encryption operation. */
    SSL_CHECK(1 == EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv));

    //EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL); // default: 12

    // Additional Authenticated Data (AAD)
    // EVP_EncryptUpdate(ctx, NULL, &n_processed, 0, 0);

    SSL_CHECK(1 == EVP_EncryptUpdate(ctx, out_data, &n_processed, data, data_size));

    SSL_CHECK(1 == EVP_EncryptFinal_ex(ctx, out_data + n_processed, &n_processed));

    SSL_CHECK(1 == EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out_mac));

    EVP_CIPHER_CTX_free(ctx);
}

bool ec256_check_point(sgx_ec256_public_t *pub_key) {
    BN_CTX *ctx = BN_CTX_new();

    EC_GROUP *curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    EC_POINT *pub = EC_POINT_new(curve);

    BIGNUM *bn_pub_x = BN_lebin2bn(pub_key->gx, 32, 0);
    BIGNUM *bn_pub_y = BN_lebin2bn(pub_key->gy, 32, 0);

    bool ret = 1 == EC_POINT_set_affine_coordinates_GFp(curve, pub, bn_pub_x, bn_pub_y, ctx);

    BN_free(bn_pub_x);
    BN_free(bn_pub_y);

    EC_POINT_free(pub);
    EC_GROUP_free(curve);
    BN_CTX_free(ctx);

    return ret;
}

AES_GCM_msg ec256_encrypt_msg(sgx_ec256_public_t* pub_key, ec256_dhkey* sk_key, const buffer &msg_data) {
    AES_GCM_msg out_msg;

    out_msg.peer_key = *pub_key;

    out_msg.data = buffer(msg_data.size());
    out_msg.data.size(msg_data.size());
    aes128_encrypt((uint8_t *) sk_key, msg_data.data(), msg_data.size(), out_msg.data.data(), &out_msg.tag);

    return out_msg;
}

buffer ec256_decrypt_msg(sgx_ec256_private_t *prv_key, AES_GCM_msg& msg) {
    ec256_dhkey* sk_key = get_shared_dhkey(prv_key, &msg.peer_key);

    buffer out(msg.data.size());
    out.size(msg.data.size());
    aes128_decrypt((uint8_t*)sk_key, msg.data.data(), msg.data.size(), &msg.tag, out.data());

    free(sk_key);

    return out;
}
