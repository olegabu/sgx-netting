#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


sgx_status_t enclave_init(uint8_t* e_sealed);
sgx_status_t enclave_close(uint8_t* e_sealed);
sgx_status_t e_get_pub_key(sgx_ec256_public_t* pub_key);
sgx_status_t e_exchange_keys(sgx_ec256_public_t* client_pub_key_in, sgx_ec256_public_t* enclave_pub_key_out);
sgx_status_t e_encrypt_trades(uint8_t* trades, uint32_t trades_size, uint8_t* out_data, uint8_t* gcm_mac);
sgx_status_t semi_local_compress(uint8_t* e_trades, uint32_t e_trades_size, uint8_t* trades_mac, uint8_t** e_out_data, uint32_t* e_out_data_size, uint8_t* e_out_mac);

sgx_status_t SGX_CDECL ocall_malloc(void** retval, uint32_t size);
sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
