#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_satus_t etc. */

#include "sgx_tcrypto.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void* SGX_UBRIDGE(SGX_NOCONVENTION, ocall_malloc, (uint32_t size));
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));

sgx_status_t enclave_init(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* e_sealed);
sgx_status_t enclave_close(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* e_sealed);
sgx_status_t e_get_pub_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* pub_key);
sgx_status_t e_exchange_keys(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* client_pub_key_in, sgx_ec256_public_t* enclave_pub_key_out);
sgx_status_t e_encrypt_trades(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* trades, uint32_t trades_size, uint8_t* out_data, uint8_t* gcm_mac);
sgx_status_t semi_local_compress(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* e_trades, uint32_t e_trades_size, uint8_t* trades_mac, uint8_t** e_out_data, uint32_t* e_out_data_size, uint8_t* e_out_mac);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
