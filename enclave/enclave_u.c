#include "enclave_u.h"
#include <errno.h>

typedef struct ms_enclave_init_t {
	sgx_status_t ms_retval;
	uint8_t* ms_e_sealed;
} ms_enclave_init_t;

typedef struct ms_enclave_close_t {
	sgx_status_t ms_retval;
	uint8_t* ms_e_sealed;
} ms_enclave_close_t;

typedef struct ms_e_get_pub_key_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_pub_key;
} ms_e_get_pub_key_t;

typedef struct ms_e_exchange_keys_t {
	sgx_status_t ms_retval;
	sgx_ec256_public_t* ms_client_pub_key_in;
	sgx_ec256_public_t* ms_enclave_pub_key_out;
} ms_e_exchange_keys_t;

typedef struct ms_e_encrypt_trades_t {
	sgx_status_t ms_retval;
	uint8_t* ms_trades;
	uint32_t ms_trades_size;
	uint8_t* ms_out_data;
	uint8_t* ms_gcm_mac;
} ms_e_encrypt_trades_t;

typedef struct ms_semi_local_compress_t {
	sgx_status_t ms_retval;
	uint8_t* ms_e_trades;
	uint32_t ms_e_trades_size;
	uint8_t* ms_trades_mac;
	uint8_t** ms_e_out_data;
	uint32_t* ms_e_out_data_size;
	uint8_t* ms_e_out_mac;
} ms_semi_local_compress_t;

typedef struct ms_ocall_malloc_t {
	void* ms_retval;
	uint32_t ms_size;
} ms_ocall_malloc_t;

typedef struct ms_ocall_print_string_t {
	int ms_retval;
	char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL enclave_ocall_malloc(void* pms)
{
	ms_ocall_malloc_t* ms = SGX_CAST(ms_ocall_malloc_t*, pms);
	ms->ms_retval = ocall_malloc(ms->ms_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ms->ms_retval = ocall_print_string((const char*)ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_enclave = {
	2,
	{
		(void*)enclave_ocall_malloc,
		(void*)enclave_ocall_print_string,
	}
};
sgx_status_t enclave_init(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* e_sealed)
{
	sgx_status_t status;
	ms_enclave_init_t ms;
	ms.ms_e_sealed = e_sealed;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclave_close(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* e_sealed)
{
	sgx_status_t status;
	ms_enclave_close_t ms;
	ms.ms_e_sealed = e_sealed;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_get_pub_key(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* pub_key)
{
	sgx_status_t status;
	ms_e_get_pub_key_t ms;
	ms.ms_pub_key = pub_key;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_exchange_keys(sgx_enclave_id_t eid, sgx_status_t* retval, sgx_ec256_public_t* client_pub_key_in, sgx_ec256_public_t* enclave_pub_key_out)
{
	sgx_status_t status;
	ms_e_exchange_keys_t ms;
	ms.ms_client_pub_key_in = client_pub_key_in;
	ms.ms_enclave_pub_key_out = enclave_pub_key_out;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t e_encrypt_trades(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* trades, uint32_t trades_size, uint8_t* out_data, uint8_t* gcm_mac)
{
	sgx_status_t status;
	ms_e_encrypt_trades_t ms;
	ms.ms_trades = trades;
	ms.ms_trades_size = trades_size;
	ms.ms_out_data = out_data;
	ms.ms_gcm_mac = gcm_mac;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t semi_local_compress(sgx_enclave_id_t eid, sgx_status_t* retval, uint8_t* e_trades, uint32_t e_trades_size, uint8_t* trades_mac, uint8_t** e_out_data, uint32_t* e_out_data_size, uint8_t* e_out_mac)
{
	sgx_status_t status;
	ms_semi_local_compress_t ms;
	ms.ms_e_trades = e_trades;
	ms.ms_e_trades_size = e_trades_size;
	ms.ms_trades_mac = trades_mac;
	ms.ms_e_out_data = e_out_data;
	ms.ms_e_out_data_size = e_out_data_size;
	ms.ms_e_out_mac = e_out_mac;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

