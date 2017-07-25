#include "enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */

#include <errno.h>
#include <string.h> /* for memcpy etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)


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

static sgx_status_t SGX_CDECL sgx_enclave_init(void* pms)
{
	ms_enclave_init_t* ms = SGX_CAST(ms_enclave_init_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_e_sealed = ms->ms_e_sealed;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_init_t));

	ms->ms_retval = enclave_init(_tmp_e_sealed);


	return status;
}

static sgx_status_t SGX_CDECL sgx_enclave_close(void* pms)
{
	ms_enclave_close_t* ms = SGX_CAST(ms_enclave_close_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_e_sealed = ms->ms_e_sealed;

	CHECK_REF_POINTER(pms, sizeof(ms_enclave_close_t));

	ms->ms_retval = enclave_close(_tmp_e_sealed);


	return status;
}

static sgx_status_t SGX_CDECL sgx_e_get_pub_key(void* pms)
{
	ms_e_get_pub_key_t* ms = SGX_CAST(ms_e_get_pub_key_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_pub_key = ms->ms_pub_key;

	CHECK_REF_POINTER(pms, sizeof(ms_e_get_pub_key_t));

	ms->ms_retval = e_get_pub_key(_tmp_pub_key);


	return status;
}

static sgx_status_t SGX_CDECL sgx_e_exchange_keys(void* pms)
{
	ms_e_exchange_keys_t* ms = SGX_CAST(ms_e_exchange_keys_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_ec256_public_t* _tmp_client_pub_key_in = ms->ms_client_pub_key_in;
	sgx_ec256_public_t* _tmp_enclave_pub_key_out = ms->ms_enclave_pub_key_out;

	CHECK_REF_POINTER(pms, sizeof(ms_e_exchange_keys_t));

	ms->ms_retval = e_exchange_keys(_tmp_client_pub_key_in, _tmp_enclave_pub_key_out);


	return status;
}

static sgx_status_t SGX_CDECL sgx_e_encrypt_trades(void* pms)
{
	ms_e_encrypt_trades_t* ms = SGX_CAST(ms_e_encrypt_trades_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_trades = ms->ms_trades;
	uint32_t _tmp_trades_size = ms->ms_trades_size;
	size_t _len_trades = _tmp_trades_size;
	uint8_t* _in_trades = NULL;
	uint8_t* _tmp_out_data = ms->ms_out_data;
	size_t _len_out_data = sizeof(*_tmp_out_data);
	uint8_t* _in_out_data = NULL;
	uint8_t* _tmp_gcm_mac = ms->ms_gcm_mac;
	size_t _len_gcm_mac = 16;
	uint8_t* _in_gcm_mac = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_e_encrypt_trades_t));
	CHECK_UNIQUE_POINTER(_tmp_trades, _len_trades);
	CHECK_UNIQUE_POINTER(_tmp_out_data, _len_out_data);
	CHECK_UNIQUE_POINTER(_tmp_gcm_mac, _len_gcm_mac);

	if (_tmp_trades != NULL) {
		_in_trades = (uint8_t*)malloc(_len_trades);
		if (_in_trades == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_trades, _tmp_trades, _len_trades);
	}
	if (_tmp_out_data != NULL) {
		if ((_in_out_data = (uint8_t*)malloc(_len_out_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_data, 0, _len_out_data);
	}
	if (_tmp_gcm_mac != NULL) {
		if ((_in_gcm_mac = (uint8_t*)malloc(_len_gcm_mac)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_gcm_mac, 0, _len_gcm_mac);
	}
	ms->ms_retval = e_encrypt_trades(_in_trades, _tmp_trades_size, _in_out_data, _in_gcm_mac);
err:
	if (_in_trades) free(_in_trades);
	if (_in_out_data) {
		memcpy(_tmp_out_data, _in_out_data, _len_out_data);
		free(_in_out_data);
	}
	if (_in_gcm_mac) {
		memcpy(_tmp_gcm_mac, _in_gcm_mac, _len_gcm_mac);
		free(_in_gcm_mac);
	}

	return status;
}

static sgx_status_t SGX_CDECL sgx_semi_local_compress(void* pms)
{
	ms_semi_local_compress_t* ms = SGX_CAST(ms_semi_local_compress_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_e_trades = ms->ms_e_trades;
	uint32_t _tmp_e_trades_size = ms->ms_e_trades_size;
	size_t _len_e_trades = _tmp_e_trades_size;
	uint8_t* _in_e_trades = NULL;
	uint8_t* _tmp_trades_mac = ms->ms_trades_mac;
	size_t _len_trades_mac = 16;
	uint8_t* _in_trades_mac = NULL;
	uint8_t** _tmp_e_out_data = ms->ms_e_out_data;
	size_t _len_e_out_data = sizeof(*_tmp_e_out_data);
	uint8_t** _in_e_out_data = NULL;
	uint32_t* _tmp_e_out_data_size = ms->ms_e_out_data_size;
	size_t _len_e_out_data_size = 4;
	uint32_t* _in_e_out_data_size = NULL;
	uint8_t* _tmp_e_out_mac = ms->ms_e_out_mac;
	size_t _len_e_out_mac = 16;
	uint8_t* _in_e_out_mac = NULL;

	CHECK_REF_POINTER(pms, sizeof(ms_semi_local_compress_t));
	CHECK_UNIQUE_POINTER(_tmp_e_trades, _len_e_trades);
	CHECK_UNIQUE_POINTER(_tmp_trades_mac, _len_trades_mac);
	CHECK_UNIQUE_POINTER(_tmp_e_out_data, _len_e_out_data);
	CHECK_UNIQUE_POINTER(_tmp_e_out_data_size, _len_e_out_data_size);
	CHECK_UNIQUE_POINTER(_tmp_e_out_mac, _len_e_out_mac);

	if (_tmp_e_trades != NULL) {
		_in_e_trades = (uint8_t*)malloc(_len_e_trades);
		if (_in_e_trades == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_e_trades, _tmp_e_trades, _len_e_trades);
	}
	if (_tmp_trades_mac != NULL) {
		_in_trades_mac = (uint8_t*)malloc(_len_trades_mac);
		if (_in_trades_mac == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_trades_mac, _tmp_trades_mac, _len_trades_mac);
	}
	if (_tmp_e_out_data != NULL) {
		if ((_in_e_out_data = (uint8_t**)malloc(_len_e_out_data)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_e_out_data, 0, _len_e_out_data);
	}
	if (_tmp_e_out_data_size != NULL) {
		_in_e_out_data_size = (uint32_t*)malloc(_len_e_out_data_size);
		if (_in_e_out_data_size == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memcpy(_in_e_out_data_size, _tmp_e_out_data_size, _len_e_out_data_size);
	}
	if (_tmp_e_out_mac != NULL) {
		if ((_in_e_out_mac = (uint8_t*)malloc(_len_e_out_mac)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_e_out_mac, 0, _len_e_out_mac);
	}
	ms->ms_retval = semi_local_compress(_in_e_trades, _tmp_e_trades_size, _in_trades_mac, _in_e_out_data, _in_e_out_data_size, _in_e_out_mac);
err:
	if (_in_e_trades) free(_in_e_trades);
	if (_in_trades_mac) free(_in_trades_mac);
	if (_in_e_out_data) {
		memcpy(_tmp_e_out_data, _in_e_out_data, _len_e_out_data);
		free(_in_e_out_data);
	}
	if (_in_e_out_data_size) {
		memcpy(_tmp_e_out_data_size, _in_e_out_data_size, _len_e_out_data_size);
		free(_in_e_out_data_size);
	}
	if (_in_e_out_mac) {
		memcpy(_tmp_e_out_mac, _in_e_out_mac, _len_e_out_mac);
		free(_in_e_out_mac);
	}

	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[6];
} g_ecall_table = {
	6,
	{
		{(void*)(uintptr_t)sgx_enclave_init, 0},
		{(void*)(uintptr_t)sgx_enclave_close, 0},
		{(void*)(uintptr_t)sgx_e_get_pub_key, 0},
		{(void*)(uintptr_t)sgx_e_exchange_keys, 0},
		{(void*)(uintptr_t)sgx_e_encrypt_trades, 0},
		{(void*)(uintptr_t)sgx_semi_local_compress, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][6];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_malloc(void** retval, uint32_t size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_malloc_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_malloc_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_malloc_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_malloc_t));

	ms->ms_size = size;
	status = sgx_ocall(0, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_string(int* retval, const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;

	ocalloc_size += (str != NULL && sgx_is_within_enclave(str, _len_str)) ? _len_str : 0;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));

	if (str != NULL && sgx_is_within_enclave(str, _len_str)) {
		ms->ms_str = (char*)__tmp;
		__tmp = (void *)((size_t)__tmp + _len_str);
		memcpy((void*)ms->ms_str, str, _len_str);
	} else if (str == NULL) {
		ms->ms_str = NULL;
	} else {
		sgx_ocfree();
		return SGX_ERROR_INVALID_PARAMETER;
	}
	
	status = sgx_ocall(1, ms);

	if (retval) *retval = ms->ms_retval;

	sgx_ocfree();
	return status;
}

