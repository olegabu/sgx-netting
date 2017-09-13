//
// Created by vytautas on 9/13/17.
//

#ifndef SGX_NETTING_APP_H
#define SGX_NETTING_APP_H

#include <sgx_urts.h>
#include <vector>
#include <stdarg.h>

#include "trade.h"
#include "buffer.h"

using std::vector;

vector<ClearedTrade> load_trades();
int algo_ec256(sgx_enclave_id_t enclave_id, buffer& trade_data);

extern struct AppGData {
    sgx_enclave_id_t   enclave_id;
    sgx_launch_token_t launch_token;
} G;

/**
 * App global initializer
 * @param enclave_changed Indicates whether enclave changed (due to hw usually)
 */
void app_init(bool& enclave_changed);

void app_close();

inline void errorf(const char* fmt, ...) {
    va_list ap;
    char buf[BUFSIZ] = {0};
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);

    throw runtime_error(buf);
}
#endif //SGX_NETTING_APP_H
