//
// Created by vytautas on 7/23/17.
//

#ifndef SGX_NETTING_SERIAL_TRADES_H
#define SGX_NETTING_SERIAL_TRADES_H

#include "trade.h"

#include "buffer.h"

vector<ClearedTrade> read_trades(uint8_t* trade_data, uint32_t trades_size);

buffer write_trades(const vector<ClearedTrade>& trades);

#endif //SGX_NETTING_SERIAL_TRADES_H
