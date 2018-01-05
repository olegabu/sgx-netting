//
// Created by vytautas on 7/23/17.
//

#include "serial_trades.h"

#include "util.h"

#include <exception>
#include <set>
#include <map>

using std::set;
using std::map;

/* The serialized trade_data:
 *  - uint32_t n_standardIds
 *  - list of StandardId where StandardId:
 *    - string scheme
 *    - string value
 *      where string:
 *       - uint32_t size;
 *       - uint8_t[size] data;
 *  - uint32_t n_trades
 *  - list of trades where trade:
 *    - uint32_t party_a;
 *    - uint32_t party_b;
 *    - uint64_t value;
 */
vector<ClearedTrade> read_trades(uint8_t *trade_data, uint32_t trades_size) {
    vector<ClearedTrade> ret;

    uint8_t* r = trade_data;
    uint8_t* end = trade_data + trades_size;

    uint32_t n_standardIds = read_i4(r, end);

    vector<party_id_t> sids;
    for(int i=0;i < n_standardIds; i++) {
        sids.push_back(read_str(r, end));
    }

    uint32_t n_trades = read_i4(r, end);
    vector<ClearedTrade>  trades;
    for(int i=0;i < n_trades; i++) {
        ClearedTrade trade;
        uint32_t p_a = read_i4(r, end);
        if(p_a >= n_standardIds)
            throw std::runtime_error("Bad id");
        trade.party = sids[p_a];
        uint32_t p_b = read_i4(r, end);
        if(p_b >= n_standardIds)
            throw std::runtime_error("Bad id");
        trade.counter_party = sids[p_b];
        trade.value = read_i8(r, end);
        trades.push_back( trade );
    }

    return trades;
}

void write_trades(const vector<ClearedTrade>& trades, buffer& to_buf) {

    set<party_id_t> sids;
    for (int i = 0; i < trades.size(); ++i) {
        sids.insert(trades[i].party);
        sids.insert(trades[i].counter_party);
    }

    map<party_id_t, uint32_t> sid_to_id;
    to_buf.put_i4(sids.size());

    uint32_t i = 0;
    for (auto it = sids.begin(); it != sids.end(); ++it, i++) {
        const party_id_t& sid = *it;
        sid_to_id[*it] = i;
        to_buf << sid;
    }

    to_buf.put_i4(trades.size());

    for (int i = 0; i < trades.size(); ++i) {
        to_buf.put_i4(sid_to_id[trades[i].party]);
        to_buf.put_i4(sid_to_id[trades[i].counter_party]);
        to_buf.put_i8(trades[i].value);
    }
}
