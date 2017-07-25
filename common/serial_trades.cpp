//
// Created by vytautas on 7/23/17.
//

#include "serial_trades.h"

#include "util.h"

#include <exception>
#include <set>
#include <map>


uint32_t read_i4(uint8_t*& r, uint8_t* end)
{
    if(r+4 > end)
        throw std::runtime_error("Unexpected EOF");
    uint32_t ret = uint32_t(r[0]) | r[1] << 8 | r[2] << 16 | r[3] << 24;
    r += 4;
    return ret;
}

uint64_t read_i8(uint8_t*& r, uint8_t* end)
{
    if(r+8 > end)
        throw std::runtime_error("Unexpected EOF");
    uint64_t ret = uint64_t(r[0]) | r[1] << 8 | r[2] << 16 | r[3] << 24 |
            uint64_t(r[4]) << 32 | uint64_t(r[5]) << 40 | uint64_t(r[6]) << 48 | uint64_t(r[7]) << 56;

    r += 8;
    return ret;
}

string read_str(uint8_t*& r, uint8_t* end)
{
    uint32_t len = read_i4(r, end);
    if(r+len > end)
        throw std::runtime_error("Unexpected EOF");
    string ret((const char*)r, len);
    r += len;
    return ret;
}

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
    printf("nsids %d", n_standardIds);

    vector<shared_ptr<StandardId>> sids;
    for(int i=0;i < n_standardIds; i++) {
        StandardId* sid = new StandardId;
        sid->scheme = read_str(r, end);
        sid->value = read_str(r, end);
        sids.push_back( sid );
    }
    printf("nsids %d", sids.size());

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

buffer write_trades(const vector<ClearedTrade>& trades) {
    buffer ret(2048);

    set<shared_ptr<StandardId>> sids;
    for (int i = 0; i < trades.size(); ++i) {
        sids.insert(trades[i].party);
        sids.insert(trades[i].counter_party);
    }

    map<shared_ptr<StandardId>, uint32_t> sid_to_id;
    ret.put_i4(sids.size());

    uint32_t i = 0;
    for (auto it = sids.begin(); it != sids.end(); ++it, i++) {
        const shared_ptr<StandardId>& sid = *it;
        sid_to_id[*it] = i;
        ret << sid->scheme << sid->value;
    }

    ret.put_i4(trades.size());

    for (int i = 0; i < trades.size(); ++i) {
        ret.put_i4(sid_to_id[trades[i].party]);
        ret.put_i4(sid_to_id[trades[i].counter_party]);
        ret.put_i8(trades[i].value);
    }

    return ret;
}
