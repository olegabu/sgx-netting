//
// Created by vytautas on 7/23/17.
//

#ifndef SGX_NETTING_TRADE_H
#define SGX_NETTING_TRADE_H

#include <string>
using std::string;

#include "shared_ptr.h"

struct StandardId {
    StandardId(){}
    StandardId(string scheme, string value)
            : scheme(scheme),value(value) {}

    string scheme, value;

    string str() {
        return scheme + "~" + value;
    }
};

//typedef shared_ptr<StandardId> party_id_t;
typedef string party_id_t;
typedef int64_t value_t;

struct ClearedTrade {
    ClearedTrade(){}
    party_id_t party;
    party_id_t counter_party;
    value_t value; // Sell if positive, buy if negative
};

#endif //SGX_NETTING_TRADE_H
