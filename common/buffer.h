//
// Created by vytautas on 7/26/17.
//

#ifndef SGX_NETTING_BUFFER_H
#define SGX_NETTING_BUFFER_H

#include <stdint.h>
#include <vector>

using std::vector;

class buffer {
    vector<uint8_t> m_data;
public:
    buffer(){}
    buffer(uint32_t reserved_size) {
        m_data.reserve(reserved_size);
    }

    const uint8_t* data() const {
        return (uint8_t*)&m_data[0];
    }

    uint32_t size() const {
        return m_data.size();
    }

    buffer& write (const uint8_t* data, int size) {
        m_data.insert(m_data.end(), data, data+size);
        return *this;
    }

    buffer& operator << (const string& rhs) {
        m_data.insert(m_data.end(), rhs.begin(), rhs.end());
        return *this;
    }

    void put_i4(int32_t i) {
        uint8_t* i_b = (uint8_t*)&i;
        m_data.insert(m_data.end(), i_b, i_b + 4);
    }
    void put_i8(int64_t i) {
        uint8_t* i_b = (uint8_t*)&i;
        m_data.insert(m_data.end(), i_b, i_b + 8);
    }
};

#endif //SGX_NETTING_BUFFER_H
