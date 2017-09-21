//
// Created by vytautas on 7/26/17.
//

#ifndef SGX_NETTING_BUFFER_H
#define SGX_NETTING_BUFFER_H

#include <stdint.h>
#include <vector>
#include <stdexcept>
#include <string>
#include <cstring>

using std::vector;
using std::string;

class buffer {
    vector<uint8_t> m_data;
    uint32_t read_pos = 0;
public:
    buffer(){}
    buffer(uint32_t reserved_size) {
        m_data.reserve(reserved_size);
    }

    const uint8_t* data() const {
        return (uint8_t*)&m_data[0];
    }
    uint8_t* data() {
        return (uint8_t*)&m_data[0];
    }

    void size(uint32_t new_size) {
        return m_data.resize(new_size);
    }

    uint32_t size() const {
        return m_data.size();
    }

    void read(void* dst, uint32_t n)
    {
        uint8_t* r = &*m_data.begin() + read_pos;
        uint8_t* end = &*m_data.end();
        if(r+n > end)
            throw std::runtime_error("Unexpected EOF");
        memcpy(dst, r, n);
        read_pos += n;
    }

    buffer& write (const void* data, int size) {
        m_data.insert(m_data.end(), (uint8_t*)data, (uint8_t*)data+size);
        return *this;
    }

    buffer& operator << (const string& rhs) {
        put_i4(rhs.size());
        m_data.insert(m_data.end(), rhs.begin(), rhs.end());
        return *this;
    }

    buffer& operator >> (string& rhs) {
        rhs =  read_str();
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

    int32_t read_i4()
    {
        uint8_t* r = &*m_data.begin() + read_pos;
        uint8_t* end = &*m_data.end();
        if(r+4 > end)
            throw std::runtime_error("Unexpected EOF");
        uint32_t ret = uint32_t(r[0]) | r[1] << 8 | r[2] << 16 | r[3] << 24;
        read_pos += 4;
        return (int32_t)ret;
    }

    int64_t read_i8()
    {
        uint8_t* r = &*m_data.begin() + read_pos;
        uint8_t* end = &*m_data.end();
        if(r+8 > end)
            throw std::runtime_error("Unexpected EOF");
        uint64_t ret = uint64_t(r[0]) | r[1] << 8 | r[2] << 16 | r[3] << 24 |
                       uint64_t(r[4]) << 32 | uint64_t(r[5]) << 40 | uint64_t(r[6]) << 48 | uint64_t(r[7]) << 56;

        read_pos += 8;
        return (int64_t)ret;
    }

    string read_str()
    {
        uint8_t* r = &*m_data.begin() + read_pos;
        uint8_t* end = &*m_data.end();
        int32_t len = read_i4();
        if(r+len > end)
            throw std::runtime_error("Unexpected EOF");
        string ret((const char*)r, len);
        read_pos += len;
        return ret;
    }

    uint8_t* read_ptr(){
        return &*m_data.begin() + read_pos;
    }

    uint8_t* begin() {
        return data();
    }
    uint8_t* end() {
        return &*m_data.begin()+m_data.size();
    }
};

inline int32_t read_i4(uint8_t*& r, uint8_t* end)
{
    if(r+4 > end)
        throw std::runtime_error("Unexpected EOF");
    uint32_t ret = uint32_t(r[0]) | r[1] << 8 | r[2] << 16 | r[3] << 24;
    r += 4;
    return (int32_t)ret;
}

inline int64_t read_i8(uint8_t*& r, uint8_t* end)
{
    if(r+8 > end)
        throw std::runtime_error("Unexpected EOF");
    uint64_t ret = uint64_t(r[0]) | r[1] << 8 | r[2] << 16 | r[3] << 24 |
                   uint64_t(r[4]) << 32 | uint64_t(r[5]) << 40 | uint64_t(r[6]) << 48 | uint64_t(r[7]) << 56;

    r += 8;
    return (int64_t)ret;
}

inline string read_str(uint8_t*& r, uint8_t* end)
{
    int32_t len = read_i4(r, end);
    if(r+len > end)
        throw std::runtime_error("Unexpected EOF");
    string ret((const char*)r, len);
    r += len;
    return ret;
}

inline buffer& operator <<(buffer& buf, const buffer& rhs){
    buf.put_i4(rhs.size());
    buf.write(rhs.data(),rhs.size());
    return buf;
}

inline buffer& operator >>(buffer& buf, buffer& rhs){
    uint32_t size = buf.read_i4();
    rhs = buffer(size);
    buf.read(rhs.data(), size);
    return buf;
}

#endif //SGX_NETTING_BUFFER_H
