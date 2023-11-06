// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_UINT256_H
#define BITCOIN_UINT256_H

#include "span.h"

#include <assert.h>
#include <cstring>
#include <stdint.h>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

#ifdef DEBUG
    #define UPDATE_HEX_STR()      \
        hex_str = GetHex()
#else
    #define UPDATE_HEX_STR()
#endif
/** Template base class for fixed-sized opaque blobs. */
template <unsigned int BITS>
class base_blob
{
public:
    static constexpr int WIDTH = BITS / 8;
public:
#ifdef DEBUG
    std::string hex_str;
#endif

    uint8_t m_data[WIDTH];
public:
    /* construct 0 value by default */
    constexpr base_blob() : m_data()
    {
        UPDATE_HEX_STR();
    }

    /* constructor for constants between 1 and 255 */
    constexpr explicit base_blob(uint8_t v) : m_data{v}
    {
        UPDATE_HEX_STR();
    }

    explicit base_blob(const std::vector<unsigned char>& vch);

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (m_data[i] != 0)
                return false;
        return true;
    }

    void SetNull()
    {
        memset(m_data, 0, sizeof(m_data));
        UPDATE_HEX_STR();
    }

    inline int Compare(const base_blob& other) const {
//        return memcmp(m_data, other.m_data, sizeof(m_data));
        for (int i = WIDTH - 1; i >= 0; i--)
        {
            if (m_data[i] < other.m_data[i])
                return -1;
            if (m_data[i] > other.m_data[i])
                return 1;
        }
        return 0;
    }

    friend inline bool operator==(const base_blob& a, const base_blob& b) { return a.Compare(b) == 0; }
    friend inline bool operator!=(const base_blob& a, const base_blob& b) { return a.Compare(b) != 0; }
    friend inline bool operator<(const base_blob& a, const base_blob& b) { return a.Compare(b) < 0; }
    friend inline bool operator>(const base_blob &a, const base_blob &b) { return a.Compare(b) > 0; }

    std::string GetHex() const;
    void SetHex(const char* psz);
    void SetHex(const std::string& str);
    std::string ToString() const;

    const unsigned char* data() const { return m_data; }
    unsigned char* data() { return m_data; }

    unsigned char* begin()
    {
        return &m_data[0];
    }

    unsigned char* end()
    {
        return &m_data[WIDTH];
    }

    const unsigned char* begin() const
    {
        return &m_data[0];
    }

    const unsigned char* end() const
    {
        return &m_data[WIDTH];
    }

    static constexpr unsigned int size()
    {
        return sizeof(m_data);
    }

    uint64_t GetUint64(int pos) const
    {
        const uint8_t* ptr = m_data + pos * 8;
        return ((uint64_t)ptr[0]) | \
               ((uint64_t)ptr[1]) << 8 | \
               ((uint64_t)ptr[2]) << 16 | \
               ((uint64_t)ptr[3]) << 24 | \
               ((uint64_t)ptr[4]) << 32 | \
               ((uint64_t)ptr[5]) << 40 | \
               ((uint64_t)ptr[6]) << 48 | \
               ((uint64_t)ptr[7]) << 56;
    }

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(MakeByteSpan(m_data));
        UPDATE_HEX_STR();
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read(MakeWritableByteSpan(m_data));
    }
};

class uint128 : public base_blob<128>
{
public:
    uint128() {}
    explicit uint128(const std::vector<unsigned char> &vch) : base_blob<128>(vch) {}

    friend std::istream &operator>>(std::istream &is, uint128 &value);
    friend std::ostream &operator<<(std::ostream &os, const uint128 &value);
};

/** 160-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 160 bits and has no integer operations.
 */
class uint160 : public base_blob<160>
{
public:
    constexpr uint160() {}
    explicit uint160(const std::vector<unsigned char> &vch) : base_blob<160>(vch) {}

    friend std::istream &operator>>(std::istream &is, uint160 &value);
    friend std::ostream &operator<<(std::ostream &os, const uint160 &value);
};

/** 256-bit opaque blob.
 * @note This type is called uint256 for historical reasons only. It is an
 * opaque blob of 256 bits and has no integer operations. Use arith_uint256 if
 * those are required.
 */
class uint256 : public base_blob<256>
{
public:
    constexpr uint256() {}
    constexpr explicit uint256(uint8_t v) : base_blob<256>(v) {}
    explicit uint256(const std::vector<unsigned char>& vch) : base_blob<256>(vch) {}
    static const uint256 ZERO;
    static const uint256 ONE;

    friend std::istream &operator>>(std::istream &is, uint256 &value);
    friend std::ostream &operator<<(std::ostream &os, const uint256 &value);
};

/** 288-bit opaque blob.
 * @note This type is called uint160 for historical reasons only. It is an opaque
 * blob of 288 bits and has no integer operations.
 */
class uint288 : public base_blob<288>
{
public:
    constexpr uint288() {}
    explicit uint288(const std::vector<unsigned char> &vch) : base_blob<288>(vch) {}

    friend std::istream &operator>>(std::istream &is, uint288 &value);
    friend std::ostream &operator<<(std::ostream &os, const uint288 &value);
};

/* uint256 from const char *.
 * This is a separate function because the constructor uint256(const char*) can result
 * in dangerously catching uint256(0).
 */
inline uint256 uint256S(const char *str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}
/* uint256 from std::string.
 * This is a separate function because the constructor uint256(const std::string &str) can result
 * in dangerously catching uint256(0) via std::string(const char*).
 */
inline uint256 uint256S(const std::string &str)
{
    uint256 rv;
    rv.SetHex(str);
    return rv;
}

uint256 &UINT256_ONE();

inline void to_json(nlohmann::json& j, const uint256& p)
{
    j = p.GetHex();
}

inline void from_json(const nlohmann::json& j, uint256& p)
{
    p.SetHex(j.get<std::string>());
}

inline void to_json(nlohmann::json& j, const uint288& p)
{
    j = p.GetHex();
}

inline void from_json(const nlohmann::json& j, uint288& p)
{
    p.SetHex(j.get<std::string>());
}

inline void to_json(nlohmann::json& j, const uint160& p)
{
    j = p.GetHex();
}

inline void from_json(const nlohmann::json& j, uint160& p)
{
    p.SetHex(j.get<std::string>());
}

inline void to_json(nlohmann::json& j, const uint128& p)
{
    j = p.GetHex();
}

inline void from_json(const nlohmann::json& j, uint128& p)
{
    p.SetHex(j.get<std::string>());
}

#endif // BITCOIN_UINT256_H