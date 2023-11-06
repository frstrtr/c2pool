// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
// Edited by Neels99 for C2Pool:
// arith_uint256 -> old uint256 logic
// added GetHex()/SetHex()

#ifndef C2POOL_UINT256_H
#define C2POOL_UINT256_H

#include <cstring>
#include <limits>
#include <stdexcept>
#include <stdint.h>
#include <string>

#include <nlohmann/json.hpp>

class uint_error : public std::runtime_error {
public:
    explicit uint_error(const std::string& str) : std::runtime_error(str) {}
};

/** Template base class for unsigned big integers. */
template<unsigned int BITS>
class base_uint
{
public:
    static_assert(BITS / 32 > 0 && BITS % 32 == 0, "Template parameter BITS must be a positive multiple of 32.");
    static constexpr int WIDTH = BITS / 32;
    static constexpr int BYTES = BITS / 8; // old uint256.WIDTH
    uint32_t pn[WIDTH];
public:

    base_uint()
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = 0;
    }

    base_uint(const base_uint& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
    }

    explicit base_uint(const std::string& str);
    explicit base_uint(const std::vector<unsigned char>& vch);

//    uint32_t* begin()
//    {
//        return &pn[0];
//    }
//
//    uint32_t* end()
//    {
//        return &pn[WIDTH];
//    }

    base_uint& operator=(const base_uint& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] = b.pn[i];
        return *this;
    }

    base_uint(uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
    }

    const base_uint operator~() const
    {
        base_uint ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        return ret;
    }

    const base_uint operator-() const
    {
        base_uint ret;
        for (int i = 0; i < WIDTH; i++)
            ret.pn[i] = ~pn[i];
        ++ret;
        return ret;
    }

    double getdouble() const;

    base_uint& operator=(uint64_t b)
    {
        pn[0] = (unsigned int)b;
        pn[1] = (unsigned int)(b >> 32);
        for (int i = 2; i < WIDTH; i++)
            pn[i] = 0;
        return *this;
    }

    base_uint& operator^=(const base_uint& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] ^= b.pn[i];
        return *this;
    }

    base_uint& operator&=(const base_uint& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] &= b.pn[i];
        return *this;
    }

    base_uint& operator|=(const base_uint& b)
    {
        for (int i = 0; i < WIDTH; i++)
            pn[i] |= b.pn[i];
        return *this;
    }

    base_uint& operator^=(uint64_t b)
    {
        pn[0] ^= (unsigned int)b;
        pn[1] ^= (unsigned int)(b >> 32);
        return *this;
    }

    base_uint& operator|=(uint64_t b)
    {
        pn[0] |= (unsigned int)b;
        pn[1] |= (unsigned int)(b >> 32);
        return *this;
    }

    base_uint& operator<<=(unsigned int shift);
    base_uint& operator>>=(unsigned int shift);

    base_uint& operator+=(const base_uint& b)
    {
        uint64_t carry = 0;
        for (int i = 0; i < WIDTH; i++)
        {
            uint64_t n = carry + pn[i] + b.pn[i];
            pn[i] = n & 0xffffffff;
            carry = n >> 32;
        }
        return *this;
    }

    base_uint& operator-=(const base_uint& b)
    {
        *this += -b;
        return *this;
    }

    base_uint& operator+=(uint64_t b64)
    {
        base_uint b;
        b = b64;
        *this += b;
        return *this;
    }

    base_uint& operator-=(uint64_t b64)
    {
        base_uint b;
        b = b64;
        *this += -b;
        return *this;
    }

    base_uint& operator*=(uint32_t b32);
    base_uint& operator*=(const base_uint& b);
    base_uint& operator/=(const base_uint& b);

    base_uint& operator++()
    {
        // prefix operator
        int i = 0;
        while (i < WIDTH && ++pn[i] == 0)
            i++;
        return *this;
    }

    const base_uint operator++(int)
    {
        // postfix operator
        const base_uint ret = *this;
        ++(*this);
        return ret;
    }

    base_uint& operator--()
    {
        // prefix operator
        int i = 0;
        while (i < WIDTH && --pn[i] == std::numeric_limits<uint32_t>::max())
            i++;
        return *this;
    }

    const base_uint operator--(int)
    {
        // postfix operator
        const base_uint ret = *this;
        --(*this);
        return ret;
    }

    int CompareTo(const base_uint& b) const;
    bool EqualTo(uint64_t b) const;

    friend inline const base_uint operator+(const base_uint& a, const base_uint& b) { return base_uint(a) += b; }
    friend inline const base_uint operator-(const base_uint& a, const base_uint& b) { return base_uint(a) -= b; }
    friend inline const base_uint operator*(const base_uint& a, const base_uint& b) { return base_uint(a) *= b; }
    friend inline const base_uint operator/(const base_uint& a, const base_uint& b) { return base_uint(a) /= b; }
    friend inline const base_uint operator|(const base_uint& a, const base_uint& b) { return base_uint(a) |= b; }
    friend inline const base_uint operator&(const base_uint& a, const base_uint& b) { return base_uint(a) &= b; }
    friend inline const base_uint operator^(const base_uint& a, const base_uint& b) { return base_uint(a) ^= b; }
    friend inline const base_uint operator>>(const base_uint& a, int shift) { return base_uint(a) >>= shift; }
    friend inline const base_uint operator<<(const base_uint& a, int shift) { return base_uint(a) <<= shift; }
    friend inline const base_uint operator*(const base_uint& a, uint32_t b) { return base_uint(a) *= b; }
    friend inline bool operator==(const base_uint& a, const base_uint& b) { return memcmp(a.pn, b.pn, sizeof(a.pn)) == 0; }
    friend inline bool operator!=(const base_uint& a, const base_uint& b) { return memcmp(a.pn, b.pn, sizeof(a.pn)) != 0; }
    friend inline bool operator>(const base_uint& a, const base_uint& b) { return a.CompareTo(b) > 0; }
    friend inline bool operator<(const base_uint& a, const base_uint& b) { return a.CompareTo(b) < 0; }
    friend inline bool operator>=(const base_uint& a, const base_uint& b) { return a.CompareTo(b) >= 0; }
    friend inline bool operator<=(const base_uint& a, const base_uint& b) { return a.CompareTo(b) <= 0; }
    friend inline bool operator==(const base_uint& a, uint64_t b) { return a.EqualTo(b); }
    friend inline bool operator!=(const base_uint& a, uint64_t b) { return !a.EqualTo(b); }

    std::string GetHex() const;
    void SetHex(const char* psz);
    void SetHex(const std::string& str);
    std::string ToString() const;

    unsigned int size() const
    {
        return sizeof(pn);
    }

    /**
     * Returns the position of the highest bit set plus one, or zero if the
     * value is zero.
     */
    unsigned int bits() const;

    bool IsNull() const
    {
        for (int i = 0; i < WIDTH; i++)
            if (pn[i] != 0)
                return false;
        return true;
    }

    //TODO: test
    void SetNull()
    {
        memset(pn, 0, sizeof(pn));
    }

    uint64_t GetLow64() const
    {
        static_assert(WIDTH >= 2, "Assertion WIDTH >= 2 failed (WIDTH = BITS / 32). BITS is a template parameter.");
        return pn[0] | (uint64_t)pn[1] << 32;
    }

    std::vector<unsigned char> GetChars() const;

    template<typename Stream>
    void Serialize(Stream& s) const
    {
        s.write(MakeByteSpan(pn));
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        s.read(MakeWritableByteSpan(pn));
    }
};

//uint160

/** 128-bit unsigned big integer. */
class uint128 : public base_uint<128>
{
public:
    uint128() = default;
    uint128(const base_uint<128> &b) : base_uint<128>(b) {}
    uint128(uint64_t b) : base_uint<128>(b) {}
    explicit uint128(const std::string& str) : base_uint<128>(str) {}
    explicit uint128(const std::vector<unsigned char>& vch) : base_uint<128>(vch) {}

    uint128& SetCompact(uint32_t nCompact, bool *pfNegative = nullptr, bool *pfOverflow = nullptr);
    uint32_t GetCompact(bool fNegative = false) const;

    friend std::istream &operator>>(std::istream &is, uint128 &value);
    friend std::ostream &operator<<(std::ostream &os, const uint128 &value);
};

/** 160-bit unsigned big integer. */
class uint160 : public base_uint<160>
{
public:
    uint160() = default;
    uint160(const base_uint<160> &b) : base_uint<160>(b) {}
    uint160(uint64_t b) : base_uint<160>(b) {}
    explicit uint160(const std::string& str) : base_uint<160>(str) {}
    explicit uint160(const std::vector<unsigned char>& vch) : base_uint<160>(vch) {}

    uint160& SetCompact(uint32_t nCompact, bool *pfNegative = nullptr, bool *pfOverflow = nullptr);
    uint32_t GetCompact(bool fNegative = false) const;

    friend std::istream &operator>>(std::istream &is, uint160 &value);
    friend std::ostream &operator<<(std::ostream &os, const uint160 &value);
};

/** 256-bit unsigned big integer. */
class uint256 : public base_uint<256> {
public:
    uint256() = default;
    uint256(const base_uint<256>& b) : base_uint<256>(b) {}
    uint256(uint64_t b) : base_uint<256>(b) {}
    explicit uint256(const std::string& str) : base_uint<256>(str) {}
    explicit uint256(const std::vector<unsigned char>& vch) : base_uint<256>(vch) {}

    /**
     * The "compact" format is a representation of a whole
     * number N using an unsigned 32bit number similar to a
     * floating point format.
     * The most significant 8 bits are the unsigned exponent of base 256.
     * This exponent can be thought of as "number of bytes of N".
     * The lower 23 bits are the mantissa.
     * Bit number 24 (0x800000) represents the sign of N.
     * N = (-1^sign) * mantissa * 256^(exponent-3)
     *
     * Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn().
     * MPI uses the most significant bit of the first byte as sign.
     * Thus 0x1234560000 is compact (0x05123456)
     * and  0xc0de000000 is compact (0x0600c0de)
     *
     * Bitcoin only uses this "compact" format for encoding difficulty
     * targets, which are unsigned 256bit quantities.  Thus, all the
     * complexities of the sign bit and using base 256 are probably an
     * implementation accident.
     */
    uint256& SetCompact(uint32_t nCompact, bool *pfNegative = nullptr, bool *pfOverflow = nullptr);
    uint32_t GetCompact(bool fNegative = false) const;

    friend std::istream &operator>>(std::istream &is, uint256 &value);
    friend std::ostream &operator<<(std::ostream &os, const uint256 &value);
};

/** 288-bit unsigned big integer. */
class uint288 : public base_uint<288>
{
public:
    uint288() = default;
    uint288(const base_uint<288> &b) : base_uint<288>(b) {}
    uint288(uint64_t b) : base_uint<288>(b) {}
    explicit uint288(const std::string& str) : base_uint<288>(str) {}
    explicit uint288(const std::vector<unsigned char>& vch) : base_uint<288>(vch) {}

    uint288& SetCompact(uint32_t nCompact, bool *pfNegative = nullptr, bool *pfOverflow = nullptr);
    uint32_t GetCompact(bool fNegative = false) const;

    friend std::istream &operator>>(std::istream &is, uint288 &value);
    friend std::ostream &operator<<(std::ostream &os, const uint288 &value);
};

extern template class base_uint<128>;
extern template class base_uint<160>;
extern template class base_uint<256>;
extern template class base_uint<288>;

// json-128
inline void to_json(nlohmann::json& j, const uint128& p)
{
    j = p.GetHex();
}

inline void from_json(const nlohmann::json& j, uint128& p)
{
    p.SetHex(j.get<std::string>());
}

// json-160
inline void to_json(nlohmann::json& j, const uint160& p)
{
    j = p.GetHex();
}

inline void from_json(const nlohmann::json& j, uint160& p)
{
    p.SetHex(j.get<std::string>());
}

// json-256
inline void to_json(nlohmann::json& j, const uint256& p)
{
    j = p.GetHex();
}

inline void from_json(const nlohmann::json& j, uint256& p)
{
    p.SetHex(j.get<std::string>());
}

// json-288
inline void to_json(nlohmann::json& j, const uint288& p)
{
    j = p.GetHex();
}

inline void from_json(const nlohmann::json& j, uint288& p)
{
    p.SetHex(j.get<std::string>());
}

#endif //C2POOL_UINT256_H
