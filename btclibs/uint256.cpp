// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "uint256.h"

#include "util/strencodings.h"

#include <string.h>

template <unsigned int BITS>
base_blob<BITS>::base_blob(const std::vector<unsigned char>& vch)
{
    assert(vch.size() == sizeof(m_data));
    memcpy(m_data, vch.data(), sizeof(m_data));
}

template <unsigned int BITS>
std::string base_blob<BITS>::GetHex() const
{
    uint8_t m_data_rev[WIDTH];
    for (int i = 0; i < WIDTH; ++i) {
        m_data_rev[i] = m_data[WIDTH - 1 - i];
    }
    return HexStr(m_data_rev);
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const char* psz)
{
    memset(m_data, 0, sizeof(m_data));

    // skip leading spaces
    while (IsSpace(*psz))
        psz++;

    // skip 0x
    if (psz[0] == '0' && ToLower(psz[1]) == 'x')
        psz += 2;

    // hex string to uint
    size_t digits = 0;
    while (::HexDigit(psz[digits]) != -1)
        digits++;
    unsigned char* p1 = (unsigned char*)m_data;
    unsigned char* pend = p1 + WIDTH;
    while (digits > 0 && p1 < pend) {
        *p1 = ::HexDigit(psz[--digits]);
        if (digits > 0) {
            *p1 |= ((unsigned char)::HexDigit(psz[--digits]) << 4);
            p1++;
        }
    }
}

template <unsigned int BITS>
void base_blob<BITS>::SetHex(const std::string& str)
{
    SetHex(str.c_str());
}

template <unsigned int BITS>
std::string base_blob<BITS>::ToString() const
{
    return (GetHex());
}

// Explicit instantiations for base_blob<128>
template base_blob<128>::base_blob(const std::vector<unsigned char> &);
template std::string base_blob<128>::GetHex() const;
template std::string base_blob<128>::ToString() const;
template void base_blob<128>::SetHex(const char *);
template void base_blob<128>::SetHex(const std::string &);

std::istream &operator>>(std::istream &is, uint128 &value)
{
    std::string Hex;
    is >> Hex;
    value.SetHex(Hex);
    return is;
}

std::ostream &operator<<(std::ostream &os, const uint128 &value)
{
    os << value.GetHex();
    return os;
}

// Explicit instantiations for base_blob<160>
template base_blob<160>::base_blob(const std::vector<unsigned char> &);
template std::string base_blob<160>::GetHex() const;
template std::string base_blob<160>::ToString() const;
template void base_blob<160>::SetHex(const char *);
template void base_blob<160>::SetHex(const std::string &);

std::istream &operator>>(std::istream &is, uint160 &value)
{
    std::string Hex;
    is >> Hex;
    value.SetHex(Hex);
    return is;
}

std::ostream &operator<<(std::ostream &os, const uint160 &value)
{
    os << value.GetHex();
    return os;
}

// Explicit instantiations for base_blob<288>
template base_blob<288>::base_blob(const std::vector<unsigned char> &);
template std::string base_blob<288>::GetHex() const;
template std::string base_blob<288>::ToString() const;
template void base_blob<288>::SetHex(const char *);
template void base_blob<288>::SetHex(const std::string &);

std::istream &operator>>(std::istream &is, uint288 &value)
{
    std::string Hex;
    is >> Hex;
    value.SetHex(Hex);
    return is;
}

std::ostream &operator<<(std::ostream &os, const uint288 &value)
{
    os << value.GetHex();
    return os;
}

// Explicit instantiations for base_blob<256>
template base_blob<256>::base_blob(const std::vector<unsigned char> &);
template std::string base_blob<256>::GetHex() const;
template std::string base_blob<256>::ToString() const;
template void base_blob<256>::SetHex(const char *);
template void base_blob<256>::SetHex(const std::string &);

std::istream &operator>>(std::istream &is, uint256 &value)
{
    std::string Hex;
    is >> Hex;
    value.SetHex(Hex);
    return is;
}

std::ostream &operator<<(std::ostream &os, const uint256 &value)
{
    os << value.GetHex();
    return os;
}

uint256 &UINT256_ONE()
{
    static uint256 *one = new uint256(uint256S("0000000000000000000000000000000000000000000000000000000000000001"));
    return *one;
}

const uint256 uint256::ZERO(0);
const uint256 uint256::ONE(1);