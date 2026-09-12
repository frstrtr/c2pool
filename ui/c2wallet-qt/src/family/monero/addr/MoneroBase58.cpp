// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
#include "MoneroBase58.hpp"

#include <array>

namespace c2wallet::monero {

namespace {

constexpr char kAlphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"; // 58 chars, no 0OIl
constexpr std::size_t kAlphabetSize = 58;
constexpr std::size_t kFullBlockSize = 8;
constexpr std::size_t kFullEncodedBlockSize = 11;

// Encoded size for a block of 0..8 raw bytes.
constexpr std::array<int, kFullBlockSize + 1> kEncodedBlockSizes =
    {0, 2, 3, 5, 6, 7, 9, 10, 11};

// Inverse: raw byte count for an encoded block of 0..11 characters; -1 = invalid.
constexpr std::array<int, kFullEncodedBlockSize + 1> kDecodedBlockSizes =
    {0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8};

std::uint64_t uint_from_bytes_be(const std::uint8_t* p, std::size_t size)
{
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < size; ++i)
        v = (v << 8) | p[i];
    return v;
}

void uint_to_bytes_be(std::uint64_t v, std::size_t size, std::uint8_t* out)
{
    for (std::size_t i = 0; i < size; ++i)
        out[size - 1 - i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
}

void encode_block(const std::uint8_t* block, std::size_t size, std::string& out)
{
    int enc_size = kEncodedBlockSizes[size];
    std::uint64_t num = uint_from_bytes_be(block, size);
    std::size_t base = out.size();
    out.append(static_cast<std::size_t>(enc_size), kAlphabet[0]);
    int i = enc_size - 1;
    while (num > 0 && i >= 0) {
        out[base + static_cast<std::size_t>(i)] = kAlphabet[num % kAlphabetSize];
        num /= kAlphabetSize;
        --i;
    }
}

int alphabet_index(char c)
{
    for (std::size_t i = 0; i < kAlphabetSize; ++i)
        if (kAlphabet[i] == c)
            return static_cast<int>(i);
    return -1;
}

bool decode_block(const char* block, std::size_t enc_size, std::vector<std::uint8_t>& out)
{
    if (enc_size > kFullEncodedBlockSize)
        return false;
    int dec_size = kDecodedBlockSizes[enc_size];
    if (dec_size <= 0)
        return false;

    std::uint64_t num = 0;
    std::uint64_t order = 1;
    for (std::size_t i = enc_size; i-- > 0;) {
        int digit = alphabet_index(block[i]);
        if (digit < 0)
            return false;
        std::uint64_t add = order * static_cast<std::uint64_t>(digit);
        // Overflow guard: num + add must not wrap 2^64.
        if (num + add < num)
            return false;
        num += add;
        if (i != 0)
            order *= kAlphabetSize;
    }
    // The decoded value must fit in dec_size bytes.
    if (dec_size < 8 && num >= (std::uint64_t(1) << (8 * dec_size)))
        return false;

    std::size_t base = out.size();
    out.resize(base + static_cast<std::size_t>(dec_size));
    uint_to_bytes_be(num, static_cast<std::size_t>(dec_size), out.data() + base);
    return true;
}

} // namespace

std::string base58_encode(const std::vector<std::uint8_t>& data)
{
    std::string out;
    std::size_t full_blocks = data.size() / kFullBlockSize;
    std::size_t rem = data.size() % kFullBlockSize;
    for (std::size_t i = 0; i < full_blocks; ++i)
        encode_block(data.data() + i * kFullBlockSize, kFullBlockSize, out);
    if (rem > 0)
        encode_block(data.data() + full_blocks * kFullBlockSize, rem, out);
    return out;
}

bool base58_decode(const std::string& enc, std::vector<std::uint8_t>& out)
{
    out.clear();
    std::size_t full_blocks = enc.size() / kFullEncodedBlockSize;
    std::size_t rem = enc.size() % kFullEncodedBlockSize;
    for (std::size_t i = 0; i < full_blocks; ++i)
        if (!decode_block(enc.data() + i * kFullEncodedBlockSize, kFullEncodedBlockSize, out))
            return false;
    if (rem > 0)
        if (!decode_block(enc.data() + full_blocks * kFullEncodedBlockSize, rem, out))
            return false;
    return true;
}

} // namespace c2wallet::monero
