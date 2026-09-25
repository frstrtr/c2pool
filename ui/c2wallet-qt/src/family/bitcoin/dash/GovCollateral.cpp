// SPDX-License-Identifier: AGPL-3.0-or-later
#include "GovCollateral.hpp"

#include "DashError.hpp"

// Reused c2pool/btclibs crypto + hex (design §2.4: reuse, never re-implement the
// hash primitives). CHash256 == double-SHA256, the same primitive Dash Core's
// CHashWriter finalizes with. NO dashscript / signer headers here — this TU
// stays on the btclibs closure so the two vendored uint256/hash trees never
// collide in one translation unit.
#include <hash.h>

#include "../hdkeys/HexUtil.hpp"

#include <cstring>

namespace c2w::dash {

namespace {

std::vector<uint8_t> compact_size(uint64_t n)
{
    std::vector<uint8_t> out;
    if (n < 0xFD) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xFFFF) {
        out.push_back(0xFD);
        out.push_back(static_cast<uint8_t>(n & 0xFF));
        out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
    } else if (n <= 0xFFFFFFFFull) {
        out.push_back(0xFE);
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xFF));
    } else {
        out.push_back(0xFF);
        for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xFF));
    }
    return out;
}

template <typename T>
void put_le(std::vector<uint8_t>& v, T value, size_t nbytes)
{
    auto u = static_cast<uint64_t>(static_cast<std::make_unsigned_t<T>>(value));
    for (size_t i = 0; i < nbytes; ++i) v.push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xFF));
}

std::string to_lower_ascii(const std::string& s)
{
    std::string out = s;
    for (char& c : out)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return out;
}

} // namespace

std::array<uint8_t, 32> gov_object_hash(const std::string& parent_hash_hex,
                                        int32_t revision,
                                        int64_t time_,
                                        const std::string& data_hex)
{
    auto parent = hdkeys::from_hex(parent_hash_hex);
    if (!parent || parent->size() != 32)
        throw DashAbort("parent hash must be 32 bytes of hex");

    // data-hex must itself be valid hex (the reference tool refuses "zz"); the
    // bytes that get hashed are the lowercase ASCII of the hex string, NOT the
    // decoded bytes — HexStr(vchData) in Dash Core.
    std::string data = to_lower_ascii(data_hex);
    // trim leading/trailing ASCII whitespace, mirroring the Python .strip().
    size_t b = data.find_first_not_of(" \t\r\n");
    size_t e = data.find_last_not_of(" \t\r\n");
    data = (b == std::string::npos) ? std::string() : data.substr(b, e - b + 1);
    if (!hdkeys::from_hex(data))
        throw DashAbort("data-hex is not valid hex");

    std::vector<uint8_t> ss;
    ss.reserve(96 + data.size());

    // hashParent: input is DISPLAY order, hashed in internal (reversed) order.
    for (auto it = parent->rbegin(); it != parent->rend(); ++it) ss.push_back(*it);

    put_le<int32_t>(ss, revision, 4);
    put_le<int64_t>(ss, time_, 8);

    auto len = compact_size(data.size());
    ss.insert(ss.end(), len.begin(), len.end());
    ss.insert(ss.end(), data.begin(), data.end());

    // null masternodeOutpoint (uint256() hash + n = (uint32)-1).
    ss.insert(ss.end(), 32, 0x00);
    ss.insert(ss.end(), {0xFF, 0xFF, 0xFF, 0xFF});
    // dummy uint8_t{} + 0xffffffff ("to match old hashing" — common.cpp:34).
    ss.push_back(0x00);
    ss.insert(ss.end(), {0xFF, 0xFF, 0xFF, 0xFF});
    // empty vchSig (proposals are unsigned): compactsize 0.
    ss.push_back(0x00);

    std::array<uint8_t, 32> out{};
    legacy::CHash256().Write(ss).Finalize(out);
    return out; // internal byte order
}

std::string gov_hash_display(const std::array<uint8_t, 32>& internal)
{
    std::array<uint8_t, 32> rev{};
    for (size_t i = 0; i < 32; ++i) rev[i] = internal[31 - i];
    return hdkeys::to_hex(rev.data(), rev.size());
}

std::vector<uint8_t> collateral_op_return_script(const std::array<uint8_t, 32>& internal)
{
    std::vector<uint8_t> s;
    s.reserve(34);
    s.push_back(0x6A); // OP_RETURN
    s.push_back(0x20); // 32-byte direct push
    s.insert(s.end(), internal.begin(), internal.end());
    return s;
}

} // namespace c2w::dash
