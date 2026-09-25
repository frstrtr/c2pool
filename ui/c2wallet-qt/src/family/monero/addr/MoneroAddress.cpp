// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
#include "MoneroAddress.hpp"
#include "MoneroBase58.hpp"

#include <cstring>

namespace c2wallet::monero {

namespace {

// Minimal CryptoNote varint writer (little-endian base-128).
void write_varint(std::uint64_t v, std::vector<std::uint8_t>& out)
{
    while (v >= 0x80) {
        out.push_back(static_cast<std::uint8_t>((v & 0x7f) | 0x80));
        v >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(v));
}

// Read a varint; returns bytes consumed, or 0 on malformed input.
std::size_t read_varint(const std::uint8_t* p, std::size_t len, std::uint64_t& v)
{
    v = 0;
    int shift = 0;
    for (std::size_t i = 0; i < len && i < 10; ++i) {
        std::uint8_t b = p[i];
        v |= static_cast<std::uint64_t>(b & 0x7f) << shift;
        if ((b & 0x80) == 0)
            return i + 1;
        shift += 7;
    }
    return 0;
}

void append_checksum(std::vector<std::uint8_t>& data)
{
    Bytes32 h = mcrypto::keccak256(data.data(), data.size());
    data.insert(data.end(), h.begin(), h.begin() + 4);
}

} // namespace

std::uint64_t address_tag(Network net, AddressType type)
{
    switch (net) {
    case Network::Mainnet:
        return type == AddressType::Standard ? 18
             : type == AddressType::Integrated ? 19 : 42;
    case Network::Testnet:
        return type == AddressType::Standard ? 53
             : type == AddressType::Integrated ? 54 : 63;
    case Network::Stagenet:
        return type == AddressType::Standard ? 24
             : type == AddressType::Integrated ? 25 : 36;
    }
    return 18;
}

std::string address_encode(const MoneroAddress& a)
{
    std::vector<std::uint8_t> data;
    write_varint(address_tag(a.net, a.type), data);
    data.insert(data.end(), a.spend_pub.begin(), a.spend_pub.end());
    data.insert(data.end(), a.view_pub.begin(), a.view_pub.end());
    if (a.type == AddressType::Integrated)
        data.insert(data.end(), a.payment_id.begin(), a.payment_id.end());
    append_checksum(data);
    return base58_encode(data);
}

bool address_decode(const std::string& s, MoneroAddress& out, std::string& err)
{
    std::vector<std::uint8_t> data;
    if (!base58_decode(s, data)) {
        err = "not valid Monero base58";
        return false;
    }
    std::uint64_t tag = 0;
    std::size_t tag_len = read_varint(data.data(), data.size(), tag);
    if (tag_len == 0) {
        err = "malformed network tag";
        return false;
    }

    // Identify network + type from the tag.
    bool found = false;
    for (Network net : {Network::Mainnet, Network::Testnet, Network::Stagenet}) {
        for (AddressType type : {AddressType::Standard, AddressType::Integrated,
                                 AddressType::Subaddress}) {
            if (address_tag(net, type) == tag) {
                out.net = net;
                out.type = type;
                found = true;
                break;
            }
        }
        if (found) break;
    }
    if (!found) {
        err = "unknown address tag " + std::to_string(tag);
        return false;
    }

    std::size_t body = 64 + (out.type == AddressType::Integrated ? 8 : 0);
    std::size_t need = tag_len + body + 4;
    if (data.size() != need) {
        err = "wrong decoded length for address type";
        return false;
    }

    // Verify checksum over everything but the trailing 4 bytes.
    Bytes32 h = mcrypto::keccak256(data.data(), data.size() - 4);
    if (std::memcmp(h.data(), data.data() + data.size() - 4, 4) != 0) {
        err = "checksum mismatch";
        return false;
    }

    const std::uint8_t* p = data.data() + tag_len;
    std::memcpy(out.spend_pub.data(), p, 32);
    std::memcpy(out.view_pub.data(), p + 32, 32);
    if (out.type == AddressType::Integrated) {
        std::memcpy(out.payment_id.data(), p + 64, 8);
        out.has_payment_id = true;
    }
    return true;
}

MoneroAddress make_standard(const Bytes32& spend_pub, const Bytes32& view_pub, Network net)
{
    MoneroAddress a;
    a.net = net;
    a.type = AddressType::Standard;
    a.spend_pub = spend_pub;
    a.view_pub = view_pub;
    return a;
}

MoneroAddress make_integrated(const Bytes32& spend_pub, const Bytes32& view_pub,
                              const std::array<std::uint8_t, 8>& payment_id, Network net)
{
    MoneroAddress a;
    a.net = net;
    a.type = AddressType::Integrated;
    a.spend_pub = spend_pub;
    a.view_pub = view_pub;
    a.payment_id = payment_id;
    a.has_payment_id = true;
    return a;
}

SubaddressResult derive_subaddress(const Bytes32& view_priv, const Bytes32& spend_pub,
                                   std::uint32_t major, std::uint32_t minor, Network net)
{
    SubaddressResult r;

    // Index (0,0) is the primary address itself (standard tag), never a
    // netbyte-42 subaddress.
    if (major == 0 && minor == 0) {
        Bytes32 view_pub{};
        if (!mcrypto::secret_to_public(view_priv, view_pub)) {
            r.error = "view private key is not a canonical scalar";
            return r;
        }
        r.sub_spend_pub = spend_pub;
        r.sub_view_pub = view_pub;
        r.addr = make_standard(spend_pub, view_pub, net);
        r.ok = true;
        return r;
    }

    // m = H_s("SubAddr\0" || k_v || major_le32 || minor_le32)
    std::array<std::uint8_t, 8 + 32 + 4 + 4> buf{};
    static const char kPrefix[8] = {'S', 'u', 'b', 'A', 'd', 'd', 'r', '\0'};
    std::memcpy(buf.data(), kPrefix, 8);
    std::memcpy(buf.data() + 8, view_priv.data(), 32);
    buf[40] = static_cast<std::uint8_t>(major & 0xff);
    buf[41] = static_cast<std::uint8_t>((major >> 8) & 0xff);
    buf[42] = static_cast<std::uint8_t>((major >> 16) & 0xff);
    buf[43] = static_cast<std::uint8_t>((major >> 24) & 0xff);
    buf[44] = static_cast<std::uint8_t>(minor & 0xff);
    buf[45] = static_cast<std::uint8_t>((minor >> 8) & 0xff);
    buf[46] = static_cast<std::uint8_t>((minor >> 16) & 0xff);
    buf[47] = static_cast<std::uint8_t>((minor >> 24) & 0xff);
    r.m = mcrypto::hash_to_scalar(buf.data(), buf.size());

    // K_s^(i,j) = K_s + m*G
    Bytes32 mG{};
    if (!mcrypto::secret_to_public(r.m, mG)) {
        r.error = "failed to derive m*G";
        return r;
    }
    if (!mcrypto::point_add(spend_pub, mG, r.sub_spend_pub)) {
        r.error = "public spend key does not decode";
        return r;
    }

    // K_v^(i,j) = k_v * K_s^(i,j)
    if (!mcrypto::point_scalarmult(view_priv, r.sub_spend_pub, r.sub_view_pub)) {
        r.error = "failed to derive subaddress view key";
        return r;
    }

    r.addr = make_standard(r.sub_spend_pub, r.sub_view_pub, net);
    r.addr.type = AddressType::Subaddress;
    r.ok = true;
    return r;
}

} // namespace c2wallet::monero
