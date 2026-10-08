// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// MMS round-message codec -- see MoneroMmsMessage.hpp for the wire layout and
// the faithful-not-verbatim interop note.

#include "family/monero/multisig/MoneroMmsMessage.hpp"

#include <cstring>

namespace c2wallet::monero::multisig {

namespace {

const char kMagic[6] = {'C', '2', 'M', 'M', 'S', '\x01'};

void put_u32(std::vector<std::uint8_t>& b, std::uint32_t v) {
    b.push_back(static_cast<std::uint8_t>(v & 0xff));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xff));
    b.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
    b.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
}

bool get_u32(const std::uint8_t* p, std::size_t len, std::size_t& off, std::uint32_t& v) {
    if (off + 4 > len) return false;
    v = static_cast<std::uint32_t>(p[off]) |
        (static_cast<std::uint32_t>(p[off + 1]) << 8) |
        (static_cast<std::uint32_t>(p[off + 2]) << 16) |
        (static_cast<std::uint32_t>(p[off + 3]) << 24);
    off += 4;
    return true;
}

int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

std::vector<std::uint8_t> mms_serialize(const MmsMessage& m) {
    std::vector<std::uint8_t> b;
    b.insert(b.end(), kMagic, kMagic + 6);
    b.push_back(static_cast<std::uint8_t>(m.type));
    put_u32(b, m.round);
    put_u32(b, m.signer_index);
    const std::uint32_t count = static_cast<std::uint32_t>(m.keys.size());
    put_u32(b, count);
    for (std::size_t i = 0; i < m.keys.size(); ++i) {
        put_u32(b, i < m.aux.size() ? m.aux[i] : 0u);
        b.insert(b.end(), m.keys[i].begin(), m.keys[i].end());
    }
    return b;
}

bool mms_deserialize(const std::uint8_t* data, std::size_t len, MmsMessage& out) {
    if (len < 6 + 1 + 12) return false;
    if (std::memcmp(data, kMagic, 6) != 0) return false;
    std::size_t off = 6;
    out.type = static_cast<MmsType>(data[off++]);
    std::uint32_t count = 0;
    if (!get_u32(data, len, off, out.round)) return false;
    if (!get_u32(data, len, off, out.signer_index)) return false;
    if (!get_u32(data, len, off, count)) return false;
    out.aux.clear();
    out.keys.clear();
    for (std::uint32_t i = 0; i < count; ++i) {
        std::uint32_t aux = 0;
        if (!get_u32(data, len, off, aux)) return false;
        if (off + 32 > len) return false;
        Bytes32 k{};
        std::memcpy(k.data(), data + off, 32);
        off += 32;
        out.aux.push_back(aux);
        out.keys.push_back(k);
    }
    return off == len;   // reject trailing garbage
}

std::string mms_to_hex(const MmsMessage& m) {
    static const char* hexd = "0123456789abcdef";
    const std::vector<std::uint8_t> b = mms_serialize(m);
    std::string s;
    s.reserve(b.size() * 2);
    for (std::uint8_t byte : b) { s.push_back(hexd[byte >> 4]); s.push_back(hexd[byte & 0xf]); }
    return s;
}

bool mms_from_hex(const std::string& hex, MmsMessage& out) {
    if (hex.size() % 2 != 0) return false;
    std::vector<std::uint8_t> b(hex.size() / 2);
    for (std::size_t i = 0; i < b.size(); ++i) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        b[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return mms_deserialize(b.data(), b.size(), out);
}

// ---- typed export ---------------------------------------------------------
MmsMessage to_mms(const KexRound1& r, std::uint32_t round) {
    MmsMessage m;
    m.type = MmsType::KexRound1;
    m.round = round;
    m.signer_index = r.signer_index;
    m.aux = {0, 0};
    m.keys = {r.spend_pub_share, r.view_sec_share};
    return m;
}

MmsMessage to_mms(const KexRound2& r, std::uint32_t round) {
    MmsMessage m;
    m.type = MmsType::KexRound2;
    m.round = round;
    m.signer_index = r.signer_index;
    m.aux = r.partner_index;
    m.keys = r.subset_pub;
    return m;
}

MmsMessage to_mms(const PartialNonce& n, std::uint32_t round) {
    MmsMessage m;
    m.type = MmsType::SignNonce;
    m.round = round;
    m.signer_index = n.signer_index;
    m.aux = {0, 0, 0};
    m.keys = {n.alpha_G, n.alpha_H, n.partial_ki};
    return m;
}

MmsMessage response_to_mms(std::uint32_t signer_index, const Bytes32& response, std::uint32_t round) {
    MmsMessage m;
    m.type = MmsType::SignResponse;
    m.round = round;
    m.signer_index = signer_index;
    m.aux = {0};
    m.keys = {response};
    return m;
}

// ---- typed import ---------------------------------------------------------
bool from_mms(const MmsMessage& m, KexRound1& out) {
    if (m.type != MmsType::KexRound1 || m.keys.size() != 2) return false;
    out.signer_index = m.signer_index;
    out.spend_pub_share = m.keys[0];
    out.view_sec_share = m.keys[1];
    return true;
}

bool from_mms(const MmsMessage& m, KexRound2& out) {
    if (m.type != MmsType::KexRound2 || m.keys.size() != m.aux.size()) return false;
    out.signer_index = m.signer_index;
    out.partner_index = m.aux;
    out.subset_pub = m.keys;
    return true;
}

bool from_mms(const MmsMessage& m, PartialNonce& out) {
    if (m.type != MmsType::SignNonce || m.keys.size() != 3) return false;
    out.signer_index = m.signer_index;
    out.alpha_G = m.keys[0];
    out.alpha_H = m.keys[1];
    out.partial_ki = m.keys[2];
    return true;
}

bool response_from_mms(const MmsMessage& m, std::uint32_t& signer_index, Bytes32& response) {
    if (m.type != MmsType::SignResponse || m.keys.size() != 1) return false;
    signer_index = m.signer_index;
    response = m.keys[0];
    return true;
}

} // namespace c2wallet::monero::multisig
