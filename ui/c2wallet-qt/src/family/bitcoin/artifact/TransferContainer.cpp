// SPDX-License-Identifier: AGPL-3.0-or-later
#include "TransferContainer.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>

namespace c2w::artifact {

// ── PSBT-like binary record framing (then hex-encoded) ──────────────────────
//
//   magic   : 'C','2','W','U'          (4 bytes)
//   version : 0x01                      (1 byte)
//   records : { type(1) | len(varint) | payload(len) } *
//
// Record types:
//   0x01 coin              (utf8)
//   0x02 network_version   (4 bytes, little-endian)
//   0x03 algebra           (1 byte)
//   0x04 unsigned_tx       (raw bytes)
//   0x05 preflight_verdict (utf8; omitted when empty)
//   0x10 input             (repeatable, in input order):
//          prevout_txid(32) | index(4 LE) | amount(8 LE, two's-complement) |
//          spk_len(varint) | spk | hint_len(varint) | hint(utf8)
//
// Unknown record types are skipped on parse (forward-compat). A raw-hex
// superset: the whole thing is a hex string carrying the unsigned tx verbatim.

static constexpr uint8_t kMagic[4] = {'C', '2', 'W', 'U'};
static constexpr uint8_t kVersion  = 0x01;

enum : uint8_t {
    R_COIN    = 0x01,
    R_NETVER  = 0x02,
    R_ALGEBRA = 0x03,
    R_UTX     = 0x04,
    R_VERDICT = 0x05,
    R_INPUT   = 0x10,
};

static void put_varint(Bytes& b, uint64_t v) {
    // Bitcoin-style CompactSize.
    if (v < 0xfd) {
        b.push_back(static_cast<uint8_t>(v));
    } else if (v <= 0xffff) {
        b.push_back(0xfd);
        b.push_back(static_cast<uint8_t>(v & 0xff));
        b.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    } else if (v <= 0xffffffffULL) {
        b.push_back(0xfe);
        for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
    } else {
        b.push_back(0xff);
        for (int i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
    }
}

static bool get_varint(const Bytes& b, size_t& p, uint64_t& out) {
    if (p >= b.size()) return false;
    uint8_t first = b[p++];
    size_t n = 0;
    if (first < 0xfd) { out = first; return true; }
    else if (first == 0xfd) n = 2;
    else if (first == 0xfe) n = 4;
    else n = 8;
    if (p + n > b.size()) return false;
    out = 0;
    for (size_t i = 0; i < n; ++i) out |= static_cast<uint64_t>(b[p + i]) << (8 * i);
    p += n;
    return true;
}

static void put_u32le(Bytes& b, uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
}
static uint32_t get_u32le(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<uint32_t>(p[i]) << (8 * i);
    return v;
}
static void put_i64le(Bytes& b, int64_t v) {
    uint64_t u = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xff));
}
static int64_t get_i64le(const uint8_t* p) {
    uint64_t u = 0;
    for (int i = 0; i < 8; ++i) u |= static_cast<uint64_t>(p[i]) << (8 * i);
    return static_cast<int64_t>(u);
}

static void put_record(Bytes& b, uint8_t type, const uint8_t* payload, size_t len) {
    b.push_back(type);
    put_varint(b, len);
    b.insert(b.end(), payload, payload + len);
}

std::string UnsignedContainer::to_hex(std::string& err) const {
    err.clear();
    Bytes b;
    b.insert(b.end(), kMagic, kMagic + 4);
    b.push_back(kVersion);

    put_record(b, R_COIN, reinterpret_cast<const uint8_t*>(coin.data()), coin.size());

    {
        Bytes nv;
        put_u32le(nv, network_version);
        put_record(b, R_NETVER, nv.data(), nv.size());
    }
    {
        uint8_t a = static_cast<uint8_t>(algebra);
        put_record(b, R_ALGEBRA, &a, 1);
    }
    put_record(b, R_UTX, unsigned_tx.data(), unsigned_tx.size());

    if (!preflight_verdict.empty()) {
        put_record(b, R_VERDICT,
                   reinterpret_cast<const uint8_t*>(preflight_verdict.data()),
                   preflight_verdict.size());
    }

    for (const auto& in : inputs) {
        Bytes rec;
        rec.insert(rec.end(), in.prevout_txid.begin(), in.prevout_txid.end());
        put_u32le(rec, in.prevout_index);
        put_i64le(rec, in.amount);
        put_varint(rec, in.script_pubkey.size());
        rec.insert(rec.end(), in.script_pubkey.begin(), in.script_pubkey.end());
        put_varint(rec, in.derivation_hint.size());
        rec.insert(rec.end(),
                   reinterpret_cast<const uint8_t*>(in.derivation_hint.data()),
                   reinterpret_cast<const uint8_t*>(in.derivation_hint.data()) + in.derivation_hint.size());
        put_record(b, R_INPUT, rec.data(), rec.size());
    }

    if (b.size() > MAX_TRANSFER_BYTES) {
        err = "unsigned container exceeds the 100 kB oversize ceiling";
        return {};
    }
    return c2w::artifact::to_hex(b);
}

std::optional<UnsignedContainer> UnsignedContainer::from_hex(const std::string& hex,
                                                             std::string& err) {
    err.clear();
    auto decoded = c2w::artifact::from_hex(hex);
    if (!decoded) { err = "not valid hex"; return std::nullopt; }
    const Bytes& b = *decoded;

    if (b.size() < 5 || std::memcmp(b.data(), kMagic, 4) != 0) {
        err = "bad magic (not a c2wallet unsigned container)";
        return std::nullopt;
    }
    if (b[4] != kVersion) { err = "unsupported container version"; return std::nullopt; }

    UnsignedContainer c;
    size_t p = 5;
    bool saw_utx = false;
    while (p < b.size()) {
        uint8_t type = b[p++];
        uint64_t len = 0;
        if (!get_varint(b, p, len)) { err = "truncated record length"; return std::nullopt; }
        if (p + len > b.size()) { err = "truncated record payload"; return std::nullopt; }
        const uint8_t* payload = b.data() + p;

        switch (type) {
            case R_COIN:
                c.coin.assign(reinterpret_cast<const char*>(payload), len);
                break;
            case R_NETVER:
                if (len != 4) { err = "network_version record not 4 bytes"; return std::nullopt; }
                c.network_version = get_u32le(payload);
                break;
            case R_ALGEBRA:
                if (len != 1) { err = "algebra record not 1 byte"; return std::nullopt; }
                if (payload[0] > 2) { err = "unknown sighash algebra tag"; return std::nullopt; }
                c.algebra = static_cast<SighashAlgebra>(payload[0]);
                break;
            case R_UTX:
                c.unsigned_tx.assign(payload, payload + len);
                saw_utx = true;
                break;
            case R_VERDICT:
                c.preflight_verdict.assign(reinterpret_cast<const char*>(payload), len);
                break;
            case R_INPUT: {
                size_t q = p;
                if (len < 32 + 4 + 8) { err = "input record too short"; return std::nullopt; }
                UnsignedInput in;
                std::memcpy(in.prevout_txid.data(), b.data() + q, 32);
                q += 32;
                in.prevout_index = get_u32le(b.data() + q); q += 4;
                in.amount = get_i64le(b.data() + q); q += 8;
                uint64_t spk_len = 0;
                if (!get_varint(b, q, spk_len)) { err = "input spk length truncated"; return std::nullopt; }
                if (q + spk_len > p + len) { err = "input spk overruns record"; return std::nullopt; }
                in.script_pubkey.assign(b.data() + q, b.data() + q + spk_len); q += spk_len;
                uint64_t hint_len = 0;
                if (!get_varint(b, q, hint_len)) { err = "input hint length truncated"; return std::nullopt; }
                if (q + hint_len > p + len) { err = "input hint overruns record"; return std::nullopt; }
                in.derivation_hint.assign(reinterpret_cast<const char*>(b.data() + q), hint_len);
                q += hint_len;
                c.inputs.push_back(std::move(in));
                break;
            }
            default:
                // Unknown record type: skip for forward-compat.
                break;
        }
        p += len;
    }
    if (!saw_utx) { err = "missing unsigned tx record"; return std::nullopt; }
    return c;
}

bool operator==(const UnsignedInput& a, const UnsignedInput& b) {
    return a.prevout_txid == b.prevout_txid &&
           a.prevout_index == b.prevout_index &&
           a.script_pubkey == b.script_pubkey &&
           a.amount == b.amount &&
           a.derivation_hint == b.derivation_hint;
}

bool operator==(const UnsignedContainer& a, const UnsignedContainer& b) {
    return a.coin == b.coin &&
           a.network_version == b.network_version &&
           a.algebra == b.algebra &&
           a.unsigned_tx == b.unsigned_tx &&
           a.preflight_verdict == b.preflight_verdict &&
           a.inputs == b.inputs;
}

// ── Signed container: the c2pool loader format ──────────────────────────────

std::string SignedContainer::emit() const {
    std::string out;
    for (const auto& hx : tx_hexes) {
        out += hx;
        out.push_back('\n');
    }
    return out;
}

std::optional<SignedContainer> SignedContainer::parse(const std::string& text,
                                                      std::string& err) {
    err.clear();
    SignedContainer c;
    std::istringstream is(text);
    std::string line;
    unsigned lineno = 0;
    while (std::getline(is, line)) {
        ++lineno;
        // Strip ALL whitespace within the line — exactly as the c2pool loader
        // (std::remove_if(isspace)).
        line.erase(std::remove_if(line.begin(), line.end(),
                                  [](unsigned char c) { return std::isspace(c); }),
                   line.end());
        if (line.empty()) continue; // blank lines skipped
        if (line.size() % 2 != 0) {
            err = "line " + std::to_string(lineno) + ": odd hex length (all-or-nothing refusal)";
            return std::nullopt;
        }
        auto raw = c2w::artifact::from_hex(line);
        if (!raw) {
            err = "line " + std::to_string(lineno) + ": not valid hex";
            return std::nullopt;
        }
        if (raw->size() > MAX_TRANSFER_BYTES) {
            err = "line " + std::to_string(lineno) + ": tx exceeds the 100 kB oversize ceiling";
            return std::nullopt;
        }
        c.tx_hexes.push_back(std::move(line));
    }
    if (c.tx_hexes.empty()) { err = "no transactions in signed container"; return std::nullopt; }
    return c;
}

std::vector<std::string> SignedContainer::txid_displays() const {
    std::vector<std::string> out;
    out.reserve(tx_hexes.size());
    for (const auto& hx : tx_hexes) {
        auto raw = c2w::artifact::from_hex(hx);
        out.push_back(raw ? sha256d_display(*raw) : std::string());
    }
    return out;
}

} // namespace c2w::artifact
