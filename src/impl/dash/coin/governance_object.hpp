// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Daemonless superblock sourcing — governance trigger data model + payment-
/// schedule parser (E-SUPERBLOCK, follow-on to E1/E2/E3/E4).
///
/// This is the reward-safe reuse of dashcore's superblock consensus logic:
///
///   dashcore governance/governance-classes.cpp
///     CSuperblock::CSuperblock(uint256, ...)      — event_block_height parse
///     CSuperblock::ParsePaymentSchedule(...)      — payment_addresses /
///                                                   payment_amounts /
///                                                   proposal_hashes split
///     ParsePaymentAmount(...)                     — strict amount grammar
///     CSuperblockManager::GetSuperblockPayments   — (payee, amount) vector
///   dashcore governance/common.cpp
///     Governance::Object::GetHash()               — object identity hash
///   dashcore governance/vote.h
///     CGovernanceVote::GetSignatureHash()/GetHash() — vote digests
///
/// A governance TRIGGER object (GOVERNANCE_OBJECT_TRIGGER == 2) carries, in
/// its vchData, the superblock payout schedule as PLAINTEXT JSON bytes.
/// NOTE (wire format): dashcore's vchData holds the raw JSON bytes — RPC
/// `DataHex` is HexStr(vchData) and GetDataAsPlainString() is simply
/// std::string(vchData.begin(), vchData.end()); there is NO hex layer on the
/// wire itself. The schedule looks like:
///
///   {"event_block_height": <int>,
///    "payment_addresses":  "addr1|addr2|...",
///    "payment_amounts":    "amt1|amt2|...",
///    "proposal_hashes":    "h1|h2|...",
///    "type": 2}
///
/// parse_superblock_trigger() ports dashcore's parse EXACTLY, including every
/// rejection dashd applies at ingest (see the function docs). Address decode
/// is CHAIN-STRICT (dashcore DecodeDestination: only the active chain's DASH
/// base58 versions are accepted) — a wrong-chain or non-DASH address fails the
/// whole trigger closed. Confirmed live against testnet dashd: a mainnet '7…'
/// P2SH address is "Invalid prefix" on testnet, and the testnet P2SH vector
/// decodes to the byte-exact a914…87 scriptPubKey (see test_dash_superblock).
///
/// STRICTLY single-coin: src/impl/dash/ only, no bitcoin_family / src/core
/// consensus reach beyond core hashing (::Hash) for the object/vote digests.

#include <core/uint256.hpp>
#include <core/hash.hpp>                // ::Hash (double-SHA256) — object/vote digests

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cctype>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace dash {
namespace coin {

/// dashcore GovernanceObjectType (governance/governance-object.h).
enum GovernanceObjectType : int32_t {
    GOVERNANCE_OBJECT_UNKNOWN  = 0,
    GOVERNANCE_OBJECT_PROPOSAL = 1,
    GOVERNANCE_OBJECT_TRIGGER  = 2,
};

/// dashcore vote_outcome_enum_t (governance/vote.h).
enum GovernanceVoteOutcome : int32_t {
    VOTE_OUTCOME_NONE    = 0,
    VOTE_OUTCOME_YES     = 1,
    VOTE_OUTCOME_NO      = 2,
    VOTE_OUTCOME_ABSTAIN = 3,
};

/// dashcore vote_signal_enum_t (governance/vote.h) — the subset we consult.
enum GovernanceVoteSignal : int32_t {
    VOTE_SIGNAL_NONE     = 0,
    VOTE_SIGNAL_FUNDING  = 1,   // superblock trigger tally axis
    VOTE_SIGNAL_VALID    = 2,
    VOTE_SIGNAL_DELETE   = 3,
    VOTE_SIGNAL_ENDORSED = 4,
};

/// DASH base58 version bytes — dashpay/dash chainparams.cpp (verified):
/// mainnet PUBKEY_ADDRESS=76 ('X…'), SCRIPT_ADDRESS=16 ('7…');
/// testnet/devnet/regtest PUBKEY_ADDRESS=140 ('y…'), SCRIPT_ADDRESS=19 ('8/9…').
inline constexpr uint8_t DASH_B58_PUBKEY_MAINNET = 76;   // 0x4c
inline constexpr uint8_t DASH_B58_SCRIPT_MAINNET = 16;   // 0x10
inline constexpr uint8_t DASH_B58_PUBKEY_TESTNET = 140;  // 0x8c
inline constexpr uint8_t DASH_B58_SCRIPT_TESTNET = 19;   // 0x13

/// dashcore amount.h: MAX_MONEY = 21000000 * COIN (MoneyRange upper bound).
inline constexpr int64_t DASH_MAX_MONEY = 21'000'000LL * 100'000'000LL;

/// One superblock coinbase output: the exact (scriptPubKey, amount-in-duffs)
/// dashcore's CGovernancePayment holds. `script` is the raw scriptPubKey bytes
/// so the embedded coinbase builder emits it byte-identically to dashd.
struct SuperblockPayment {
    std::vector<uint8_t> script;   // raw scriptPubKey
    int64_t              amount{0}; // duffs (satoshi)

    bool operator==(const SuperblockPayment& o) const {
        return script == o.script && amount == o.amount;
    }
};

/// Parsed superblock TRIGGER: the height it pays and the ordered payee vector.
struct GovernanceTrigger {
    uint256                        object_hash;       // key: dashd object hash
    int32_t                        event_block_height{0};
    std::vector<SuperblockPayment> payments;

    int64_t total_amount() const {
        int64_t t = 0;
        for (const auto& p : payments) t += p.amount;
        return t;
    }
};

// ── Small helpers (byte-for-byte dashcore-equivalent) ──────────────────────

/// Hex-decode a DataHex string into the plaintext it encodes. This is the
/// RPC-vector helper (RPC `DataHex` == HexStr(vchData)); the WIRE vchData is
/// already plaintext bytes and must NOT be routed through this (see header
/// note). Returns nullopt on odd length / non-hex input (fail closed).
inline std::optional<std::string> govdata_hex_to_plain(const std::string& hex)
{
    if (hex.size() % 2 != 0) return std::nullopt;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<char>((hi << 4) | lo));
    }
    return out;
}

/// dashcore ParsePaymentAmount (governance/classes.cpp) — EXACT port of the
/// grammar dashd enforces on trigger payment_amounts, layered over
/// util/strencodings ParseFixedPoint(8) + MoneyRange:
///   - non-empty, length <= 20;
///   - characters strictly in [0-9.] (NO '+', NO '-', no spaces, no exponent);
///   - no leading '.'; at most one '.';
///   - integer part: single "0" or no leading zero ("007" rejected);
///   - if a '.' is present, at least one and at most 8 fractional digits;
///   - resulting duffs within MoneyRange [0, 21e6 * 1e8].
/// Returns nullopt on ANY violation (fail closed). NOTE: "0" parses to 0 here
/// exactly as in dashd; the trigger parser separately requires amount > 0.
inline std::optional<int64_t> parse_payment_amount(const std::string& s)
{
    if (s.empty() || s.size() > 20) return std::nullopt;
    if (s.find_first_not_of("0123456789.") != std::string::npos)
        return std::nullopt;                                  // rejects +/-/e/space
    const size_t dot = s.find('.');
    if (dot == 0) return std::nullopt;                        // leading '.'
    if (dot != std::string::npos &&
        s.find('.', dot + 1) != std::string::npos)
        return std::nullopt;                                  // more than one '.'

    const std::string whole = (dot == std::string::npos) ? s : s.substr(0, dot);
    const std::string frac  = (dot == std::string::npos) ? std::string()
                                                         : s.substr(dot + 1);
    // ParseFixedPoint: the integer part is a single '0' or starts 1-9.
    if (whole.empty()) return std::nullopt;
    if (whole.size() > 1 && whole[0] == '0') return std::nullopt;
    // ParseFixedPoint: digits are required after a decimal point ("5." fails),
    // and more than `decimals` (8) fractional digits fail.
    if (dot != std::string::npos && frac.empty()) return std::nullopt;
    if (frac.size() > 8) return std::nullopt;

    int64_t w = 0;
    for (char c : whole) {
        w = w * 10 + (c - '0');
        if (w > 21'000'000LL) return std::nullopt;            // > MAX_MONEY already
    }
    int64_t f = 0;
    for (char c : frac) f = f * 10 + (c - '0');
    for (size_t i = frac.size(); i < 8; ++i) f *= 10;

    const int64_t duffs = w * 100'000'000LL + f;
    if (duffs < 0 || duffs > DASH_MAX_MONEY) return std::nullopt;  // MoneyRange
    return duffs;
}

/// Split a pipe-delimited field into its parts (dashcore uses '|' as the
/// address/amount/proposal-hash separator in the trigger schedule).
inline std::vector<std::string> split_pipe(const std::string& s)
{
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        size_t bar = s.find('|', start);
        out.push_back(s.substr(start, bar == std::string::npos ? std::string::npos
                                                               : bar - start));
        if (bar == std::string::npos) break;
        start = bar + 1;
    }
    return out;
}

/// dashcore util ParseHashStr equivalent: a proposal hash must be exactly 64
/// hex characters (a well-formed uint256 hex string).
inline bool is_valid_hash_str(const std::string& s)
{
    if (s.size() != 64) return false;
    for (char c : s) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
                         (c >= 'A' && c <= 'F');
        if (!hex) return false;
    }
    return true;
}

/// CHAIN-STRICT DASH base58check address -> scriptPubKey (dashcore
/// DecodeDestination over the ACTIVE chain's base58Prefixes). Only the four
/// DASH version bytes are accepted, and only the pair belonging to `testnet`:
///   mainnet: 0x4c -> P2PKH 76a914<h160>88ac, 0x10 -> P2SH a914<h160>87
///   testnet: 0x8c -> P2PKH,                  0x13 -> P2SH
/// A wrong-chain address (e.g. a mainnet '7…' while running testnet), any
/// other coin's base58, bech32, or a checksum failure returns {} (fail
/// closed) — mirroring dashd's "Invalid Dash Address" trigger rejection.
inline std::vector<uint8_t> dash_address_to_script(const std::string& address,
                                                   bool testnet)
{
    // Base58check decode into version + hash160 + checksum (25 bytes).
    static constexpr const char* B58 =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if (address.size() < 25 || address.size() > 40) return {};
    uint8_t decoded[25] = {};
    for (unsigned char ch : address) {
        const char* p = std::strchr(B58, static_cast<char>(ch));
        if (!p) return {};
        int carry = static_cast<int>(p - B58);
        for (int i = 24; i >= 0; --i) {
            carry += 58 * static_cast<int>(decoded[i]);
            decoded[i] = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
        if (carry) return {};
    }
    // Verify checksum: SHA256d(decoded[0..20])[0..4] == decoded[21..24].
    {
        CHash256 hasher;
        unsigned char chk[32];
        hasher.Write(std::span<const unsigned char>(decoded, 21))
              .Finalize(std::span<unsigned char>(chk, 32));
        for (int i = 0; i < 4; ++i)
            if (chk[i] != decoded[21 + i]) return {};
    }

    const uint8_t version = decoded[0];
    const uint8_t pubkey_ver = testnet ? DASH_B58_PUBKEY_TESTNET
                                       : DASH_B58_PUBKEY_MAINNET;
    const uint8_t script_ver = testnet ? DASH_B58_SCRIPT_TESTNET
                                       : DASH_B58_SCRIPT_MAINNET;
    std::vector<uint8_t> out;
    if (version == pubkey_ver) {
        out.reserve(25);
        out.push_back(0x76); out.push_back(0xa9); out.push_back(0x14);
        out.insert(out.end(), decoded + 1, decoded + 21);
        out.push_back(0x88); out.push_back(0xac);
    } else if (version == script_ver) {
        out.reserve(23);
        out.push_back(0xa9); out.push_back(0x14);
        out.insert(out.end(), decoded + 1, decoded + 21);
        out.push_back(0x87);
    }
    // Any other version byte (wrong chain / wrong coin): {} — fail closed.
    return out;
}

// ── Serialization helpers for the dashcore governance digests ──────────────

namespace govhash_detail {
inline void put_u8(std::vector<unsigned char>& v, uint8_t x) { v.push_back(x); }
inline void put_u32le(std::vector<unsigned char>& v, uint32_t x) {
    v.push_back(static_cast<unsigned char>(x & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 8) & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 16) & 0xff));
    v.push_back(static_cast<unsigned char>((x >> 24) & 0xff));
}
inline void put_i32le(std::vector<unsigned char>& v, int32_t x) {
    put_u32le(v, static_cast<uint32_t>(x));
}
inline void put_i64le(std::vector<unsigned char>& v, int64_t x) {
    put_u32le(v, static_cast<uint32_t>(static_cast<uint64_t>(x) & 0xffffffffULL));
    put_u32le(v, static_cast<uint32_t>(static_cast<uint64_t>(x) >> 32));
}
inline void put_compactsize(std::vector<unsigned char>& v, uint64_t n) {
    if (n < 253) { put_u8(v, static_cast<uint8_t>(n)); return; }
    if (n <= 0xffff) {
        put_u8(v, 0xfd);
        put_u8(v, static_cast<uint8_t>(n & 0xff));
        put_u8(v, static_cast<uint8_t>((n >> 8) & 0xff));
        return;
    }
    put_u8(v, 0xfe);
    put_u32le(v, static_cast<uint32_t>(n));
}
inline void put_uint256(std::vector<unsigned char>& v, const uint256& h) {
    v.insert(v.end(), h.data(), h.data() + 32);
}
inline void put_bytes(std::vector<unsigned char>& v,
                      const std::vector<uint8_t>& b) {
    put_compactsize(v, b.size());
    v.insert(v.end(), b.begin(), b.end());
}
} // namespace govhash_detail

/// dashcore Governance::Object::GetHash() (governance/common.cpp) — EXACT
/// preimage port. dashcore's own comment: "Note: doesn't match serialization".
/// The preimage is:
///   hashParent (32 raw bytes)
///   nRevision  (int32 LE)
///   nTime      (int64 LE)
///   HexStr(vchData) serialized as a string: compactsize(2*len) + lowercase hex
///   masternodeOutpoint (hash 32 raw + n uint32 LE)
///   uint8_t{0} + uint32 0xffffffff        (legacy dummy bytes)
///   vchSig serialized: compactsize(len) + bytes
/// It EXCLUDES nCollateralHash and nObjectType (and the fee tx) on purpose.
/// Double-SHA256 over that. Pinned byte-exact against two FROM-WIRE testnet
/// governance objects in test_dash_superblock (hashes match `gobject list`).
inline uint256 govobject_hash(const uint256& hash_parent,
                              int32_t revision,
                              int64_t time,
                              const std::vector<uint8_t>& vch_data,
                              const uint256& mn_outpoint_hash,
                              uint32_t mn_outpoint_index,
                              const std::vector<uint8_t>& vch_sig)
{
    using namespace govhash_detail;
    static const char* H = "0123456789abcdef";
    std::vector<unsigned char> pre;
    pre.reserve(32 + 4 + 8 + 9 + 2 * vch_data.size() + 32 + 4 + 5 + 9 +
                vch_sig.size());
    put_uint256(pre, hash_parent);
    put_i32le(pre, revision);
    put_i64le(pre, time);
    // HexStr(vchData) as a serialized std::string (lowercase hex).
    put_compactsize(pre, static_cast<uint64_t>(vch_data.size()) * 2);
    for (uint8_t b : vch_data) {
        pre.push_back(static_cast<unsigned char>(H[b >> 4]));
        pre.push_back(static_cast<unsigned char>(H[b & 0x0f]));
    }
    put_uint256(pre, mn_outpoint_hash);
    put_u32le(pre, mn_outpoint_index);
    put_u8(pre, 0x00);            // legacy dummy uint8_t{}
    put_u32le(pre, 0xffffffffu);  // legacy dummy 0xffffffff
    put_bytes(pre, vch_sig);
    return ::Hash(std::span<const unsigned char>(pre.data(), pre.size()));
}

/// dashcore CGovernanceVote::GetSignatureHash() == SerializeHash(vote) with
/// SER_GETHASH — the vote serialization WITHOUT vchSig:
///   masternodeOutpoint (hash 32 raw + n uint32 LE)
///   nParentHash (32 raw)
///   nVoteOutcome (int32 LE)   <-- outcome BEFORE signal (serialization order)
///   nVoteSignal  (int32 LE)
///   nTime        (int64 LE)
/// Double-SHA256. THIS is the digest a masternode signs — for TRIGGER funding
/// votes with its BLS OPERATOR key (see the vote-verifier contract in
/// coin_state_maintainer.hpp).
inline uint256 govvote_signature_hash(const uint256& mn_outpoint_hash,
                                      uint32_t mn_outpoint_index,
                                      const uint256& parent_hash,
                                      int32_t outcome,
                                      int32_t signal,
                                      int64_t time)
{
    using namespace govhash_detail;
    std::vector<unsigned char> pre;
    pre.reserve(32 + 4 + 32 + 4 + 4 + 8);
    put_uint256(pre, mn_outpoint_hash);
    put_u32le(pre, mn_outpoint_index);
    put_uint256(pre, parent_hash);
    put_i32le(pre, outcome);
    put_i32le(pre, signal);
    put_i64le(pre, time);
    return ::Hash(std::span<const unsigned char>(pre.data(), pre.size()));
}

/// dashcore CGovernanceVote::GetHash() / UpdateHash() — the vote's IDENTITY
/// hash (dedup / inv key; "Note: doesn't match serialization"):
///   masternodeOutpoint + uint8_t{0} + uint32 0xffffffff (legacy dummies)
///   nParentHash
///   nVoteSignal  (int32 LE)   <-- signal BEFORE outcome here (legacy order)
///   nVoteOutcome (int32 LE)
///   nTime        (int64 LE)
/// Double-SHA256. Pinned byte-exact against two FROM-WIRE testnet votes in
/// test_dash_superblock (hashes match `gobject getcurrentvotes`).
inline uint256 govvote_identity_hash(const uint256& mn_outpoint_hash,
                                     uint32_t mn_outpoint_index,
                                     const uint256& parent_hash,
                                     int32_t outcome,
                                     int32_t signal,
                                     int64_t time)
{
    using namespace govhash_detail;
    std::vector<unsigned char> pre;
    pre.reserve(32 + 4 + 5 + 32 + 4 + 4 + 8);
    put_uint256(pre, mn_outpoint_hash);
    put_u32le(pre, mn_outpoint_index);
    put_u8(pre, 0x00);
    put_u32le(pre, 0xffffffffu);
    put_uint256(pre, parent_hash);
    put_i32le(pre, signal);
    put_i32le(pre, outcome);
    put_i64le(pre, time);
    return ::Hash(std::span<const unsigned char>(pre.data(), pre.size()));
}

/// dashcore CSuperblock::CSuperblock(govObj) + ParsePaymentSchedule
/// (governance-classes.cpp) port. Parses a trigger's plaintext JSON into a
/// GovernanceTrigger. Fails closed (returns nullopt) on ANY malformation
/// dashcore would reject at trigger ingest:
///   - not a bare JSON object (the legacy [["trigger",{...}]] array form is
///     REJECTED outright — dead format; narrower-than-dashd is the safe
///     direction);
///   - "type" missing or != 2 (dashd: obj["type"].getInt() throws if absent);
///   - event_block_height missing / non-integer / <= 0;
///   - payment_addresses / payment_amounts / proposal_hashes missing (all
///     three are mandatory in dashd) or with mismatched split counts;
///   - an address that is not a valid DASH address FOR THE ACTIVE CHAIN
///     (chain-strict decode, see dash_address_to_script);
///   - an amount violating dashcore's ParsePaymentAmount grammar, or == 0;
///   - a proposal hash that is not a well-formed uint256 hex string.
///
/// The caller (GovernanceStore / superblock.hpp) is responsible for the
/// event_block_height == candidate-height match and the budget/threshold gates.
inline std::optional<GovernanceTrigger> parse_superblock_trigger(
    const std::string& plain_json, const uint256& object_hash, bool testnet)
{
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(plain_json);
    } catch (...) {
        return std::nullopt;
    }
    // Bare JSON object ONLY. dashcore still unwraps the legacy nested array
    // form (objResult[0][1]); no live trigger uses it and mis-normalizing it
    // is a payee hazard, so we refuse it entirely (fail closed).
    if (!j.is_object()) return std::nullopt;

    // type is MANDATORY and must be trigger (dashd throws on absence).
    {
        if (!j.contains("type")) return std::nullopt;
        const auto& t = j.at("type");
        if (!t.is_number_integer()) return std::nullopt;
        if (t.get<int32_t>() != GOVERNANCE_OBJECT_TRIGGER) return std::nullopt;
    }

    GovernanceTrigger trig;
    trig.object_hash = object_hash;

    // event_block_height: JSON integer only (dashd getInt<int> — a string
    // value throws there, so a string is REJECTED here too).
    {
        if (!j.contains("event_block_height")) return std::nullopt;
        const auto& e = j.at("event_block_height");
        if (!e.is_number_integer()) return std::nullopt;
        trig.event_block_height = e.get<int32_t>();
    }
    if (trig.event_block_height <= 0) return std::nullopt;

    std::string addrs, amts, prop_hashes;
    try {
        if (!j.contains("payment_addresses") || !j.contains("payment_amounts") ||
            !j.contains("proposal_hashes"))
            return std::nullopt;
        addrs       = j.at("payment_addresses").get<std::string>();
        amts        = j.at("payment_amounts").get<std::string>();
        prop_hashes = j.at("proposal_hashes").get<std::string>();
    } catch (...) { return std::nullopt; }

    auto addr_v = split_pipe(addrs);
    auto amt_v  = split_pipe(amts);
    auto prop_v = split_pipe(prop_hashes);
    // dashd: all three split counts must match, and must be non-empty.
    if (addr_v.empty() || addr_v.size() != amt_v.size() ||
        addr_v.size() != prop_v.size())
        return std::nullopt;

    trig.payments.reserve(addr_v.size());
    for (size_t k = 0; k < addr_v.size(); ++k) {
        auto script = dash_address_to_script(addr_v[k], testnet);
        if (script.empty()) return std::nullopt;             // bad/wrong-chain address
        auto duffs = parse_payment_amount(amt_v[k]);
        if (!duffs || *duffs <= 0) return std::nullopt;      // bad/zero amount
        if (!is_valid_hash_str(prop_v[k])) return std::nullopt;  // bad proposal hash
        SuperblockPayment p;
        p.script = std::move(script);
        p.amount = *duffs;
        trig.payments.push_back(std::move(p));
    }
    return trig;
}

} // namespace coin
} // namespace dash
