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
///                                                   payment_amounts split
///     CSuperblockManager::GetSuperblockPayments   — (payee, amount) vector
///
/// A governance TRIGGER object (GOVERNANCE_OBJECT_TRIGGER == 2) carries, in its
/// vchData (hex-encoded plaintext JSON), the superblock payout schedule:
///
///   {"event_block_height": <int>,
///    "payment_addresses":  "addr1|addr2|...",
///    "payment_amounts":    "amt1|amt2|...",
///    "proposal_hashes":    "h1|h2|...",
///    "type": 2}
///
/// ParsePaymentSchedule() is a VERBATIM port of dashcore's: split the two
/// pipe-delimited strings, require equal counts, decode each address to a
/// scriptPubKey and each amount (fixed-point, 8 decimals) to duffs. The result
/// is the exact (script, amount) vector dashd would place in the superblock
/// coinbase — pinned by the from-wire KAT against testnet superblock 1519800.
///
/// STRICTLY single-coin: src/impl/dash/ only, no bitcoin_family / src/core
/// consensus reach beyond ::core::address_to_script (address→script decode).

#include <core/uint256.hpp>
#include <core/address_utils.hpp>       // ::core::address_to_script (base58→scriptPubKey)

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cctype>
#include <optional>
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

/// Hex-decode the object vchData into its plaintext JSON string. Mirror of
/// dashcore CGovernanceObject::GetDataAsPlainString (hex → bytes → string).
/// Returns nullopt on odd length / non-hex input (fail closed).
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

/// Fixed-point (8-decimal) money parser — dashcore util/moneystr ParseFixedPoint
/// semantics for CSuperblock payment amounts. Accepts an integer or decimal
/// DASH amount string and returns duffs (×1e8). Rejects anything non-numeric,
/// negative, or with > 8 fractional digits (fail closed → nullopt).
inline std::optional<int64_t> parse_fixed_point_8(const std::string& s)
{
    if (s.empty()) return std::nullopt;
    size_t i = 0;
    bool neg = false;
    if (s[i] == '-') { neg = true; ++i; }
    else if (s[i] == '+') { ++i; }
    if (i >= s.size()) return std::nullopt;

    int64_t whole = 0;
    bool any_digit = false;
    for (; i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])); ++i) {
        any_digit = true;
        whole = whole * 10 + (s[i] - '0');
        if (whole > 92233720368LL) return std::nullopt; // overflow guard (>~92e9 DASH)
    }
    int64_t frac = 0;
    int frac_digits = 0;
    if (i < s.size() && s[i] == '.') {
        ++i;
        for (; i < s.size() && std::isdigit(static_cast<unsigned char>(s[i])); ++i) {
            if (frac_digits >= 8) return std::nullopt; // more precision than duffs
            frac = frac * 10 + (s[i] - '0');
            ++frac_digits;
            any_digit = true;
        }
    }
    if (i != s.size() || !any_digit) return std::nullopt; // trailing garbage
    while (frac_digits < 8) { frac *= 10; ++frac_digits; }
    int64_t duffs = whole * 100'000'000LL + frac;
    if (neg) return std::nullopt; // superblock amounts are strictly positive
    return duffs;
}

/// Split a pipe-delimited field into its parts (dashcore uses '|' as the
/// address/amount separator in the trigger schedule).
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

/// dashcore CSuperblock::ParsePaymentSchedule (governance-classes.cpp) port.
/// Parses a trigger's plaintext JSON into a GovernanceTrigger. Fails closed
/// (returns nullopt) on ANY malformation dashcore would reject:
///   - not a trigger ("type" != 2)
///   - missing event_block_height / payment_addresses / payment_amounts
///   - address-count != amount-count
///   - an address that does not decode to a scriptPubKey
///   - an amount that is not fixed-point-parseable / non-positive
///
/// The caller (GovernanceStore / superblock.hpp) is responsible for the
/// event_block_height == candidate-height match and the budget/threshold gates.
inline std::optional<GovernanceTrigger> parse_superblock_trigger(
    const std::string& plain_json, const uint256& object_hash)
{
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(plain_json);
    } catch (...) {
        return std::nullopt;
    }
    // dashcore accepts either a bare object or a legacy [["trigger", {...}]]
    // wrapper; normalize the modern bare-object form we observe on the wire.
    if (j.is_array()) {
        // legacy nested form: find the object payload
        if (j.empty()) return std::nullopt;
        auto& inner = j.back();
        if (inner.is_array() && inner.size() == 2 && inner[1].is_object())
            j = inner[1];
        else if (inner.is_object())
            j = inner;
        else
            return std::nullopt;
    }
    if (!j.is_object()) return std::nullopt;

    // type must be trigger.
    if (j.contains("type")) {
        int t = 0;
        try { t = j.at("type").get<int>(); } catch (...) { return std::nullopt; }
        if (t != GOVERNANCE_OBJECT_TRIGGER) return std::nullopt;
    }

    GovernanceTrigger trig;
    trig.object_hash = object_hash;

    // event_block_height (int or numeric string).
    try {
        if (!j.contains("event_block_height")) return std::nullopt;
        const auto& e = j.at("event_block_height");
        if (e.is_number_integer()) trig.event_block_height = e.get<int32_t>();
        else if (e.is_string())    trig.event_block_height = std::stoi(e.get<std::string>());
        else return std::nullopt;
    } catch (...) { return std::nullopt; }
    if (trig.event_block_height <= 0) return std::nullopt;

    std::string addrs, amts;
    try {
        if (!j.contains("payment_addresses") || !j.contains("payment_amounts"))
            return std::nullopt;
        addrs = j.at("payment_addresses").get<std::string>();
        amts  = j.at("payment_amounts").get<std::string>();
    } catch (...) { return std::nullopt; }

    auto addr_v = split_pipe(addrs);
    auto amt_v  = split_pipe(amts);
    if (addr_v.empty() || addr_v.size() != amt_v.size()) return std::nullopt;

    trig.payments.reserve(addr_v.size());
    for (size_t k = 0; k < addr_v.size(); ++k) {
        auto script = ::core::address_to_script(addr_v[k]);
        if (script.empty()) return std::nullopt;             // bad address → fail closed
        auto duffs = parse_fixed_point_8(amt_v[k]);
        if (!duffs || *duffs <= 0) return std::nullopt;      // bad/zero amount → fail closed
        SuperblockPayment p;
        p.script.assign(script.begin(), script.end());
        p.amount = *duffs;
        trig.payments.push_back(std::move(p));
    }
    return trig;
}

} // namespace coin
} // namespace dash
