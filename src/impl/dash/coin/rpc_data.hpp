// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Parsed getblocktemplate response with Dash-specific fields.
// Reference: ref/p2pool-dash/p2pool/dash/helper.py::getwork()

#include "transaction.hpp"

#include <string>
#include <vector>
#include <cstdint>

#include <core/uint256.hpp>
#include <nlohmann/json.hpp>

namespace dash
{
namespace coin
{

// One masternode / superblock / platform payment entry after normalization.
// payee == "!" + hex_script when the payment is a raw script (OP_RETURN
// platform payment); otherwise payee is a base58 address.
//
// script carries dashd's GBT-provided scriptPubKey bytes VERBATIM whenever the
// entry had a "script" field — even when the base58 payee wins the payee
// string. It is the byte-faithful fallback for the coinbase lane: if the payee
// string later fails to decode (wrong-net address version, future address
// type), the coinbase builder emits these exact bytes instead of silently
// dropping a consensus-REQUIRED output (bad-cb-payee => every won block lost).
// The payee STRING semantics are unchanged (share-wire compatible — the
// sharechain PackedPayment in share_types.hpp is a distinct struct and still
// carries only the string).
struct PackedPayment {
    std::string payee;
    uint64_t    amount{0};
    std::vector<unsigned char> script;   // raw GBT scriptPubKey (may be empty)
};

// Normalize ONE masternode / superblock / platform payment entry from a dashd
// getblocktemplate/getwork response into a PackedPayment.
//
// bad-cb-payee TRAP: dashd surfaces the platform credit-pool OP_RETURN burn as
// a masternode[] entry shaped {"payee":"", "script":"6a", "amount":N} -- the
// payee field is PRESENT but an EMPTY string. The empty string must NOT win the
// address branch: a "" payee flows into the base58 decode path downstream, fails
// to decode, and the whole burn output is silently dropped -> missing-payee /
// bad-cb-payee on submit. Require a NON-EMPTY payee before treating it as a
// base58 address; otherwise fall through to the raw "!"+script form so the burn
// output is preserved byte-for-byte.
inline PackedPayment normalize_payment(const nlohmann::json& entry)
{
    PackedPayment pp;
    if (entry.is_object())
    {
        if (entry.contains("payee") && entry["payee"].is_string()
            && !entry["payee"].get<std::string>().empty())
            pp.payee = entry["payee"].get<std::string>();
        else if (entry.contains("script") && entry["script"].is_string())
            pp.payee = "!" + entry["script"].get<std::string>();
        if (entry.contains("amount"))
            pp.amount = entry["amount"].get<uint64_t>();
        // ALWAYS preserve the raw GBT scriptPubKey bytes alongside the payee
        // string (bad-cb-payee hardening): dashd hands us the exact script it
        // will enforce at ConnectBlock; keeping it means the coinbase builder
        // never has to silently drop a consensus-required output just because
        // the base58 round-trip failed. Manual hex decode keeps this header
        // dependency-light (nlohmann-only, mirrors decode_payee_script).
        if (entry.contains("script") && entry["script"].is_string())
        {
            const std::string hex = entry["script"].get<std::string>();
            auto nib = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            std::vector<unsigned char> raw;
            raw.reserve(hex.size() / 2);
            bool ok = (hex.size() % 2 == 0);
            for (size_t i = 0; ok && i + 1 < hex.size(); i += 2) {
                const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
                if (hi < 0 || lo < 0) { ok = false; break; }
                raw.push_back(static_cast<unsigned char>((hi << 4) | lo));
            }
            if (ok)
                pp.script = std::move(raw);
        }
    }
    return pp;
}

struct DashWorkData {
    // Raw getblocktemplate JSON response (kept for fallback access to fields
    // we haven't promoted to members yet).
    nlohmann::json m_raw;

    // Standard Bitcoin-family fields.
    int32_t               m_version{0};
    uint256               m_previous_block;
    uint32_t              m_height{0};
    uint64_t              m_coinbase_value{0};   // "coinbasevalue" in sat
    uint32_t              m_bits{0};
    uint32_t              m_curtime{0};
    uint32_t              m_mintime{0};
    std::string           m_coinbase_flags_hex;

    // Transactions from GBT (parsed into full tx objects + their ids).
    std::vector<Transaction> m_txs;
    std::vector<uint256>  m_tx_hashes;
    std::vector<uint64_t> m_tx_fees;
    // Raw "data" hex for each transaction — kept so we can assemble a full
    // block to submit via submitblock when a miner wins.
    std::vector<std::string> m_tx_data_hex;

    // Dash-specific ------------------------------------------------------------
    // Normalized list of masternode + superblock + platform payments, in the
    // exact order they must appear in the coinbase outputs.
    std::vector<PackedPayment> m_packed_payments;

    // Sum of all m_packed_payments[i].amount — this is the portion of the
    // block reward that miners do NOT receive (masternode+treasury share).
    uint64_t m_payment_amount{0};

    // DIP3/DIP4 coinbase extra payload (raw bytes, hex-decoded from GBT).
    // Empty if the daemon did not return one.
    std::vector<uint8_t> m_coinbase_payload;

    // RPC round-trip latency (seconds).
    int64_t m_latency{0};
};

} // namespace coin
} // namespace dash