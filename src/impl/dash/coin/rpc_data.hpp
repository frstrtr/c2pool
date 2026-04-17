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
struct PackedPayment {
    std::string payee;
    uint64_t    amount{0};
};

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
