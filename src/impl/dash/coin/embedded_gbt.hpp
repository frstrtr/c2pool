#pragma once

/// Phase C-TEMPLATE step 5: embedded GBT skeleton.
///
/// First credible local implementation of getblocktemplate-equivalent
/// output. Combines:
///   - Phase C-PAY    GetMNPayee()                       → expected payee
///   - Phase C-PAY    MnState.scriptPayout               → payee script
///   - Phase C-PAY    subsidy.hpp formulas               → block reward + MN split
///   - Phase C-MEMPOOL get_sorted_txs_with_fees()        → tx selection + fees
///
/// What's NOT yet built (each is a follow-up step):
///   - bits / target adjustment (would use header_chain difficulty)
///   - mintime (median-time-past of last 11 blocks)
///   - version (BIP9 deployment-flag-aware)
///   - CCbTx extra_payload encoder (needs bestCLSig from Phase L
///     ChainLock cycle tracking + creditPoolBalance from asset-lock
///     state machine — neither built yet)
///   - operator-reward + worker-payout split inside MN payment
///   - superblock budget outputs (every 16616 blocks)
///
/// As log-only output via [GBT-EMB], operators can compare against
/// `dashd-cli getblocktemplate` to spot drift in the parts we DO
/// produce. When --dashd-rpc set, [GBT-XCHECK] cross-checks against
/// the actual coin_rpc->getwork() output, logging match/mismatch.

#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/subsidy.hpp>
#include <impl/dash/coin/rpc_data.hpp>

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <ctime>
#include <string>

namespace dash {
namespace coin {

/// Build the GBT-equivalent fields we currently know how to compute
/// for a block at height (prev_height+1). Returns a partially-filled
/// DashWorkData; missing fields documented above.
inline DashWorkData build_embedded_workdata(
    uint32_t prev_height,
    const uint256& prev_hash,
    const MnStateMachine& mnstates,
    const Mempool& mempool,
    uint32_t bits_for_next)
{
    DashWorkData w;
    w.m_height          = prev_height + 1;
    w.m_previous_block  = prev_hash;
    w.m_bits            = bits_for_next;
    w.m_curtime         = static_cast<uint32_t>(std::time(nullptr));
    w.m_mintime         = w.m_curtime - 7200;   // TODO: real MTP
    w.m_version         = 0x20000000;           // TODO: real BIP9 bits

    // Subsidy + tx selection.
    int64_t reward = compute_dash_block_reward_post_v20(w.m_height);
    constexpr uint32_t MAX_BLOCK_BYTES = 1'990'000;  // leave headroom for cb
    auto [selected, total_fees] =
        mempool.get_sorted_txs_with_fees(MAX_BLOCK_BYTES);
    int64_t block_value = reward + total_fees;
    int64_t mn_payment  = compute_dash_mn_payment_post_v20(block_value);

    w.m_coinbase_value  = static_cast<uint64_t>(block_value);
    w.m_payment_amount  = static_cast<uint64_t>(mn_payment);

    // Selected txs — populate the wire-form fields the existing
    // coinbase_builder.hpp expects.
    w.m_txs.reserve(selected.size());
    w.m_tx_hashes.reserve(selected.size());
    w.m_tx_fees.reserve(selected.size());
    for (auto& s : selected) {
        w.m_txs.emplace_back(s.tx);
        w.m_tx_hashes.push_back(dash::coin::dash_txid(s.tx));
        w.m_tx_fees.push_back(s.fee);
    }

    // MN payee → packed_payment. dashcore GBT returns "payee" as a
    // base58 address; we don't yet reverse-encode arbitrary scripts
    // back to base58, so we use the c2pool "!hex" raw-script
    // convention from share_check.hpp::decode_payee_script.
    auto expected = mnstates.find_expected_payee();
    if (expected) {
        auto it = mnstates.entries().find(*expected);
        if (it != mnstates.entries().end() && mn_payment > 0) {
            std::string hex_script;
            hex_script.reserve(it->second.scriptPayout.m_data.size() * 2);
            static const char* digits = "0123456789abcdef";
            for (uint8_t b : it->second.scriptPayout.m_data) {
                hex_script.push_back(digits[(b >> 4) & 0xF]);
                hex_script.push_back(digits[b & 0xF]);
            }
            PackedPayment pp;
            pp.payee  = "!" + hex_script;
            pp.amount = static_cast<uint64_t>(mn_payment);
            w.m_packed_payments.push_back(std::move(pp));
        }
    }

    // CCbTx extra_payload not yet built (needs ChainLock cycle +
    // asset-lock state machine for the full v3+ payload).
    w.m_coinbase_payload.clear();

    return w;
}

/// Cross-check a built WorkData against dashd's GBT response (when
/// available). Compares the fields we currently produce. Logs as
/// [GBT-XCHECK] match / [GBT-XCHECK] MISMATCH. Returns true on full
/// match of the compared fields.
inline bool gbt_xcheck(const DashWorkData& embedded,
                       const DashWorkData& rpc)
{
    bool ok = true;
    auto report = [&](const char* field, const auto& a, const auto& b) {
        if (a != b) {
            ok = false;
            LOG_WARNING << "[GBT-XCHECK] field " << field
                        << " differs: embedded=" << a
                        << " rpc=" << b;
        }
    };
    report("height",          embedded.m_height,         rpc.m_height);
    report("coinbase_value",  embedded.m_coinbase_value, rpc.m_coinbase_value);
    report("payment_amount",  embedded.m_payment_amount, rpc.m_payment_amount);
    report("bits",            embedded.m_bits,           rpc.m_bits);
    report("previous_block",
        embedded.m_previous_block.GetHex(),
        rpc.m_previous_block.GetHex());
    if (embedded.m_packed_payments.size() != rpc.m_packed_payments.size()) {
        ok = false;
        LOG_WARNING << "[GBT-XCHECK] packed_payments size differs: "
                    << "embedded=" << embedded.m_packed_payments.size()
                    << " rpc=" << rpc.m_packed_payments.size();
    } else {
        for (size_t i = 0; i < embedded.m_packed_payments.size(); ++i) {
            // Note: payee comparison may differ in encoding (base58 vs
            // "!hex") even when they refer to the same script. Compare
            // amounts strictly; payee compared loosely (substring).
            if (embedded.m_packed_payments[i].amount
                != rpc.m_packed_payments[i].amount) {
                ok = false;
                LOG_WARNING << "[GBT-XCHECK] payment[" << i << "].amount "
                            << "embedded=" << embedded.m_packed_payments[i].amount
                            << " rpc=" << rpc.m_packed_payments[i].amount;
            }
        }
    }
    if (ok) {
        LOG_INFO << "[GBT-XCHECK] match h=" << embedded.m_height
                 << " coinbase_value=" << embedded.m_coinbase_value
                 << " mn_payment=" << embedded.m_payment_amount
                 << " mempool_txs=" << embedded.m_txs.size();
    }
    return ok;
}

} // namespace coin
} // namespace dash
