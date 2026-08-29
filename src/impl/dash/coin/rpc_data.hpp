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
struct PackedPayment {
    std::string payee;
    uint64_t    amount{0};
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
    }
    return pp;
}

// Classify a dashd `submitblock` RPC result under the dual-path won-block
// contract (M1). submitblock returns null on accept; a non-null string is a
// reject reason. A "duplicate" / "inconclusive" / "already-have" result means
// the block is ALREADY on the network — the OTHER broadcast arm (embedded P2P
// relay, or a peer) landed it first — which is SUCCESS (the block reached the
// network), NOT a failure. "duplicate-invalid" is the one exception: the block
// was rejected as invalid, a genuine failure. Pure over the JSON so the KAT can
// pin it without a live RPC client.
inline bool submitblock_result_accepted(const nlohmann::json& result)
{
    if (result.is_null()) return true;
    if (!result.is_string()) return false;
    std::string code = result.get<std::string>();
    for (char& c : code)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    const bool already_have = code == "duplicate"
                           || code.find("inconclusive") != std::string::npos
                           || code.find("already") != std::string::npos;
    return already_have && code.find("invalid") == std::string::npos;
}

// ── NON-CONSENSUS: what happened to each configured pinned local tx on THIS
// template. One entry per configured pin, in file order, written by the splice
// that judges it.
//
// It exists because a pin that is simply ABSENT is indistinguishable from a pin
// that was never considered, and that ambiguity cost the donation on block
// 2518044 (2026-08-07): the embedded builder logged four `pinned tx INCLUDED`
// lines, the GBT-xcheck backstop swapped in dashd's template 57 ms later, and
// the served template carried neither the pins nor one word about them.
//
// Never serialized, never hashed, never read by any consensus path -- the block
// assembler reads m_txs / m_tx_data_hex only. It is the ANSWER a test can assert
// on without scraping a log line.
struct PinOutcome {
    uint256     txid;
    bool        included{false};
    /// Named refusal reason when !included; empty when included.
    std::string cause;
    /// The height the pin GATE judged at (our tip + 1), and the height of the
    /// template the pin was offered to. They are separate numbers because the
    /// gate runs beside the coin state and the template may come from dashd.
    uint32_t    gate_height{0};
    uint32_t    template_height{0};
    /// Sum of the pin's outputs, in satoshi. This is WHAT IS LOST when the pin
    /// does not ride a template that then wins: the donation is a zero-fee
    /// self-spend, so its output total is the whole amount at stake. Recorded
    /// so the drop alarm can name a number instead of a count.
    int64_t     value{0};
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

    // ── NON-CONSENSUS diagnostic: "this template's tx set is empty ON PURPOSE"
    // Empty string = normal template (mempool selection ran as usual). Non-empty
    // = the embedded builder DELIBERATELY served a coinbase-only body and this
    // names WHY (currently only "utxo-immature-serving"). Never serialized, never
    // read by any consensus path -- it exists so the node can SAY it is in the
    // degraded-but-valid serving mode instead of running there silently, and so a
    // soak can measure both the duration and the price.
    //
    // m_txset_forgone_fees is the mempool's total KNOWN fees at build time: the
    // upper bound on what a fully-populated template could have collected. It is
    // an upper bound, not the exact loss (selection also drops unknown-fee,
    // special, and MN-collateral-spending txs), so read it as "at most this much".
    std::string m_txset_empty_cause;
    uint64_t    m_txset_forgone_fees{0};

    // ── THE CANDIDATE SET (observe-without-arming) ────────────────────────
    // What selection WOULD have chosen, recorded when the served body is
    // deliberately coinbase-only. NEVER served: these ids/fees are not in
    // m_txs, m_tx_hashes, m_tx_fees or m_tx_data_hex, contribute nothing to
    // m_coinbase_value, and no consensus path reads them.
    //
    // They exist because the gate that must pass BEFORE fee-carrying
    // templates are enabled cannot be evaluated from templates built while
    // that flag is OFF: the served set is empty by construction, so a
    // coverage measurement over it reads 0% forever and the only ways left to
    // evaluate the gate are to arm the money path first (exactly what the
    // gate prevents) or to enable on faith. Measuring the candidate set is
    // what makes the fee lane completable at all.
    std::vector<uint256>  m_txset_candidates;
    std::vector<uint64_t> m_txset_candidate_fees;
    // Wire-form hex of each candidate, parallel to m_txset_candidates. The
    // MEMPOOL VALIDITY GATE (mempool_validity_gate.hpp) feeds these to dashd's
    // testmempoolaccept: the condition that decides whether
    // --embedded-serve-mempool-txs may be armed cannot be evaluated from ids
    // alone, and while the flag is OFF the candidate set is the ONLY place the
    // transactions we would serve exist. Diagnostic: no consensus path reads it.
    std::vector<std::string> m_txset_candidate_data_hex;

    // ── THE MEMPOOL-SOURCED RANGE OF THE SERVED BODY ──────────────────────
    // When the template DOES carry mempool transactions they are appended
    // LAST, after the consensus-mandatory type-6 quorum commitments and any
    // pinned local tx, so they occupy the contiguous range
    // [m_mempool_tx_first_index, m_mempool_tx_first_index + m_mempool_tx_count)
    // of m_txs / m_tx_hashes / m_tx_fees / m_tx_data_hex.
    //
    // The validity gate must probe EXACTLY that range and nothing else: a
    // type-6 commitment and a zero-fee pinned tx are both refused by relay
    // policy BY DESIGN, so probing them would manufacture INVALID verdicts out
    // of correct behaviour. Carried as a RANGE rather than a second copy of
    // the hex so the money path does not grow a duplicate block body for a
    // diagnostic. count == 0 means "no mempool-sourced tx in this body".
    uint32_t m_mempool_tx_first_index{0};
    uint32_t m_mempool_tx_count{0};

    // Per-entry "this tx spends an output of an EARLIER entry of the same
    // probe set" flag, parallel to whichever probe set is populated (the
    // served range above, or the candidate set). dashd's testmempoolaccept
    // takes ONE transaction, so a child probed alone answers `missing-inputs`
    // when its parent is only in OUR template — an artefact of the probe, not
    // a defect of the transaction. The flag is computed at build time from the
    // real vins, so the exemption is a FACT about the set rather than an
    // inference from a reject string. Diagnostic: no consensus path reads it.
    std::vector<uint8_t>  m_mempool_probe_depends_in_set;

    // -- EMBEDDED TX-SERVE INTERNAL-CONSISTENCY STAMP -----------------------
    // Written ONLY by the embedded builder when it produces a mempool-tx-
    // carrying body (embedded_gbt.hpp; armed == !suppress_mempool_txs). The
    // serve-time internal-consistency referee (tx_serve_referee.hpp) reads it
    // to decide whether c2pool may serve ITS OWN valid tx set instead of
    // falling back to dashd merely because our tx-merkle-root differs. A
    // divergent-but-internally-consistent set is a NORMAL, perfectly valid
    // block; the safety requirement is per-tx validity + no double-spend +
    // coinbase fee-consistency, NOT tx-set parity with dashd.
    //
    // The two facts here are the ones the referee cannot re-derive from the
    // wire body alone: whether every mempool-range tx passed the fee-fold
    // proof (mempool.hpp exclusion-discipline: the vin-present/unspent,
    // in_sum>=out_sum guarantee), and the treasury/superblock slice that was
    // added to m_coinbase_value on a funded superblock height (so the referee
    // can assert m_coinbase_value == subsidy + Sum(m_tx_fees) + superblock).
    // armed == false on every non-serving build (coinbase-only, dashd
    // fallback) -> the referee never runs and behaviour is byte-identical.
    struct EmbeddedTxServeStamp {
        // The mempool-serving path produced this body (--embedded-serve-
        // mempool-txs ON at build time). When false the referee is dormant.
        bool     armed{false};
        // Every tx in the mempool-sourced range [m_mempool_tx_first_index,
        // +m_mempool_tx_count) passed the fee-fold proof at selection. The
        // selector already refuses non-proven entries (mempool.hpp:~1018
        // "if(!e.fee_fold_proven) continue;"); this records that guarantee so
        // the referee can fail-close if a future selection path ever admits an
        // unproven tx.
        bool     all_mempool_fee_fold_proven{false};
        // Treasury payout total added to m_coinbase_value at a funded
        // superblock height (0 on every ordinary block). Lets the referee
        // reconstruct the coinbase value exactly from (subsidy + fees +
        // superblock) rather than approximating it.
        uint64_t superblock_total{0};
    };
    EmbeddedTxServeStamp m_tx_serve_stamp;

    // ── PIN OUTCOMES (see PinOutcome above) ───────────────────────────────
    // One entry per configured pinned local tx, written by the splice on the
    // SERVED dashd-fallback arm. Empty on the embedded arm (which splices in
    // its own builder and logs there) and empty when no pin is configured.
    std::vector<PinOutcome> m_pin_outcomes;

    // ── THE DROP ALARM (non-consensus) ────────────────────────────────────
    // Non-empty when this SERVED template is missing at least one configured
    // pin. It names the count, the height, the satoshi value at stake and the
    // cause(s), because "pins=0/4" on its own does not tell an operator that
    // money is going missing or why.
    //
    // The flag-off xcheck-swap arm is the case this exists for: with
    // --pin-splice-xcheck-arm at its default the donation is DELIBERATELY not
    // spliced, and a deliberate loss that is only visible as an INFO line is
    // operationally identical to the silent loss that cost h=2518044.
    std::string m_pin_drop_alarm;

    // ── BLOCK-BUDGET NOT ENFORCED (non-consensus) ─────────────────────────
    // True when a pin was appended even though it pushed the template past
    // kMaxPinnedBlockBytes, because --pin-splice-block-budget is OFF (the
    // default: enforcing it CHANGES SERVED BYTES on the already-live
    // declined-embedded arm, so it may not be on by default). The block may be
    // rejected as bad-blk-length if it wins. Always accompanied by a WARNING.
    bool m_pin_block_budget_unenforced{false};
};

} // namespace coin
} // namespace dash