// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 5: embedded GBT skeleton (S7 capstone).
///
/// First credible local implementation of getblocktemplate-equivalent
/// output. Combines:
///   - Phase C-PAY    GetMNPayee()                       → expected payee
///   - Phase C-PAY    MnState.scriptPayout               → payee script
///   - Phase C-PAY    subsidy.hpp formulas               → block reward + MN split
///   - Phase C-MEMPOOL get_sorted_txs_with_fees()        → tx selection + fees
///
/// Oracle: frstrtr/p2pool-dash getwork() (older-than-v35 semantics).
/// dashd getblocktemplate RPC fallback remains the cross-check path
/// (gbt_xcheck / cbtx_xcheck below).
///
/// What's NOT yet built (each is a follow-up step):
///   - bits / target adjustment (would use header_chain difficulty)
///   - mintime (median-time-past of last 11 blocks) — caller supplies
///   - version (BIP9 deployment-flag-aware)
///   - CCbTx extra_payload encoder for the FULL v3+ payload (creditPool
///     needs the DIP-0027 asset-lock state machine, not built yet)
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
#include <impl/dash/coin/governance_object.hpp>   // SuperblockPayment (daemonless superblock outputs)
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/log.hpp>
#include <core/address_utils.hpp>

#include <array>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>

namespace dash {
namespace coin {

// ── Underfill guard (v36 cutover deploy path) ───────────────────────────────
// Port of the LTC/DOGE template-builder guard (src/impl/ltc/coin/
// template_builder.hpp, src/impl/doge/coin/template_builder.hpp) to the DASH
// embedded GBT path. Detects the "near-empty template on a non-empty mempool"
// regression: the tx selector returns almost no transactions even though the
// local mempool holds a substantial fee-paying backlog. c2pool-side
// template-fill safety net — NOT the byte-parity KAT axis; thresholds are the
// v36-native shared structure (bucket-2, standardize cross-coin) pinned to
// the legacy p2pool near-empty floor (~50 kB), identical to LTC/DOGE.
// DASH counts base_size bytes (no segwit), so "bytes" here are the same
// serialized-tx bytes the mempool byte cap and dashcore's 2 MB limit count.
inline constexpr uint64_t UNDERFILL_MIN_FILL_BYTES = 50'000ull; // < this = near-empty block
inline constexpr uint64_t UNDERFILL_BACKLOG_SLACK  = 50'000ull; // unselected fee-paying material that should have filled it

/// Pure trip predicate — the exact boolean the LTC/DOGE guards evaluate.
/// Factored out so the KAT can pin it without a log scraper:
///   near_empty  : template packed fewer bytes than the near-empty floor
///   has_backlog : the mempool holds fee-paying material (known fees > 0)
///                 well beyond what was selected (> selected + slack)
/// Genuinely empty (or fee-unknown-only) mempools never trip.
inline bool underfill_guard_trips(uint64_t selected_bytes,
                                  uint64_t mempool_bytes,
                                  uint64_t mempool_known_fees)
{
    const bool near_empty  = selected_bytes < UNDERFILL_MIN_FILL_BYTES;
    const bool has_backlog = mempool_known_fees > 0
                          && mempool_bytes > selected_bytes + UNDERFILL_BACKLOG_SLACK;
    return near_empty && has_backlog;
}

/// Build the GBT-equivalent fields we currently know how to compute
/// for a block at height (prev_height+1). Returns a partially-filled
/// DashWorkData; missing fields documented above.
// Forward decls (definitions below) -- E2d folds the DIP-0004 type-5
// CCbTx extra_payload into the embedded template via these.
inline vendor::CCbTx build_embedded_cbtx(
    uint32_t, const vendor::CSimplifiedMNList&, const QuorumManager&,
    int32_t, const std::array<uint8_t, 96>&, int64_t);
inline std::vector<unsigned char> encode_cbtx(const vendor::CCbTx&);
// Zero CLSIG default for the E2d best_cl_sig seam (no temporary-bound ref).
inline const std::array<uint8_t, 96> k_zero_cl_sig{};

inline DashWorkData build_embedded_workdata(
    uint32_t prev_height,
    const uint256& prev_hash,
    const MnStateMachine& mnstates,
    const Mempool& mempool,
    uint32_t bits_for_next,
    uint32_t mtp_at_tip,
    uint8_t  address_version,
    uint8_t  address_p2sh_version,
    // Step 8 seam: injectable block time. Defaults to std::time(nullptr) so
    // every existing caller is byte-for-byte unchanged (SAFE-ADDITIVE); the
    // G1 golden KAT pins it for a deterministic template+coinbase vector.
    uint32_t curtime = static_cast<uint32_t>(std::time(nullptr)),
    // Seam: injectable block version. Defaults to 0x20000000 (BIP9 "no
    // signaling" baseline) so every existing caller is byte-for-byte
    // unchanged (SAFE-ADDITIVE); the G1 golden KAT pins it, and a real
    // BIP9-deployment-aware value can later be threaded in without touching
    // the default header projection.
    uint32_t version = 0x20000000u,
    // Seam: optional underfill-guard observation point. Defaults to nullptr so
    // every existing caller is byte-for-byte unchanged (SAFE-ADDITIVE); the
    // guard KAT passes a bool to pin the wiring without a log scraper. The
    // guard itself is log-only (WARNING), exactly like LTC/DOGE — it never
    // alters the template.
    bool* underfill_tripped = nullptr,
    // E2d seams: optional SML/quorum inputs for the DIP-0004 type-5
    // CCbTx extra_payload. Default nullptr so every existing caller is
    // byte-for-byte unchanged (SAFE-ADDITIVE) and still gets an empty
    // payload; when supplied, the template becomes block-valid.
    const vendor::CSimplifiedMNList* sml = nullptr,
    const QuorumManager* qmgr = nullptr,
    int32_t best_cl_height = 0,
    const std::array<uint8_t, 96>& best_cl_sig = k_zero_cl_sig,
    int64_t last_observed_credit_pool = 0,
    // Network seam: the MN_RR activation height gating the DIP-0027
    // platform-share accrual (dashcore Params().GetConsensus().MN_RRHeight).
    // Defaults to MAINNET (existing callers byte-unchanged); testnet callers
    // MUST pass DASH_MN_RR_HEIGHT_TESTNET or the platform reward evaluates to
    // 0 and the committed creditPoolBalance sits one block-reward low (the E4
    // re-soak constant −66,966,830-duff bias).
    int mn_rr_height = DASH_MN_RR_HEIGHT_MAINNET,
    // E-SUPERBLOCK seam: daemonless superblock (governance treasury) outputs.
    // Default nullptr => every existing caller byte-unchanged (no superblock
    // outputs — the normal-block path). At a FUNDED superblock height the
    // governance provider resolves the winning trigger's (script, amount)
    // vector (superblock.hpp::get_superblock_payments) and threads it here;
    // build appends those outputs AND adds their total to the coinbase value,
    // exactly as dashd's getblocktemplate augments coinbasevalue with the
    // superblock array. An empty/nullptr vector is a normal block (a
    // confidently-UNFUNDED superblock height serves normally). The MN payment /
    // platform burn / mempool selection above are untouched — superblock
    // outputs are purely additive, matching dashcore GetBlockTxOuts ordering.
    const std::vector<SuperblockPayment>* superblock_payments = nullptr)
{
    DashWorkData w;
    w.m_height          = prev_height + 1;
    w.m_previous_block  = prev_hash;
    w.m_bits            = bits_for_next;
    w.m_curtime         = curtime;
    // Step 8: real median-time-past from header_chain. dashcore
    // requires curtime > MTP for the candidate block to be valid;
    // GBT returns MTP+1 as mintime so miners don't accidentally
    // produce stale-time blocks.
    w.m_mintime         = mtp_at_tip + 1;
    w.m_version         = version;              // seam: default 0x20000000 (BIP9 baseline)

    // Subsidy + tx selection.
    int64_t reward = compute_dash_block_reward_post_v20(w.m_height);
    constexpr uint32_t MAX_BLOCK_BYTES = 1'990'000;  // leave headroom for cb
    // C-3: exclude Dash special txs (tx.type != 0) from the embedded template.
    // dashd recomputes the CbTx roots + creditPool by applying the block's own
    // special txs; including one without accounting for it yields bad-cbtx. The
    // safe-minimal cut keeps the embedded block special-tx-free so the creditPool
    // accrual below is exactly the platform-reward term.
    auto [selected, total_fees] =
        mempool.get_sorted_txs_with_fees(MAX_BLOCK_BYTES, /*exclude_special=*/true);
    int64_t block_value      = reward + static_cast<int64_t>(total_fees);
    int64_t platform_reward  = compute_dash_platform_reward_post_v20_mn_rr(
        w.m_height, mn_rr_height);
    int64_t mn_payment       = compute_dash_mn_payment_post_v20(block_value) - platform_reward;

    w.m_coinbase_value  = static_cast<uint64_t>(block_value);
    w.m_payment_amount  = static_cast<uint64_t>(mn_payment);

    // Selected txs — populate the wire-form fields the existing
    // coinbase_builder.hpp expects.
    w.m_txs.reserve(selected.size());
    w.m_tx_hashes.reserve(selected.size());
    w.m_tx_fees.reserve(selected.size());
    uint64_t selected_bytes = 0;  // wire bytes packed into this template (underfill guard)
    for (auto& s : selected) {
        selected_bytes += s.base_size;
        w.m_txs.emplace_back(s.tx);
        w.m_tx_hashes.push_back(dash::coin::dash_txid(s.tx));
        w.m_tx_fees.push_back(s.fee);
    }

    // ── Underfill guard ─────────────────────────────────────────────
    // Do not silently treat a near-empty DASH template as healthy when the
    // DASH mempool held fee-paying backlog that should have filled it. We
    // cannot fabricate transactions, so surface loudly (WARNING) for
    // contabo-prod-watch / the operator rather than shipping a false-empty
    // block as normal. Genuinely empty mempools never trip. Mirrors the
    // LTC/DOGE TemplateBuilder guard; additive only — masternode payment /
    // CbTx / superblock projection below is untouched either way.
    {
        const uint64_t mempool_bytes = static_cast<uint64_t>(mempool.byte_size());
        const uint64_t mempool_fees  = mempool.total_known_fees();
        const bool tripped = underfill_guard_trips(selected_bytes,
                                                   mempool_bytes,
                                                   mempool_fees);
        if (underfill_tripped) *underfill_tripped = tripped;
        if (tripped) {
            LOG_WARNING << "[GBT-EMB] UNDERFILL: selected "
                        << selected.size() << " tx / " << selected_bytes
                        << "B into template while mempool holds " << mempool.size()
                        << " tx / " << mempool_bytes << "B (" << mempool_fees
                        << " sat fees) — near-empty block on a non-empty "
                        << "mempool; template-fill regression, gates cutover.";
        }
    }

    // Platform Credit Pool burn (DIP-0027): emit OP_RETURN payment
    // FIRST (matches dashcore GetBlockTxOuts ordering at payments.cpp:55).
    // Payee uses the "!hex" raw-script convention; OP_RETURN single byte = 0x6a.
    if (platform_reward > 0) {
        PackedPayment burn;
        burn.payee  = "!6a";
        burn.amount = static_cast<uint64_t>(platform_reward);
        w.m_packed_payments.push_back(std::move(burn));
    }

    // MN payee → packed_payment. dashcore GBT returns "payee" as a
    // base58 address. We use script_to_address() to produce the same
    // wire form for standard P2PKH/P2SH scripts. Unrecognized script
    // types fall back to the c2pool "!hex" raw-script convention from
    // share_check.hpp::decode_payee_script — preserves bytes for
    // share_check verification while keeping the GBT API clean.
    auto expected = mnstates.find_expected_payee();
    if (expected) {
        auto it = mnstates.entries().find(*expected);
        if (it != mnstates.entries().end() && mn_payment > 0) {
            const auto& script = it->second.scriptPayout.m_data;
            // Dash mainnet has no bech32 (P2WPKH/P2WSH inactive); pass
            // empty hrp so script_to_address() falls through cleanly.
            std::string addr = ::core::script_to_address(
                script, /*bech32_hrp=*/"",
                address_version, address_p2sh_version);
            PackedPayment pp;
            if (!addr.empty()) {
                pp.payee = std::move(addr);
            } else {
                // Non-standard script: fall back to !hex.
                std::string hex_script;
                hex_script.reserve(script.size() * 2);
                static const char* digits = "0123456789abcdef";
                for (uint8_t b : script) {
                    hex_script.push_back(digits[(b >> 4) & 0xF]);
                    hex_script.push_back(digits[b & 0xF]);
                }
                pp.payee = "!" + hex_script;
            }
            pp.amount = static_cast<uint64_t>(mn_payment);
            w.m_packed_payments.push_back(std::move(pp));
        }
    }

    // ── Daemonless superblock (governance treasury) outputs (E-SUPERBLOCK) ──
    // At a FUNDED superblock height dashd's coinbase pays the governance-
    // determined treasury payees IN ADDITION to the masternode payment +
    // platform burn, and augments coinbasevalue by their total. We mirror that:
    // append each (script, amount) as a packed payment (via script_to_address
    // for standard scripts, "!hex" fallback for non-standard — same convention
    // as the MN payee above) and add the total to m_coinbase_value. The payee
    // vector is the winning trigger's schedule, already budget-validated by
    // superblock.hpp::get_superblock_payments. When nullptr/empty this is a
    // normal block (unfunded superblock or non-superblock height) — no-op.
    if (superblock_payments != nullptr && !superblock_payments->empty()) {
        int64_t superblock_total = 0;
        for (const auto& sp : *superblock_payments) {
            std::string addr = ::core::script_to_address(
                sp.script, /*bech32_hrp=*/"", address_version, address_p2sh_version);
            PackedPayment pp;
            if (!addr.empty()) {
                pp.payee = std::move(addr);
            } else {
                std::string hex_script;
                hex_script.reserve(sp.script.size() * 2);
                static const char* digits = "0123456789abcdef";
                for (uint8_t b : sp.script) {
                    hex_script.push_back(digits[(b >> 4) & 0xF]);
                    hex_script.push_back(digits[b & 0xF]);
                }
                pp.payee = "!" + hex_script;
            }
            pp.amount = static_cast<uint64_t>(sp.amount);
            w.m_packed_payments.push_back(std::move(pp));
            superblock_total += sp.amount;
        }
        // dashd augments coinbasevalue by the superblock total (the accrued
        // treasury slice released this block).
        w.m_coinbase_value += static_cast<uint64_t>(superblock_total);
    }

    // E2d: fold the DIP-0004 type-5 CCbTx extra_payload so the block is
    // consensus-valid. Minimal cut -- version/height/merkleRootMNList/
    // merkleRootQuorums (+ bestCL when known); the v3+ asset-lock/DIP-0027
    // credit-pool state machine is still deferred and seeded from
    // last_observed_credit_pool. When the SML/quorum inputs are not
    // supplied (legacy callers) fall back to an empty payload.
    if (sml != nullptr && qmgr != nullptr) {
        // H-4 creditPool accrual. dashd commits, for block N, the credit-pool
        // balance AFTER block N's activity (evo/creditpool.cpp DiffFromBlock):
        //   creditPoolBalance(N) = creditPoolBalance(N-1)
        //                          + platformReward(N)              (locked this block)
        //                          + Σ assetLocks(N) − Σ assetUnlocks(N)
        // last_observed_credit_pool is creditPoolBalance(N-1) (the freshness gate
        // guarantees the SML/CCbTx seed is current at the tip we build on). The
        // embedded template excludes special txs (C-3 mempool filter), so the
        // asset-lock/unlock terms are exactly zero and the accrual reduces to the
        // platform-reward burn locked this block. Verified byte-exact against a
        // real testnet dashd getblocktemplate: creditPoolBalance stepped by
        // exactly the platform reward (66966830 duff) each block — see
        // test_dash_embedded_cbtx_byte_parity.cpp. When platform_reward is 0
        // (pre-MN_RR) the balance carries forward unchanged, also correct.
        const int64_t accrued_credit_pool =
            last_observed_credit_pool + platform_reward;
        vendor::CCbTx cb = build_embedded_cbtx(
            prev_height, *sml, *qmgr, best_cl_height, best_cl_sig,
            accrued_credit_pool);
        w.m_coinbase_payload = encode_cbtx(cb);
    } else {
        w.m_coinbase_payload.clear();
    }

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
    report("mintime",         embedded.m_mintime,        rpc.m_mintime);
    // Step 10: version. We always emit 0x20000000 (BIP9 default,
    // top-bit set, no signaling). On Dash mainnet steady-state this
    // matches because V19/V20/MN_RR all activated long ago. A
    // mismatch flags either (a) testnet/devnet with an active BIP9
    // deployment we don't model, or (b) a new mainnet softfork
    // window we need to wire up.
    report("version",         embedded.m_version,        rpc.m_version);
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
            // Step 12: both sides emit base58 for standard P2PKH/P2SH
            // scripts now, so payee compares strictly. Non-standard
            // scripts still fall back to "!hex" on our side; if dashd
            // also returns the script-hex form for the same input,
            // strings still match. Mismatches on the payee field now
            // surface real wire-form drift.
            if (embedded.m_packed_payments[i].amount
                != rpc.m_packed_payments[i].amount) {
                ok = false;
                LOG_WARNING << "[GBT-XCHECK] payment[" << i << "].amount "
                            << "embedded=" << embedded.m_packed_payments[i].amount
                            << " rpc=" << rpc.m_packed_payments[i].amount;
            }
            if (embedded.m_packed_payments[i].payee
                != rpc.m_packed_payments[i].payee) {
                ok = false;
                LOG_WARNING << "[GBT-XCHECK] payment[" << i << "].payee "
                            << "embedded=" << embedded.m_packed_payments[i].payee.substr(0, 40)
                            << " rpc=" << rpc.m_packed_payments[i].payee.substr(0, 40);
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

/// Phase C-TEMPLATE step 6/7: build a CCbTx struct (extra_payload
/// of the coinbase tx) from local SML + QuorumManager state.
///
/// We populate the fields we can compute now:
///   - nVersion = VERSION_CLSIG_AND_BALANCE (3) — Dash mainnet has
///     been on v3 since DEPLOYMENT_V20 activated at h=1,987,776.
///   - nHeight = prev_height + 1
///   - merkleRootMNList   = sml.CalcMerkleRoot()  [Phase C-SML]
///   - merkleRootQuorums  = compute_merkle_root_quorums(qmgr)
///                          [Phase C-TEMPLATE step 4c]
///   - bestCLHeightDiff / bestCLSignature: from the Phase C-TEMPLATE
///     step 7 best-CLSIG tracker. dashcore's CalcCbTxBestChainlock
///     formula: bestCLHeightDiff = (cb_height - 1) - bestCLHeight.
///     If best_cl_height == 0 (we haven't observed a CLSIG since
///     restart), we leave the fields zero — same wire shape dashd
///     uses for "no chainlock for the window".
///
/// The field we CANNOT YET compute (left seeded — known shadow
/// MISMATCH at INFO when asset-lock activity occurs):
///   - creditPoolBalance: requires the asset-lock state machine
///     (DIP-0027) which tracks deposits/withdrawals across cycles.
///     Not built yet; seeded from the last observed CCbTx.
inline vendor::CCbTx build_embedded_cbtx(
    uint32_t prev_height,
    const vendor::CSimplifiedMNList& sml,
    const QuorumManager& qmgr,
    int32_t  best_cl_height,
    const std::array<uint8_t, 96>& best_cl_sig,
    int64_t  last_observed_credit_pool)
{
    vendor::CCbTx c;
    c.nVersion           = vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    c.nHeight            = static_cast<int32_t>(prev_height + 1);
    // CalcMerkleRoot() caches upstream; take a mutable copy to call
    // into it without breaking const-correctness of the caller. The
    // cost is one ~450 KB SML vector copy per 5s shadow tick — within
    // budget for log-only validation.
    auto sml_mut = sml;
    c.merkleRootMNList   = sml_mut.CalcMerkleRoot();
    c.merkleRootQuorums  = compute_merkle_root_quorums(qmgr);

    // bestCL fields: only set when we have an actual best.
    // dashcore's formula is heightDiff = (cb_height - 1) - bestCLHeight.
    // best_cl_height == 0 ⇒ no CLSIG seen ⇒ leave both zero, matching
    // the pre-V20 / no-CL wire shape.
    if (best_cl_height > 0
        && best_cl_height <= static_cast<int32_t>(prev_height)) {
        c.bestCLHeightDiff = static_cast<uint32_t>(
            static_cast<int32_t>(prev_height) - best_cl_height);
        c.bestCLSignature  = best_cl_sig;
    } else {
        c.bestCLHeightDiff = 0;
        c.bestCLSignature  = {};
    }

    // creditPoolBalance: the caller (build_embedded_workdata) supplies the
    // ALREADY-ACCRUED balance for THIS block — i.e. creditPoolBalance(N-1) +
    // platformReward(N) (+ asset lock/unlock, which are zero because the
    // embedded template excludes special txs). We commit it verbatim. See the
    // H-4 accrual note in build_embedded_workdata and the byte-parity KAT.
    c.creditPoolBalance  = last_observed_credit_pool;
    return c;
}

/// Encode a CCbTx struct to wire bytes. Equivalent to dashcore's
/// SetTxPayload(coinbase, ccbtx) — produces what would go into the
/// coinbase tx's extra_payload field.
inline std::vector<unsigned char> encode_cbtx(const vendor::CCbTx& c)
{
    auto stream = ::pack(c);
    auto sp = stream.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

/// Cross-check our embedded CCbTx against the RPC's coinbase_payload.
/// Parses the RPC bytes back into a CCbTx and compares field-by-field.
/// The two roots are the high-value comparison: a match here proves
/// our SML and QuorumManager are in lockstep with dashd. Mismatches
/// on bestCL* / creditPool are EXPECTED until we wire those phases —
/// they're logged at INFO (not WARNING) so they don't pollute alerts.
inline bool cbtx_xcheck(const vendor::CCbTx& embedded,
                        const std::vector<unsigned char>& rpc_payload)
{
    vendor::CCbTx rpc_cbtx;
    if (!vendor::parse_cbtx(rpc_payload, rpc_cbtx)) {
        LOG_WARNING << "[CBTX-XCHECK] could not parse RPC payload ("
                    << rpc_payload.size() << " B) — skipping shadow";
        return false;
    }

    bool roots_ok = true;
    if (embedded.nVersion != rpc_cbtx.nVersion) {
        LOG_WARNING << "[CBTX-XCHECK] nVersion differs: embedded="
                    << embedded.nVersion << " rpc=" << rpc_cbtx.nVersion;
        roots_ok = false;
    }
    if (embedded.nHeight != rpc_cbtx.nHeight) {
        LOG_WARNING << "[CBTX-XCHECK] nHeight differs: embedded="
                    << embedded.nHeight << " rpc=" << rpc_cbtx.nHeight;
        roots_ok = false;
    }
    if (embedded.merkleRootMNList != rpc_cbtx.merkleRootMNList) {
        LOG_WARNING << "[CBTX-XCHECK] merkleRootMNList MISMATCH "
                    << "embedded=" << embedded.merkleRootMNList.GetHex().substr(0, 16)
                    << " rpc="     << rpc_cbtx.merkleRootMNList.GetHex().substr(0, 16);
        roots_ok = false;
    }
    if (embedded.merkleRootQuorums != rpc_cbtx.merkleRootQuorums) {
        LOG_WARNING << "[CBTX-XCHECK] merkleRootQuorums MISMATCH "
                    << "embedded=" << embedded.merkleRootQuorums.GetHex().substr(0, 16)
                    << " rpc="     << rpc_cbtx.merkleRootQuorums.GetHex().substr(0, 16);
        roots_ok = false;
    }

    // bestCL* comparison: severity depends on whether we have a
    // best yet. If our best_cl_height==0 (no CLSIG observed since
    // restart), mismatch is EXPECTED — log at INFO. Once we have
    // a best, mismatches become real drift signals — log at WARNING.
    if (rpc_cbtx.nVersion >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE) {
        bool we_have_best = (embedded.bestCLSignature != std::array<uint8_t, 96>{});
        if (embedded.bestCLHeightDiff != rpc_cbtx.bestCLHeightDiff
            || embedded.bestCLSignature != rpc_cbtx.bestCLSignature) {
            if (!we_have_best) {
                LOG_INFO << "[CBTX-XCHECK] bestCL* differs (expected — "
                            "no verified CLSIG observed since restart): "
                         << "embedded.diff=" << embedded.bestCLHeightDiff
                         << " rpc.diff="     << rpc_cbtx.bestCLHeightDiff
                         << " rpc.sig="      << (rpc_cbtx.has_best_cl_signature() ? "set" : "null");
            } else {
                LOG_WARNING << "[CBTX-XCHECK] bestCL* MISMATCH "
                            << "embedded.diff=" << embedded.bestCLHeightDiff
                            << " rpc.diff="     << rpc_cbtx.bestCLHeightDiff
                            << " sigs_match="
                            << (embedded.bestCLSignature == rpc_cbtx.bestCLSignature
                                ? "yes" : "no");
                roots_ok = false;
            }
        }
        // creditPoolBalance: step 11 seeds this from the most
        // recently observed CCbTx. Mismatches after step 11 mean
        // asset-lock OR asset-unlock activity occurred in the
        // candidate block we're templating, and the embedded path
        // needs the (not-yet-built) DIP-0027 state machine to catch
        // up. INFO until the state machine ships.
        if (embedded.creditPoolBalance != rpc_cbtx.creditPoolBalance) {
            int64_t delta = rpc_cbtx.creditPoolBalance - embedded.creditPoolBalance;
            LOG_INFO << "[CBTX-XCHECK] creditPoolBalance differs "
                        "(expected — asset-lock activity not yet "
                        "tracked): embedded=" << embedded.creditPoolBalance
                     << " rpc=" << rpc_cbtx.creditPoolBalance
                     << " delta=" << delta;
        }
    }

    if (roots_ok) {
        LOG_INFO << "[CBTX-XCHECK] roots match h=" << embedded.nHeight
                 << " mnlist=" << embedded.merkleRootMNList.GetHex().substr(0, 16)
                 << " quorums=" << embedded.merkleRootQuorums.GetHex().substr(0, 16);
    }
    return roots_ok;
}

} // namespace coin
} // namespace dash