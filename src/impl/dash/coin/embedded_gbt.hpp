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
#include <impl/dash/coin/sml_projection.hpp>    // confirmedHash rollover pass + collateral-spend predicate
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/asset_lock_fold.hpp>   // #107 phase 2: DIP-0027 type-8 credit-pool fold
#include <impl/dash/coin/asset_unlock_admission.hpp>  // #143 Variant B: verified type-9 set (light bridge struct)
#include <impl/dash/coin/subsidy.hpp>
#include <impl/dash/coin/governance_object.hpp>   // SuperblockPayment (daemonless superblock outputs)
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/quorum_manager.hpp>
#include <impl/dash/coin/dkg_commitments.hpp>   // E1: build_qc_tx (mandatory type-6 txs)
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <btclibs/util/strencodings.h>          // HexStr (m_tx_data_hex fill)

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/log.hpp>
#include <core/address_utils.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <ctime>
#include <set>
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
    int32_t, const std::array<uint8_t, 96>&, int64_t,
    const uint256* quorum_root_override);
inline std::vector<unsigned char> encode_cbtx(const vendor::CCbTx&);
// Zero CLSIG default for the E2d best_cl_sig seam (no temporary-bound ref).
inline const std::array<uint8_t, 96> k_zero_cl_sig{};

/// PINNED LOCAL TX splice — the ONE admission-and-append used by BOTH serving
/// arms (embedded builder and the served-dashd-template arm), so the gate can
/// never drift between them. `arm` names the caller in the log lines
/// ("GBT-EMB" / "dashd-splice") so soaks can tell which arm carried the pin.
/// Exclusion is the only failure mode: gate re-checked on EVERY build (inputs
/// unspent against OUR UTXO view, coinbase-mature at this height, fee exactly
/// zero, no MN-collateral spend). A bad pin must never cost a block, and an
/// unverifiable one (utxo-view-unset) must never be included.
/// The pin gate's ANSWER as a self-contained VALUE.
///
/// The served-dashd arm cannot run the gate where it appends. The gate reads
/// the mempool UTXO view and the MN state machine, which the coin-P2P
/// maintainer mutates on the io thread — reading them from the re-source
/// thread is the #1134 heap-corruption shape on the serve path. So the gate
/// runs beside the coin state and only this value crosses.
struct PinVerdict {
    bool        ok{false};
    const char* cause{""};     ///< named refusal reason when !ok
    uint32_t    at_height{0};  ///< the height the gate judged AT
};

/// Gate only — no template touched. Same checks, same order, same names as the
/// splice below, because it IS the splice's gate.
inline PinVerdict pin_gate_verdict(const MutableTransaction& pin,
                                   const Mempool& mempool,
                                   const MnStateMachine& mnstates,
                                   uint32_t next_height)
{
    PinVerdict v;
    v.at_height = next_height;
    const auto gate = mempool.pinned_tx_admissible(pin, next_height);
    if (gate != Mempool::PinnedTxGate::Ok) {
        v.cause = Mempool::pinned_gate_name(gate);
        return v;
    }
    uint256 protx;
    if (tx_spends_mn_collateral(mnstates, pin, &protx)) {
        v.cause = "spends-mn-collateral";
        return v;
    }
    v.ok = true;
    return v;
}

/// Wire-form hex of one transaction — the shape dashd's testmempoolaccept and
/// submitblock both take.
inline std::string embedded_tx_hex(const MutableTransaction& mtx)
{
    auto stream = ::pack(mtx);
    auto sp = stream.get_span();
    return HexStr(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()), sp.size()));
}

/// TRUE when `tx` spends an output of a transaction ALREADY in `in_set`.
///
/// The MEMPOOL VALIDITY GATE (mempool_validity_gate.hpp) probes one
/// transaction at a time, because that is the only shape Dash Core's
/// testmempoolaccept takes. A child probed alone answers `missing-inputs`
/// whenever its parent rides the same template but is not (yet) in dashd's own
/// mempool — an artefact of the probe, not a defect of the transaction, since
/// selection is topological (mempool.hpp G1) and the parent IS in the block.
/// Recording the dependency HERE, from the real vins, is what lets the gate
/// excuse exactly that case without excusing a genuine missing input.
inline bool spends_earlier_in_set(const MutableTransaction& tx,
                                  const std::set<uint256>& in_set)
{
    for (const auto& vin : tx.vin)
        if (in_set.count(vin.prevout.hash)) return true;
    return false;
}

/// Append only — the caller must already hold an ok PinVerdict for THIS height.
inline void pin_append(DashWorkData& w, const MutableTransaction& pin)
{
    auto stream = ::pack(pin);
    auto sp = stream.get_span();
    w.m_txs.emplace_back(pin);
    w.m_tx_hashes.push_back(dash::coin::dash_txid(pin));
    w.m_tx_fees.push_back(0);
    w.m_tx_data_hex.push_back(HexStr(std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()), sp.size())));
}

// ── BLOCK-LEVEL PIN BUDGET ──────────────────────────────────────────────
// #1177 unified the size budget on the EMBEDDED arm: the consensus-required
// set is measured BEFORE mempool selection and deducted, with an explicit
// zero floor. The SERVED-DASHD arm never got that discipline. Its only cap
// was pins-vs-kMaxPinnedTotalBytes — never pins-vs-what-dashd's-template-
// ALREADY-HOLDS. dashd fills its own template to its own blockmaxsize
// (node/miner.cpp:212 clamps to MaxBlockSize()-1000, DEFAULT_BLOCK_MAX_SIZE
// is 2000000, policy/policy.h:23); splicing 400000 bytes of pins onto a
// template already near that reproduces EXACTLY the bad-blk-length overshoot
// #1177 removed — on the arm we describe as the always-reachable safety path.
//
// This is not hypothetical: block 2518186 was won on arm=dashd-fallback
// carrying 154 KB of pinned donation. One large dashd template away.
//
// ORDER, mirrored from dashd node/miner.cpp deliberately, because the order
// encodes which component may be dropped:
//   1. coinbase reserve   (miner.cpp:115, resetBlock: nBlockSize = 1000)
//   2. consensus-required (miner.cpp:235, nBlockSize += qcTx->GetTotalSize())
//   3. mempool selection  (miner.cpp:361, TestPackage against nBlockMaxSize)
// On the served-dashd arm steps 1-3 have ALREADY happened inside dashd and
// arrive as a finished template. The only component left that may yield is
// the pin set — pins are policy, everything already in dashd's template is
// either required for validity or paid for with fees we would be throwing
// away. So the pins yield, and they yield by being REFUSED WITH A NAME.

/// dashd consensus.h:10 — MAX_DIP0001_BLOCK_SIZE. A block over this is
/// INVALID (bad-blk-length), not merely large.
inline constexpr uint64_t kDashMaxBlockBytes = 2'000'000;

/// dashd node/miner.cpp:115 — resetBlock() starts nBlockSize at 1000 for a
/// coinbase it has not built yet. We reserve the same, for the same reason:
/// at splice time our coinbase does not exist either.
inline constexpr uint64_t kCoinbaseReserveBytes = 1'000;

/// serialize_full_block (block_producer.hpp:207-217) emits an 80-byte header
/// plus a CompactSize tx count before the coinbase. 9 is the WIDEST
/// CompactSize, so this over-reserves by at most 8 bytes — in the safe
/// direction, which is the only direction a budget may err.
inline constexpr uint64_t kBlockOverheadBytes = 80 + 9;

/// Bytes the template body ALREADY occupies, measured from the exact field
/// serialize_full_block() emits verbatim (block_producer.hpp:220). Not an
/// estimate and not a re-derivation: these ARE the bytes that go on the wire.
inline uint64_t template_body_bytes(const DashWorkData& w)
{
    uint64_t n = 0;
    for (const auto& h : w.m_tx_data_hex) n += h.size() / 2;
    return n;
}

/// How many MORE bytes the pin set may add before the ASSEMBLED block
/// exceeds the consensus limit, capped by the pin policy budget.
///
/// The subtraction has an explicit zero floor. An unsigned subtraction of an
/// over-cap occupancy wraps to ~18 EB and hands the splice an unbounded
/// budget, silently restoring the very behaviour this removes — the same
/// underflow face #1177 called out on the embedded arm.
inline uint64_t pin_headroom_bytes(const DashWorkData& w)
{
    const uint64_t occupied =
        kBlockOverheadBytes + kCoinbaseReserveBytes + template_body_bytes(w);
    const uint64_t left =
        occupied >= kDashMaxBlockBytes ? 0ull : kDashMaxBlockBytes - occupied;
    return std::min<uint64_t>(left, Mempool::kMaxPinnedTotalBytes);
}

/// The NAMED answer to "may this pin ride?" at BLOCK scale. nullptr == yes.
///
/// Two distinct refusals, kept distinct on purpose. "tx-too-large" (the
/// gate's own TooLarge face) blames the TRANSACTION; neither of these is a
/// property of the transaction — one is the pin set's own policy budget, the
/// other is a property of the TEMPLATE this pin happened to meet. A cause
/// name is the operator's only handle on a refusal, so it must say which.
inline const char* pin_budget_refusal(uint64_t spliced_bytes,
                                      uint64_t pin_bytes,
                                      uint64_t pin_cap,
                                      uint64_t headroom)
{
    if (spliced_bytes + pin_bytes > pin_cap)  return "pin-total-too-large";
    if (spliced_bytes + pin_bytes > headroom) return "pin-over-block-headroom";
    return nullptr;
}

/// What a splice DID, as a value — so a test can assert the NAMED refusal
/// without scraping a log line, and a caller can report it.
struct PinSpliceReport {
    size_t   included{0};
    size_t   excluded{0};
    uint64_t spliced_bytes{0};   ///< bytes actually appended
    uint64_t headroom{0};        ///< the budget this splice ran against
    /// Per-pin outcome in file order: "" when included, else the named cause.
    std::vector<const char*> causes;
};

/// THE splice, in file order, under a CUMULATIVE byte cap AND the block
/// budget. Both serving arms land here so neither can drift from the other.
///
/// The donation consolidation had to be split into four transactions after a
/// single 152258-byte pin was rejected as bad-txns-oversize and cost block
/// 2517855. Four quarter-sized transactions ride ONE template, so the money
/// lands in one block instead of four.
///
/// Each pin is judged INDEPENDENTLY: one bad pin excludes itself and the
/// others still ride. Both caps are checked against what has ALREADY been
/// accepted, so the answer never depends on the order the caller happened to
/// pass them in beyond file order itself.
///
/// The served-dashd arm cannot run the gate where it appends (the gate reads
/// coin state the io thread mutates — the #1134 heap-corruption shape), so it
/// arrives with verdicts already decided beside that state. The embedded arm
/// gates in place and hands the verdicts straight through. Either way the
/// SIZE arithmetic below is one implementation.
///
/// `enforce_block_budget` is the money-path flag. OFF (default) reproduces
/// the pre-fix arithmetic byte-for-byte: headroom == the pin policy cap, so
/// the block-headroom arm of pin_budget_refusal is unreachable and every
/// splice decision is identical to what shipped. ON measures dashd's real
/// template and refuses against the REAL remaining room.
inline PinSpliceReport splice_verdicted_pins(
    DashWorkData& w,
    const std::vector<MutableTransaction>& pins,
    const std::vector<PinVerdict>& verdicts,
    const char* arm,
    bool enforce_block_budget)
{
    PinSpliceReport rep;
    rep.causes.assign(pins.size(), "");
    if (verdicts.size() != pins.size()) return rep;

    constexpr uint64_t pin_cap = Mempool::kMaxPinnedTotalBytes;
    // Measured ONCE, from the template as dashd handed it over — before a
    // single pin is appended. `spliced_bytes` then tracks what we add, so the
    // two together are exactly "occupied now". Re-measuring inside the loop
    // would double-count the pins already appended.
    rep.headroom = enforce_block_budget ? pin_headroom_bytes(w) : pin_cap;

    for (size_t i = 0; i < pins.size(); ++i) {
        const auto& pin = pins[i];
        const auto& v   = verdicts[i];
        const auto txid = dash::coin::dash_txid(pin).GetHex().substr(0, 16);

        if (!v.ok) {
            rep.causes[i] = v.cause;
            ++rep.excluded;
            LOG_INFO << "[" << arm << "] pinned tx EXCLUDED h=" << v.at_height
                     << " cause=" << v.cause << " txid=" << txid
                     << " (template built without it; re-checked next build)";
            continue;
        }

        const uint64_t sz = ::pack(pin).get_span().size();
        if (const char* why = pin_budget_refusal(rep.spliced_bytes, sz,
                                                 pin_cap, rep.headroom)) {
            rep.causes[i] = why;
            ++rep.excluded;
            LOG_INFO << "[" << arm << "] pinned tx EXCLUDED h=" << v.at_height
                     << " cause=" << why << " txid=" << txid
                     << " (" << rep.spliced_bytes << "+" << sz
                     << " > pin_cap=" << pin_cap
                     << " headroom=" << rep.headroom
                     << " body=" << template_body_bytes(w)
                     << "; earlier pins keep their places)";
            continue;
        }

        pin_append(w, pin);
        rep.spliced_bytes += sz;
        ++rep.included;
        LOG_INFO << "[" << arm << "] pinned tx INCLUDED h=" << v.at_height
                 << " txid=" << txid << " vin=" << pin.vin.size()
                 << " fee=0 (rides this template)";
    }
    return rep;
}

/// Splice EVERY admissible pin, in file order, gating each one HERE. The
/// embedded arm's entry point; the size arithmetic is the shared one above.
inline PinSpliceReport splice_pinned_txs(DashWorkData& w,
                                         const std::vector<MutableTransaction>& pins,
                                         const Mempool& mempool,
                                         const MnStateMachine& mnstates,
                                         const char* arm,
                                         bool enforce_block_budget = false)
{
    std::vector<PinVerdict> verdicts;
    verdicts.reserve(pins.size());
    for (const auto& pin : pins)
        verdicts.push_back(pin_gate_verdict(pin, mempool, mnstates, w.m_height));
    return splice_verdicted_pins(w, pins, verdicts, arm, enforce_block_budget);
}

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
    // E1 seams: the mandatory type-6 quorum-commitment set for THIS height
    // (dkg_commitments.hpp daemonless plan) and the with-block
    // merkleRootQuorums the CbTx must commit. Default nullptr => every
    // existing caller is byte-for-byte unchanged (SAFE-ADDITIVE): no qc txs,
    // plain compute_merkle_root_quorums root.
    const std::vector<vendor::CFinalCommitment>* qc_commitments = nullptr,
    const uint256* quorum_root_override = nullptr,
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
    const std::vector<SuperblockPayment>* superblock_payments = nullptr,
    // Network seam: Consensus::Params.nMasternodeMinimumConfirmations for the
    // confirmedHash rollover projection (sml_projection.hpp). Mainnet default
    // (15, dashcore chainparams.cpp:177); testnet/devnet/regtest are 1. Only
    // consulted when the CCbTx seams (sml + qmgr) are supplied. SAFE-ADDITIVE:
    // appended last so every existing positional caller is byte-unchanged.
    int mn_min_confirmations = DASH_MN_MIN_CONFIRMATIONS_MAINNET,
    // ── UTXO-IMMATURE SERVING seam ───────────────────────────────────────────
    // When true, SKIP mempool selection entirely and build a coinbase-only body
    // (the mandatory type-6 quorum commitments above still ride -- they are
    // consensus-REQUIRED at a DKG height and carry zero fee, so dropping them
    // would make the block invalid while keeping none of them costs nothing).
    //
    // WHY THIS IS CONSENSUS-SAFE, not a shortcut: consensus never requires any
    // mempool transaction in a block. With zero selected txs total_fees is
    // exactly 0, so block_value == subsidy exactly; platform_reward and the
    // creditPool accrual are height-derived and never touched fees; mn_payment
    // is a pure function of block_value. Every value this template commits is
    // therefore EXACT, and exact by the cheapest possible route -- there is no
    // fee to overstate, so the bad-cb-amount risk the maturity gate exists to
    // prevent is structurally absent rather than merely unlikely. That matters
    // here because this builder has no TestBlockValidity equivalent: fee
    // exactness normally rides entirely on the UTXO lane, and this mode is the
    // one path that does not depend on it at all.
    //
    // Default false => every existing positional caller is byte-unchanged.
    bool suppress_mempool_txs = false,
    // NAME-THE-STATE seam for the suppressed body: WHY this template is
    // coinbase-only. Two producers exist: the UTXO-immature serving window
    // (the historical default, kept as the default string so every existing
    // positional caller is byte-unchanged) and the --embedded-serve-mempool-txs
    // default-OFF posture ("mempool-txs-disabled", node_coin_state.hpp). The
    // cause rides the template (m_txset_empty_cause) + the log line, so soaks
    // can tell the two coinbase-only modes apart.
    const char* txset_empty_cause = "utxo-immature-serving",
    // ── PINNED LOCAL TX seam (donation-dust consolidation lane) ──────────
    // An operator-supplied, externally-signed, ZERO-fee tx that can only
    // reach the chain through OUR OWN block (relay rejects 0-fee). Included
    // right after the mandatory type-6 commitments when — and only when —
    // Mempool::pinned_tx_admissible() passes against the live UTXO view; on
    // ANY failure the tx is EXCLUDED and the template is built exactly as if
    // no pin existed (a bad pinned tx must never cost a block, and must
    // never refuse a template). Fee is 0 by the gate's contract, so
    // total_fees / block_value / mn_payment stay exact untouched. Rides
    // regardless of suppress_mempool_txs — the coinbase-only posture is
    // about MEMPOOL selection; the pin is not a mempool tx.
    // Default nullptr => every existing positional caller byte-unchanged.
    const std::vector<MutableTransaction>* pinned_local_txs = nullptr,
    // ── #107 PHASE 2 seam: ACCRUE PENDING TYPE-8 ASSET LOCKS ──────────────
    // --embedded-accrue-asset-locks (default OFF). When true, the CbTx
    // creditPoolBalance below accrues the DIP-0027 asset-lock (type-8) term
    // dashd would commit for this block — Σ first-OP_RETURN value over the
    // pending type-8 locks in the mempool (asset_lock_fold.hpp, dashd
    // creditpool.cpp:262-276). This makes our committed pool match dashd's so
    // the gbt-xcheck-modulo-special-explained swap stops firing on the
    // EXPLAINED (type-8-only) case. DEFAULT false => the accrual is exactly
    // last_observed + platform_reward, byte-identical to today. Type-9
    // (unlock) is OUT OF SCOPE and never accrued.
    //
    // CONSENSUS NOTE (why default OFF): the value committed here is re-derived
    // and compared by the validator (specialtxman.cpp:749-755) against the
    // block's OWN txs. A block that commits this accrual is VALID only if the
    // SAME type-8 txs are in the served body (which requires tx-serving,
    // --embedded-serve-mempool-txs, itself blocked on #125). Committing the
    // accrual with a coinbase-only body would be a bad-cbtx-assetlocked-amount
    // REJECTED block — see the PR body B1.
    bool accrue_pending_asset_locks = false,
    // ── Variant B (#143) seam: VERIFIED TYPE-9 ASSET UNLOCKS ──────────────
    // --embedded-accrue-asset-unlocks (default OFF). The SINGLE template-side
    // call site of the CreditPool INDEX follower: nullptr or empty (the
    // default, and the ONLY possible value while the flag is OFF or any
    // fail-closed conjunct fails) means EXCLUDE-ALL — byte-identical to
    // today's template. When non-empty, every tx here already passed the
    // follower's full predicate (proven-complete index, fresh at THIS
    // template's parent, index ∉ CRangesSet, era-correct LimitAmount,
    // expiry window, quorumSig BLS-verified — credit_pool_idx.hpp
    // try_admit_unlocks), and three values thread through:
    //   * txs ride the body right after the pinned local txs (byte-budgeted
    //     like them, BEFORE mempool selection gets the remainder);
    //   * total_payload_fees joins total_fees (dashd GetAssetUnlockFee: the
    //     unlock fee is ordinary miner fee), so block_value stays exact and
    //     the coinbase-split FORMULA is untouched (reward_path_note);
    //   * gross_unlocked (Σ vout + fee) is SUBTRACTED from the committed
    //     creditPoolBalance — exactly dashd's GetTotalLocked sessionUnlocked
    //     term (creditpool.h:98-100) — so the validator's re-derivation from
    //     the block's OWN txs matches (specialtxman.cpp bad-cbtx-assetlocked-
    //     amount otherwise).
    const AssetUnlockAdmission* admitted_asset_unlocks = nullptr)
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

    // ── UNIFIED SIZE BUDGET (block 2517855) ────────────────────────────────
    // Every component of the block competes for ONE budget. Before this, the
    // mempool selection was handed the WHOLE cap as if it were alone, and the
    // consensus-required qc set plus any pinned transactions were appended on
    // top of it. Worst case that overshoots the 2 MB block limit outright, and
    // an oversize block is INVALID, not merely large — dashd rejects it with
    // bad-blk-length and the height goes to another miner.
    //
    // dashd does the same accounting in the other direction: node/miner.cpp
    // starts nBlockSize at a 1000-byte coinbase reserve, adds each qcTx's
    // GetTotalSize(), and packages the rest against nBlockMaxSize minus that
    // reserve. We mirror the ORDER — reserve, then consensus-required qc, then
    // pins, then selection gets the remainder — so the component that can be
    // dropped safely (mempool txs, worth fees) yields to the ones that cannot
    // (coinbase and qc, required for validity).
    //
    // We size qc and pins BEFORE selection rather than after, because a budget
    // discovered after the fact is not a budget. The pin figure here is an
    // UPPER BOUND (every configured pin, before the admission gate runs); the
    // gate can only shrink it, so deducting the bound is conservative and can
    // never let the block exceed the cap.
    // DELIBERATE ~9 KB conservative divergence from dashd (audited, kept):
    // dashd's effective ceiling is nBlockMaxSize = MaxBlockSize(2,000,000) -
    // 1000 = 1,999,000 (miner.cpp:212) against a 1000-byte coinbase reserve —
    // its coinbase pays ONE output. OURS pays the whole PPLNS window (dozens
    // to hundreds of miner outputs, kilobytes), so the extra headroom is
    // load-bearing against bad-blk-length on a won block (the block-2517855
    // loss class). Cost: byte-parity with dashd can break ONLY when the
    // mempool backlog fills blocks to within ~9 KB of the cap — set/merkle
    // divergence in the consensus-safe (smaller) direction. Do NOT raise this
    // to 1,999,000 without sizing the REAL coinbase into reserved_bytes.
    constexpr uint32_t MAX_BLOCK_BYTES   = 1'990'000;
    constexpr uint32_t kCoinbaseReserve  = 1'000;      // dashd node/miner.cpp:115
    uint64_t reserved_bytes = kCoinbaseReserve;
    if (qc_commitments != nullptr) {
        for (const auto& c : *qc_commitments)
            reserved_bytes += ::pack(build_qc_tx(w.m_height, c)).get_span().size();
    }
    if (pinned_local_txs != nullptr) {
        for (const auto& t : *pinned_local_txs)
            reserved_bytes += ::pack(t).get_span().size();
    }
    // #143: admitted type-9 unlocks are byte-budgeted like the pins —
    // BEFORE selection gets the remainder (a budget discovered after the
    // fact is not a budget). nullptr/empty (flag OFF / fail-closed) adds 0.
    if (admitted_asset_unlocks != nullptr) {
        for (const auto& t : admitted_asset_unlocks->txs)
            reserved_bytes += ::pack(t).get_span().size();
    }
    // Selection gets what is left. If the required set alone has eaten the
    // budget, selection gets ZERO rather than a negative number wrapping to a
    // huge unsigned cap — the underflow face is the one that would silently
    // restore the old behaviour.
    const uint32_t selection_budget =
        reserved_bytes >= MAX_BLOCK_BYTES
            ? 0u
            : static_cast<uint32_t>(MAX_BLOCK_BYTES - reserved_bytes);
    // C-3: exclude Dash special txs (tx.type != 0) from the embedded template.
    // dashd recomputes the CbTx roots + creditPool by applying the block's own
    // special txs; including one without accounting for it yields bad-cbtx. The
    // safe-minimal cut keeps the embedded block special-tx-free so the creditPool
    // accrual below is exactly the platform-reward term.
    // suppress_mempool_txs: coinbase-only body, total_fees == 0 exactly. The
    // mempool is not even consulted for selection (only, below, for the forgone-
    // fee report), so no partially-warm UTXO view can price anything into this
    // template.
    // next_height threads the G3 coinbase-maturity check into selection: a
    // vin spending a UTXO coinbase younger than 100 confs AT THIS HEIGHT is
    // refused (bad-txns-premature-spend-of-coinbase). Selection is also
    // topological (G1) and sigop-capped (G2) — see mempool.hpp.
    // lock_time_cutoff=mtp_at_tip threads dashd's TestPackageTransactions
    // finality re-check (IsFinalTx at nHeight/MTP(prev), miner.cpp:377) into
    // selection — the reorg-edge closure of the bad-txns-nonfinal
    // N-A-by-invariant row. The IS mining-safety hold (WAIT_FOR_ISLOCK_
    // TIMEOUT) also runs inside selection; its arming is pushed separately
    // (Mempool::set_instantsend_mining_hold + the isdlock feed liveness).
    auto [selected, total_fees] =
        suppress_mempool_txs
            ? std::pair<std::vector<Mempool::SelectedTx>, uint64_t>{{}, 0ull}
            : mempool.get_sorted_txs_with_fees(selection_budget,
                                               /*exclude_special=*/true,
                                               /*next_height=*/w.m_height,
                                               /*lock_time_cutoff=*/mtp_at_tip);
    // MN-collateral spend filter (sml_projection.hpp, FINDING-2). The C-3
    // special-tx cut above is NOT sufficient: dashd's verifier removes a
    // masternode from the list when ANY block tx — special or not — spends
    // its collateral outpoint (specialtxman.cpp:457-464, no type guard), and
    // that removal changes the merkleRootMNList the CbTx must commit. A plain
    // type-0 collateral spend selected here would poison EVERY template built
    // while it sits in the mempool (bad-cbtx-mnmerkleroot on a winning share
    // = a silently lost block). No tx is ever mandatory, so EXCLUDING it is
    // consensus-clean — dashd's own miner folds the removal instead, but the
    // exclusion needs no second root computation. Fee follows the tx out of
    // the template so block_value / mn_payment below stay exact.
    {
        size_t kept = 0;
        for (size_t i = 0; i < selected.size(); ++i) {
            uint256 protx;
            if (tx_spends_mn_collateral(mnstates, selected[i].tx, &protx)) {
                total_fees -= selected[i].fee;
                LOG_WARNING << "[GBT-EMB] excluding tx "
                            << dash::coin::dash_txid(selected[i].tx).GetHex().substr(0, 16)
                            << " from template h=" << (prev_height + 1)
                            << ": spends collateral of MN "
                            << protx.GetHex().substr(0, 16)
                            << " (verifier would remove the MN and expect a "
                            << "different merkleRootMNList)";
                continue;
            }
            if (kept != i) selected[kept] = std::move(selected[i]);
            ++kept;
        }
        selected.resize(kept);
    }
    // #143: the admitted unlocks' payload fees are ordinary miner fees (dashd
    // GetAssetUnlockFee, assetlocktx.cpp:200-212 — the fee reaches the miner
    // through the coinbase). Folded into total_fees BEFORE block_value below,
    // so every downstream value (block_value, mn_payment) is exact through
    // the EXISTING formulas — no new branch in the split math.
    if (admitted_asset_unlocks != nullptr)
        total_fees += static_cast<uint64_t>(admitted_asset_unlocks->total_payload_fees);
    // ── CANDIDATE-SET RECORDING (observe-without-arming) ────────────────
    // When the body is deliberately coinbase-only, run the SAME selection the
    // serving path would run and record only its identities and fees. Nothing
    // here can reach the served template: `selected` and `total_fees` above
    // are untouched, so the coinbase value, the tx vectors and the merkle are
    // byte-identical to a build with this block deleted.
    //
    // The property the original comment asserts — "no partially-warm UTXO view
    // can price anything into this template" — is preserved exactly: a
    // candidate priced from a partial UTXO view lands in m_txset_candidates,
    // which no consensus path reads.
    if (suppress_mempool_txs) {
        auto [cand, cand_fees] =
            // Same budget as the served path. Reporting the forgone set
            // against the FULL cap would overstate it — we could not have
            // served more than selection_budget even with serving enabled.
            mempool.get_sorted_txs_with_fees(selection_budget,
                                             /*exclude_special=*/true,
                                             /*next_height=*/w.m_height,
                                             /*lock_time_cutoff=*/mtp_at_tip);
        (void)cand_fees;
        w.m_txset_candidates.reserve(cand.size());
        w.m_txset_candidate_fees.reserve(cand.size());
        w.m_txset_candidate_data_hex.reserve(cand.size());
        w.m_mempool_probe_depends_in_set.reserve(cand.size());
        // In-set parents, accumulated in SELECTION order: selection is
        // topological (mempool.hpp G1), so a parent that rides this template
        // has already been pushed when its child is considered.
        std::set<uint256> candidate_ids;
        for (const auto& c : cand) {
            // The SAME MN-collateral exclusion the served path applies: a
            // candidate set that included them would overstate what we could
            // actually have served and make the coverage gate too generous.
            uint256 protx;
            if (tx_spends_mn_collateral(mnstates, c.tx, &protx)) continue;
            const uint256 cid = dash::coin::dash_txid(c.tx);
            w.m_mempool_probe_depends_in_set.push_back(
                spends_earlier_in_set(c.tx, candidate_ids) ? 1u : 0u);
            w.m_txset_candidates.push_back(cid);
            w.m_txset_candidate_fees.push_back(c.fee);
            // Wire hex for the MEMPOOL VALIDITY GATE's testmempoolaccept
            // probe. Still NEVER served: this vector is not m_tx_data_hex, no
            // consensus path reads it, and the coinbase value and merkle are
            // byte-identical to a build with this line deleted.
            w.m_txset_candidate_data_hex.push_back(embedded_tx_hex(c.tx));
            candidate_ids.insert(cid);
        }
    }

    int64_t block_value      = reward + static_cast<int64_t>(total_fees);
    int64_t platform_reward  = compute_dash_platform_reward_post_v20_mn_rr(
        w.m_height, mn_rr_height);
    int64_t mn_payment       = compute_dash_mn_payment_post_v20(block_value) - platform_reward;

    w.m_coinbase_value  = static_cast<uint64_t>(block_value);
    w.m_payment_amount  = static_cast<uint64_t>(mn_payment);

    // Selected txs — populate the wire-form fields the existing
    // coinbase_builder.hpp expects.
    w.m_txs.reserve(selected.size()
                    + (qc_commitments ? qc_commitments->size() : 0));
    w.m_tx_hashes.reserve(w.m_txs.capacity());
    w.m_tx_fees.reserve(w.m_txs.capacity());
    w.m_tx_data_hex.reserve(w.m_txs.capacity());
    // Wire-form hex of one tx (the submit-time block body source). The
    // embedded arm previously left m_tx_data_hex EMPTY (only the dashd-GBT
    // parser filled it), so a won embedded block's body could omit txs whose
    // ids were already folded into the job merkle — fill it here for every
    // template tx (E1; additive, the dashd fallback path is untouched).
    auto tx_hex = [](const MutableTransaction& mtx) {
        return embedded_tx_hex(mtx);
    };
    // E1: mandatory type-6 quorum-commitment txs FIRST — dashd's miner
    // places them immediately after the coinbase, before mempool txs
    // (node/miner.cpp CreateNewBlock), and the daemonless template mirrors
    // that for byte parity. Zero fee, zero in/out; consensus-checked via
    // the NodeCoinState emit gate against the same deterministic plan.
    //
    // ██ PHASE-L LANDMINE — PoSe punishment on REAL commitments ██
    // dashd's verifier PoSe-punishes every !validMembers[i] quorum member
    // when a NON-NULL commitment is in the block (specialtxman.cpp:159-174
    // HandleQuorumCommitment -> PoSePunish(CalcPenalty(66))), and a penalty
    // that crosses the ban threshold flips that MN's isValid IN THE SAME
    // BLOCK's MN list — changing the merkleRootMNList THIS coinbase commits.
    // Null commitments are exempt (specialtxman.cpp:432 IsNull() guard), so
    // today's all-null qc plans cannot trip it and the projected root above
    // stays correct. THE DAY Phase L serves REAL (non-null) commitments,
    // this inclusion site MUST fold the PoSe pass into the committed MN root
    // (mirror of the confirmedHash rollover projection above) or every block
    // carrying a commitment with a failed member is bad-cbtx-mnmerkleroot —
    // a silently lost block. Do not ship real commitments without it.
    if (qc_commitments != nullptr) {
        for (const auto& c : *qc_commitments) {
            MutableTransaction qtx = build_qc_tx(w.m_height, c);
            w.m_txs.emplace_back(qtx);
            w.m_tx_hashes.push_back(dash::coin::dash_txid(qtx));
            w.m_tx_fees.push_back(0);
            w.m_tx_data_hex.push_back(tx_hex(qtx));
        }
    }
    // ── PINNED LOCAL TX — after the consensus-required type-6 set, before
    // mempool selection. Gate re-checked on EVERY build: inputs unspent,
    // coinbase-mature at THIS height, fee exactly zero. Exclusion is the
    // only failure mode (see the parameter note); the MN-collateral filter
    // applies here too — a pinned tx spending a collateral would poison the
    // committed merkleRootMNList exactly like a selected one.
    if (pinned_local_txs != nullptr && !pinned_local_txs->empty())
        splice_pinned_txs(w, *pinned_local_txs, mempool, mnstates, "GBT-EMB");
    // ── #143 VERIFIED TYPE-9 UNLOCKS — after the consensus-required type-6
    // set and the pins, BEFORE the mempool-sourced range below (they are not
    // testmempoolaccept-probe material: special txs with no vin). Every tx
    // here already passed the follower's full fail-closed predicate; this
    // site only PLACES them. nullptr/empty = today's template, byte-identical.
    if (admitted_asset_unlocks != nullptr) {
        for (const auto& utx : admitted_asset_unlocks->txs) {
            w.m_txs.emplace_back(utx);
            w.m_tx_hashes.push_back(dash::coin::dash_txid(utx));
            // The unlock's miner fee is carried in its payload, not derivable
            // from vin (it has none) — record it so per-tx fee accounting sums
            // to the total_fees fold above.
            vendor::CAssetUnlockPayload upl;
            const uint64_t ufee =
                vendor::parse_assetunlock_payload(utx.extra_payload, upl)
                    ? upl.fee : 0;
            w.m_tx_fees.push_back(ufee);
            w.m_tx_data_hex.push_back(tx_hex(utx));
        }
        if (!admitted_asset_unlocks->txs.empty()) {
            LOG_INFO << "[GBT-EMB] #143 type-9 unlocks in template h="
                     << w.m_height << ": " << admitted_asset_unlocks->txs.size()
                     << " tx, gross_unlocked="
                     << admitted_asset_unlocks->gross_unlocked
                     << " payload_fees="
                     << admitted_asset_unlocks->total_payload_fees;
        }
    }
    uint64_t selected_bytes = 0;  // wire bytes packed into this template (underfill guard)
    // ── THE MEMPOOL-SOURCED RANGE (validity-gate probe set) ─────────────
    // Everything appended from here on is mempool-sourced; the type-6
    // commitments and the pinned local txs are already in. Recorded as a
    // RANGE so the gate probes exactly these and does not have to guess which
    // entries relay policy is entitled to refuse.
    w.m_mempool_tx_first_index = static_cast<uint32_t>(w.m_txs.size());
    std::set<uint256> selected_ids;
    for (auto& s : selected) {
        selected_bytes += s.base_size;
        const uint256 sid = dash::coin::dash_txid(s.tx);
        w.m_mempool_probe_depends_in_set.push_back(
            spends_earlier_in_set(s.tx, selected_ids) ? 1u : 0u);
        selected_ids.insert(sid);
        w.m_txs.emplace_back(s.tx);
        w.m_tx_hashes.push_back(sid);
        w.m_tx_fees.push_back(s.fee);
        w.m_tx_data_hex.push_back(tx_hex(s.tx));
    }
    w.m_mempool_tx_count = static_cast<uint32_t>(selected.size());

    // ── Underfill guard ─────────────────────────────────────────────
    // Do not silently treat a near-empty DASH template as healthy when the
    // DASH mempool held fee-paying backlog that should have filled it. We
    // cannot fabricate transactions, so surface loudly (WARNING) for
    // contabo-prod-watch / the operator rather than shipping a false-empty
    // block as normal. Genuinely empty mempools never trip. Mirrors the
    // LTC/DOGE TemplateBuilder guard; additive only — masternode payment /
    // CbTx / superblock projection below is untouched either way.
    if (!suppress_mempool_txs) {
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
    } else {
        // ── NAME THE STATE ───────────────────────────────────────────────────
        // The underfill guard is DELIBERATELY not consulted here: it exists to
        // catch an UNEXPLAINED near-empty template, and this one is explained.
        // Letting it fire would train operators to ignore the one line that is
        // supposed to mean "template-fill regression".
        //
        // Instead the mode says its own name, on the template itself and in the
        // log, with the price attached. A soak greps this to answer both "how
        // long did the node run coinbase-only" and "what did that cost".
        const uint64_t mempool_fees = mempool.total_known_fees();
        w.m_txset_empty_cause  = txset_empty_cause;
        w.m_txset_forgone_fees = mempool_fees;
        if (underfill_tripped) *underfill_tripped = false;
        LOG_INFO << "[GBT-EMB] arm=EMBEDDED txset=empty"
                 << " cause=" << txset_empty_cause
                 << " h=" << w.m_height
                 << " mempool_tx=" << mempool.size()
                 << " forgone_fees<=" << mempool_fees
                 << " sat (coinbase-only body: subsidy exact, no fee to"
                    " overstate; a valid block beats no block)";
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

    // MN payee → packed_payment(s). dashcore GBT returns "payee" as a
    // base58 address. We use script_to_address() to produce the same
    // wire form for standard P2PKH/P2SH scripts. Unrecognized script
    // types fall back to the c2pool "!hex" raw-script convention from
    // share_check.hpp::decode_payee_script — preserves bytes for
    // share_check verification while keeping the GBT API clean.
    auto script_to_payee_token = [&](const std::vector<unsigned char>& script) {
        // Dash mainnet has no bech32 (P2WPKH/P2WSH inactive); pass
        // empty hrp so script_to_address() falls through cleanly.
        std::string addr = ::core::script_to_address(
            script, /*bech32_hrp=*/"",
            address_version, address_p2sh_version);
        if (!addr.empty()) return addr;
        // Non-standard script: fall back to !hex.
        std::string hex_script;
        hex_script.reserve(script.size() * 2 + 1);
        hex_script.push_back('!');
        static const char* digits = "0123456789abcdef";
        for (uint8_t b : script) {
            hex_script.push_back(digits[(b >> 4) & 0xF]);
            hex_script.push_back(digits[b & 0xF]);
        }
        return hex_script;
    };
    auto expected = mnstates.find_expected_payee();
    if (expected) {
        auto it = mnstates.entries().find(*expected);
        if (it != mnstates.entries().end() && mn_payment > 0) {
            const auto& st = it->second;
            // ── Operator-reward split (incident h=2516595 bad-cb-payee) ──
            // dashd masternode/payments.cpp GetBlockTxOuts pays the MN
            // share as a SET: when the scheduled MN registered an operator
            // share (nOperatorReward bps, ProRegTx) AND its operator set a
            // payout script (ProUpServTx), the coinbase carries
            //   owner   : mnShare - floor(mnShare * bps / 10000)
            //   operator: floor(mnShare * bps / 10000)
            // in that order, and CheckMasternodePayments validates scripts
            // AND amounts. h=2516595 (mn 0037c2c5…, bps=800) was rejected
            // bad-cb-payee precisely because this builder paid the whole
            // share to the owner. The truncating division is dashd's own;
            // do NOT "fix" the rounding.
            const int64_t operator_payment = st.operator_payment_of(mn_payment);
            const int64_t owner_payment    = mn_payment - operator_payment;
            if (owner_payment > 0) {
                PackedPayment pp;
                pp.payee  = script_to_payee_token(st.scriptPayout.m_data);
                pp.amount = static_cast<uint64_t>(owner_payment);
                w.m_packed_payments.push_back(std::move(pp));
            }
            // dashd: `if (operatorReward > 0) emplace_back(...)` — a split
            // whose floor rounds to zero emits NO operator output.
            if (operator_payment > 0) {
                PackedPayment pp;
                pp.payee  = script_to_payee_token(st.scriptOperatorPayout.m_data);
                pp.amount = static_cast<uint64_t>(operator_payment);
                w.m_packed_payments.push_back(std::move(pp));
            }
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
        //
        // #107 PHASE 2: when --embedded-accrue-asset-locks is armed, ADD the
        // DIP-0027 type-8 (asset-lock) term dashd commits for this block. dashd
        // builds its template from the pending locks in its mempool and adds,
        // for each, the value of the lock tx's FIRST OP_RETURN output
        // (creditpool.cpp:262-276) to GetTotalLocked() (creditpool.h:98-100),
        // written to the CbTx at miner.cpp:314. We fold the SAME source — the
        // pending type-8 locks in OUR mempool — with the SAME arithmetic
        // (asset_lock_fold.hpp), each validated by check_asset_lock_tx
        // (assetlocktx.cpp:44-95) so only would-be-valid block members count.
        // Off (default) the term is 0 and the accrual is byte-identical to the
        // pre-phase-2 template. The emit gate (node_coin_state.hpp
        // embedded_template_emit_ok) re-derives this SAME term over the SAME
        // mempool snapshot, so a fresh build cannot trip emit-creditpool-value-
        // drift (PR body B2).
        int64_t asset_lock_accrual = 0;
        if (accrue_pending_asset_locks) {
            const AssetLockFold f =
                pending_asset_lock_fold(mempool.pending_asset_lock_txs());
            asset_lock_accrual = f.accrued;
            if (f.count > 0 || f.rejected > 0) {
                LOG_INFO << "[GBT-EMB] #107 asset-lock accrual h="
                         << (prev_height + 1) << " folded=" << f.count
                         << " rejected=" << f.rejected
                         << " accrual=" << asset_lock_accrual
                         << " duff (committed creditPoolBalance now INCLUDES the"
                            " pending type-8 locks; block is valid ONLY if those"
                            " same txs ride the served body -- #125/tx-serving)";
            }
        }
        // #143: the admitted unlocks' GROSS amount (Σ vout + fee) LEAVES the
        // pool — dashd's sessionUnlocked term in GetTotalLocked
        // (creditpool.h:98-100). The validator re-derives this from the
        // block's OWN type-9 txs (which ride this template's body above), so
        // committing the deduction is what MAKES the block valid; nullptr /
        // empty deducts 0 and the accrual is byte-identical to today.
        const int64_t asset_unlock_deduction =
            admitted_asset_unlocks != nullptr
                ? admitted_asset_unlocks->gross_unlocked : 0;
        const int64_t accrued_credit_pool =
            last_observed_credit_pool + platform_reward + asset_lock_accrual
            - asset_unlock_deduction;
        // confirmedHash rollover (sml_projection.hpp, FINDING-1): the tip SML
        // is the verifier's PREV list, not the list for the block being
        // templated — dashd's rebuild starts with a purely height-driven
        // confirmation pass (specialtxman.cpp:206-215) that flips a
        // registered MN's confirmedHash at the crossing height with NO tx
        // causing it. Commit the PROJECTED root, not the tip root. When the
        // projection is unprojectable (a null-confirmedHash entry with no
        // known registration height) the root below may be stale; the
        // NodeCoinState viability + pre-emit gates fail closed on exactly
        // that condition ("mn-confirm-rollover-pending"), so this build can
        // never be SERVED — the warning is for callers outside that gate.
        auto proj = project_sml_confirmations(
            *sml, prev_height, prev_hash, mnstates, mn_min_confirmations);
        if (!proj.ok) {
            LOG_WARNING << "[GBT-EMB] confirmedHash rollover UNPROJECTABLE at h="
                        << (prev_height + 1) << ": SML entry "
                        << proj.unprojectable_protx.GetHex().substr(0, 16)
                        << " has null confirmedHash but no known registration "
                        << "height — committed merkleRootMNList may be stale "
                        << "(emit gate refuses this template)";
        } else if (proj.confirmed > 0) {
            LOG_INFO << "[GBT-EMB] confirmedHash rollover: " << proj.confirmed
                     << " MN(s) cross nMasternodeMinimumConfirmations at h="
                     << (prev_height + 1)
                     << " — committing projected merkleRootMNList";
        }
        vendor::CCbTx cb = build_embedded_cbtx(
            prev_height, proj.sml, *qmgr, best_cl_height, best_cl_sig,
            accrued_credit_pool, quorum_root_override);
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
    int64_t  last_observed_credit_pool,
    // E1: the with-block merkleRootQuorums (fold of the template's own
    // type-6 commitments over the active set). nullptr (default) => the
    // plain PROVEN active-set root — byte-identical for every pre-E1 caller
    // AND for all-null commitment sets.
    const uint256* quorum_root_override = nullptr)
{
    vendor::CCbTx c;
    c.nVersion           = vendor::CCbTx::VERSION_CLSIG_AND_BALANCE;
    c.nHeight            = static_cast<int32_t>(prev_height + 1);
    // CalcMerkleRoot() is const and does NOT cache — every call hashes the
    // full list (~2000 x SHA256d on mainnet). A prior comment here claimed
    // "CalcMerkleRoot() caches upstream" and budgeted the ~450 KB copy it
    // took to call it "per 5s shadow tick"; BOTH clauses were false — this
    // builder runs on the live serve path, and that assumed-cheap root
    // recompute is the class behind the 2026-08-07/08 hotel freeze (26
    // rigs -> 0, twice). The serve-time re-derivations are memoized at
    // NodeCoinState level (root-memo epoch); this build-time call runs once
    // per template build, directly on the caller's list, no copy.
    c.merkleRootMNList   = sml.CalcMerkleRoot();
    c.merkleRootQuorums  = quorum_root_override
        ? *quorum_root_override
        : compute_merkle_root_quorums(qmgr);

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