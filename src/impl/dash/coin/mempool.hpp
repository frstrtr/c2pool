// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-MEMPOOL step 1: in-memory Dash mempool.
///
/// Adapted from src/impl/ltc/coin/mempool.hpp (~735 LOC) with these
/// Dash-specific simplifications:
///   - No segwit → no TX_WITH_WITNESS / TX_NO_WITNESS distinction; just
///     `pack(tx)` and `dash::coin::dash_txid()`.
///   - No weight calculation → just base_size = sizeof serialized tx.
///   - No wtxid index (BIP 152 v2 never reaches Dash; we already pin
///     CMPCTBLOCKS_VERSION=1 in Phase U).
///   - Special-tx (type 1-4 ProTx, type 5 CCbTx, type 6 quorum
///     commitment) are stored as opaque MutableTransaction blobs;
///     consumers (Phase C-PAY's state machine, future block-template
///     builder) decode their own way.
///
/// Step 1 SCOPE: storage layer + UTXO fee + LRU size-cap eviction +
/// confirm-eviction + double-spend conflict detection. All thread-safe
/// via single std::mutex.
///
/// Step 2 ADDS:
///   - Feerate-sorted index (m_feerate_index) maintained on add/remove
///   - get_sorted_txs_with_fees(max_bytes): highest-feerate-first
///     selection up to a byte cap, with stale-input guard. Phase
///     C-TEMPLATE prerequisite.
///   - recompute_unknown_fees(utxo): re-attempts fee computation for
///     entries marked fee_known=false (typically after a block
///     connect added their inputs to UTXO).
///
/// DEFERRED (later steps):
///   - BIP 35 mempool initial sync drain (step 3 — wire already in
///     p2p_node.hpp, no consumer yet)
///   - revalidate_inputs (evict txs whose inputs got spent without
///     us catching it via remove_for_block conflict path)
///   - Orphan-children removal after conflict eviction
///   - Lightweight summary API for the explorer/dashboard
///
/// ██ SOLE-INGESTION-PATH INVARIANT (audit N-A-BY-SOURCE-INVARIANT rows) ██
/// The ONLY path that feeds add_tx() in a live node is dashd-peer relay:
/// interfaces::Node::new_tx → wire_mempool_ingest (mempool_ingest.hpp) →
/// CoinStateMaintainer::on_mempool_tx → add_tx. Two whole ConnectBlock
/// reject classes are argued N-A on exactly this invariant
/// (DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md §6):
///   - bad-txns-nonfinal (BIP68/locktime): relay-admitted txs are final at
///     admission and finality is monotonic in height/MTP;
///   - mandatory-script-verify-flag (CheckInputScripts): relay-admitted txs
///     passed full script checks at every relaying dashd, and we never
///     mutate tx bytes.
/// If ANY other ingestion seam is ever added (RPC sendrawtransaction, local
/// wallet submission, cross-coin tx forward, BIP35 sync drain), those two
/// rows become GAPs: re-audit and add local finality + script checks BEFORE
/// wiring it. Do not silently add callers of add_tx().

#include "block.hpp"
#include "transaction.hpp"
#include "utxo_adapter.hpp"
#include "sigops.hpp"             // G2: bad-blk-sigops accounting during selection
#include "vendor/assetlock.hpp"   // DIP-0027 CAssetUnlockPayload (type-9 fee source)

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <atomic>
#include <cmath>                 // block_min_fee_for_size: dashd CFeeRate::GetFee std::ceil
#include <functional>
#include <cstdint>
#include <ctime>
#include <deque>
#include <map>
#include <set>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

struct MempoolEntry {
    MutableTransaction tx;
    uint256  txid;
    uint32_t base_size{0};
    uint64_t fee{0};            // satoshi (computed from UTXO when available)
    // W5-B: PrioritiseTransaction-style fee delta (dashd mapDeltas /
    // CTxMemPoolEntry::GetModifiedFee). SCORING uses fee + fee_delta
    // (feerate index, ancestor aggregates, blockMinFeeRate gate — dashd's
    // nModFeesWithAncestors basis); ACCOUNTING (total_fees → coinbasevalue,
    // SelectedTx.fee) stays BASE fee, exactly dashd's split (miner.cpp
    // AddToBlock nFees += iter->GetFee()). Today's only writer is the
    // BLS-verified DSTX admission (+0.1 COIN, net_processing.cpp:3609);
    // 0 everywhere else = byte-identical ordering (modified == base).
    uint64_t fee_delta{0};
    bool     fee_known{false};
    // EXCLUSION-DISCIPLINE selection predicate (tx-serving reward-safety).
    // fee_known is TWO things: "priceable via the W5 UTXO fold" OR "a DSTX
    // whose fee was FORCED to 0 because the fold could not price it"
    // (add_tx_locked is_dstx branch). The forced case sets fee_known=true on
    // inputs the fold could NOT vouch for, so fee_known ⇏ inputs-proven-present
    // — unsafe to SELECT a template member on. fee_fold_proven is set ONLY by
    // compute_fee_locked success (every vin priced from our own UTXO view /
    // in-pool parent, in_sum >= out_sum, or an input-free type-9 with a
    // well-formed explicit-fee payload). It is the ONE bit that proves BOTH
    // invariant-1 "inputs available in our UTXO view" AND invariant-2 "fee is
    // fold-exact, never overstated". The template selector gates on THIS, never
    // on fee_known; fee_known stays the RELAY/index/stats predicate unchanged.
    bool     fee_fold_proven{false};
    time_t   time_added{0};

    uint64_t modified_fee() const { return fee + fee_delta; }

    double feerate_satvb() const {
        return (fee_known && base_size > 0)
            ? static_cast<double>(fee) / base_size
            : 0.0;
    }
};

/// Deterministic block-template selection key. Sorts highest-feerate
/// first; ties broken by txid ascending. Byte-reproducible across
/// nodes/runs AND bit-for-bit conformant with dashcore BlockAssembler
/// ordering. dashcore CompareTxMemPoolEntryByAncestorFee compares two
/// entries by cross-multiplication of (fee, size) as doubles --
/// f1 = a.fee * b.size vs f2 = b.fee * a.size -- explicitly "avoid
/// division by rewriting (a/b > c/d) as (a*d > c*b)". A pre-divided
/// fee/base_size double rounds where the cross-multiply does not, so the
/// two representations can order a tie-pair differently. We therefore
/// carry (fee, base_size) and reproduce the exact double cross-multiply;
/// equal feerate is broken by GetHash()/txid ascending, as the oracle
/// does.
///
/// The persistent m_feerate_index keys FeeKey by an entry's STANDALONE
/// (fee, base_size). The block-template selector (get_sorted_txs_with_fees)
/// additionally reuses this exact comparator over the ANCESTOR-SCORE
/// (min-of-two) values — see anc_score_key / build_anc_state_locked — which
/// is precisely how dashd shares CompareTxMemPoolEntryByAncestorFee between
/// mapTx and mapModifiedTx (D1/D2). The struct and its operator< are
/// identical either way; only the (fee, size) fed in differ.
// dashcore CompareIteratorByHash / CTransaction::GetHash() tie-break order.
//
// The embedded uint256 is base_uint<256>, whose operator< delegates to
// CompareTo(): an ARITHMETIC limb comparison, most-significant 32-bit limb
// first. dashcore breaks every equal-feerate / equal-ancestor-count mining tie
// with CTxMemPool::CompareIteratorByHash, i.e. uint256::operator< ==
// base_blob::Compare == std::memcmp over the RAW (wire-serialized, little-
// endian) hash bytes, byte 0 first. Those two orders differ, so using the
// arithmetic operator< for the tie-break transposes adjacent equal-key txs vs
// dashd and diverges the block tx-merkle root (the tx-serving ordering
// residual). Reproduce dashd's memcmp exactly: compare the serialized bytes,
// byte 0 (limb 0 LSB) first. Extraction is by shift, so it is identical on any
// host endianness and matches the wire bytes dashd hashes.
inline bool txid_oracle_less(const uint256& a, const uint256& b)
{
    for (int i = 0; i < 32; ++i) {
        const uint8_t ba = static_cast<uint8_t>(a.pn[i >> 2] >> (8 * (i & 3)));
        const uint8_t bb = static_cast<uint8_t>(b.pn[i >> 2] >> (8 * (i & 3)));
        if (ba != bb) return ba < bb;
    }
    return false;
}

struct FeeKey {
    uint64_t fee;        // satoshi
    uint32_t base_size;  // serialized bytes (>0 for every indexed entry)
    uint256  txid;
    bool operator<(const FeeKey& o) const {
        // dashcore CompareTxMemPoolEntryByAncestorFee, division-free form.
        const double f1 = static_cast<double>(fee)   * o.base_size;
        const double f2 = static_cast<double>(o.fee) * base_size;
        if (f1 != f2) return f1 > f2;   // higher feerate first
        return txid_oracle_less(txid, o.txid);   // dashd GetHash() memcmp tie-break
    }
};

class Mempool {
public:
    static constexpr size_t DEFAULT_MAX_BYTES   = 300ULL * 1024 * 1024;
    static constexpr time_t DEFAULT_EXPIRY_SECS = 14 * 24 * 3600;

    /// dashd DEFAULT_BLOCK_MIN_TX_FEE (src/policy/policy.h:25) — the minimum
    /// ancestor-package feerate, in duffs per 1000 bytes, below which
    /// BlockAssembler::addPackageTxs stops adding transactions (miner.cpp:69,
    /// blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE)). This is the
    /// canonical dashd default: keeping it here makes the embedded selection
    /// terminate at the SAME floor as dashd's own miner out of the box.
    static constexpr int64_t DEFAULT_BLOCK_MIN_TX_FEE = 1000;

    /// dashd BlockAssembler MAX_CONSECUTIVE_FAILURES (src/node/miner.cpp:490):
    /// once this many packages in a row fail the byte/sigop caps AND the block
    /// is within 1000 bytes of full, addPackageTxs gives up scanning.
    static constexpr int64_t MAX_CONSECUTIVE_FAILURES = 1000;

    /// dashd WAIT_FOR_ISLOCK_TIMEOUT (src/chainlock/handler.cpp:35, 10min) —
    /// the IS/CL MINING-SAFETY HOLD. On mainnet (spork2 InstantSend + spork3
    /// RejectConflictingBlocks active) dashd's BlockAssembler REFUSES any
    /// package member with vins that is not islocked AND whose first-seen age
    /// is under this bound (TestPackageTransactions, miner.cpp:374-391 →
    /// ChainlockHandler::IsTxSafeForMining, handler.cpp:204-215). It is the
    /// miner-side defence against the islock-formation race: mine a tx whose
    /// outpoints then get islocked to a CONFLICTING spend and the won block
    /// dies conflict-tx-lock (validation.cpp). MempoolEntry::time_added is our
    /// txFirstSeenTime; a tx with a KNOWN islock (m_islock_txids) is safe
    /// immediately, exactly dashd's IsLocked(txid) short-circuit.
    static constexpr time_t WAIT_FOR_ISLOCK_TIMEOUT_SECS = 600;

    /// c2pool-side LIVENESS GATE on the hold (NO dashd equivalent — dashd
    /// trusts its own islock db to be alive). Our islock knowledge rides the
    /// coin-P2P isdlock leg; if that leg goes dark (the qrinfo-#1077 silent-
    /// registry failure class) an armed hold would quietly hold EVERY young tx
    /// for 10 minutes — far WORSE template parity than no hold at all. So the
    /// hold is active only while an islock has been seen this recently; a dark
    /// feed degrades to the pre-hold include-immediately behaviour (reward-
    /// safe: the #1218 gbt-xcheck fails closed to dashd on any divergence
    /// while the fallback arm exists). Mainnet forms an islock for most txs,
    /// so a healthy feed ticks many times per block interval.
    static constexpr time_t ISLOCK_FEED_FRESH_SECS = 600;

    explicit Mempool(size_t max_bytes  = DEFAULT_MAX_BYTES,
                     time_t expiry_sec = DEFAULT_EXPIRY_SECS)
        : m_max_bytes(max_bytes)
        , m_expiry_sec(expiry_sec)
    {}

    Mempool(const Mempool&) = delete;
    Mempool& operator=(const Mempool&) = delete;

    void set_utxo(::core::coin::UTXOViewCache* u) { m_utxo.store(u); }

    /// blockmintxfee-equivalent knob (dashd -blockmintxfee / BlockAssembler
    /// Options::blockMinFeeRate, miner.cpp:100). Sets the min ancestor-package
    /// feerate in duffs/kB used by the blockMinFeeRate early-return in
    /// get_sorted_txs_with_fees. DEFAULT_BLOCK_MIN_TX_FEE (1000) matches
    /// canonical dashd; callers may lower it (e.g. 0 to disable the floor) or
    /// raise it. Locked because the selector reads it under m_mutex.
    void set_block_min_tx_fee(int64_t duff_per_k)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_block_min_tx_fee = duff_per_k;
    }
    int64_t block_min_tx_fee() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_block_min_tx_fee;
    }

    /// Arm/disarm the IS/CL mining-safety hold. The caller (main_dash, off the
    /// coin-P2P SporkState on its io thread) pushes the spork2+spork3
    /// conjunction here — dashd's own gate: TestPackageTransactions skips the
    /// hold entirely when !RejectConflictingBlocks() || !IsInstantSendEnabled()
    /// (miner.cpp:382). Atomic because the selection path reads it from the
    /// serve executor. DEFAULT OFF so unit tests and un-wired callers keep the
    /// pre-hold selection behaviour bit-for-bit; even when armed, the hold
    /// additionally self-gates on isdlock-feed liveness (ISLOCK_FEED_FRESH_SECS).
    void set_instantsend_mining_hold(bool armed)
    {
        m_is_hold_armed.store(armed, std::memory_order_relaxed);
    }
    bool instantsend_mining_hold() const
    {
        return m_is_hold_armed.load(std::memory_order_relaxed);
    }

    /// ── PINNED-LOCAL-TX include gate (donation-dust consolidation lane) ────
    /// A pinned tx is an operator-supplied, externally-signed, ZERO-fee
    /// transaction that rides OUR OWN block template (relay rejects 0-fee, so
    /// self-mining is its only chain-ward path). A bad pinned tx would make
    /// the whole found block invalid — a lost block — so admission is checked
    /// against the live UTXO view on EVERY template build and the tx is
    /// EXCLUDED (never the template refused) on any failure:
    ///   * every input must exist unspent in our UTXO view;
    ///   * a coinbase-output input must be MATURE at the template height
    ///     (100 confs — donation outputs ARE coinbase outputs, so the newest
    ///     ones are immature for ~4.5 h after their block; the tx self-heals
    ///     into templates once they mature);
    ///   * inputs minus outputs must equal EXACTLY ZERO — this lane's
    ///     contract. Nonzero means the snapshot the tx was built from has
    ///     drifted (or the wrong tx was pinned); negative would be
    ///     consensus-invalid (bad-txns-in-belowout) outright.
    /// Once mined, the inputs leave the UTXO set and the gate excludes the tx
    /// forever after — no explicit "done" state is needed.
    enum class PinnedTxGate : uint8_t {
        Ok = 0,
        UtxoViewUnset,          // no UTXO view wired yet (cold start)
        InputMissingOrSpent,    // an input is not an unspent coin we know
        ImmatureCoinbaseInput,  // a coinbase-output input below 100 confs
        FeeNotZero,             // sum(in) - sum(out) != 0: snapshot drift
        TooLarge,               // serialized size exceeds the consensus cap
    };
    /// Dash rejects an oversize transaction at CONSENSUS, not merely policy —
    /// CheckTransaction() returns "bad-txns-oversize", so a block carrying one
    /// is INVALID, not just non-standard. That distinction cost a real block:
    ///
    ///   2026-08-07 14:33:45  won block height=2517855 bytes=152889
    ///   2026-08-07 14:33:45  submit_block_hex result: "bad-txns-oversize"
    ///
    /// height 2517855 went to another miner. The pinned tx was 152258 bytes
    /// (1032 inputs). Every gate face we had — inputs unspent, coinbase
    /// maturity, fee exactly zero, no MN-collateral spend — PASSED. The tx was
    /// admissible by every rule we had thought to write, and unmineable.
    /// Confirmed independently against the daemon:
    ///   testmempoolaccept -> allowed=false reject-reason="bad-txns-oversize"
    ///
    /// A pin costs the WHOLE BLOCK when it is wrong, not just its own value.
    static constexpr size_t kMaxPinnedTxBytes = 100000;
    /// Cumulative cap across ALL pins in one template. Well under Dash's
    /// 2 MB block limit, because the pins are not the only thing in the block
    /// and a template we cannot mine is worth nothing.
    static constexpr size_t kMaxPinnedTotalBytes = 400000;
    /// Dash's consensus maximum serialized block size (DIP-0001, 2 MB).
    static constexpr size_t kMaxBlockBytes = 2000000;
    /// Headroom the pin splice refuses to touch: the 80-byte header, the
    /// tx-count varint, and a coinbase that carries the DIP-0004 payload plus
    /// every masternode/superblock/platform output. 100 KB is far more than any
    /// of those need; the point is that the number is CONSERVATIVE and named,
    /// not that it is tight.
    static constexpr size_t kBlockBytesReserve = 100000;
    /// THE BLOCK-LEVEL BUDGET. kMaxPinnedTotalBytes caps the pins against each
    /// OTHER; this caps them against what the template they are being appended
    /// to ALREADY holds. Without it a 400 KB pin set is admitted onto a dashd
    /// template that is already near 2 MB and the block is unmineable
    /// (bad-blk-length) -- the same class of loss as the 152258-byte pin that
    /// cost block 2517855, one level up.
    static constexpr size_t kMaxPinnedBlockBytes =
        kMaxBlockBytes - kBlockBytesReserve;
    static const char* pinned_gate_name(PinnedTxGate g) {
        switch (g) {
            case PinnedTxGate::Ok:                    return "ok";
            case PinnedTxGate::UtxoViewUnset:         return "utxo-view-unset";
            case PinnedTxGate::InputMissingOrSpent:   return "input-missing-or-spent";
            case PinnedTxGate::ImmatureCoinbaseInput: return "immature-coinbase-input";
            case PinnedTxGate::TooLarge:              return "tx-too-large";
            case PinnedTxGate::FeeNotZero:            return "fee-not-zero";
        }
        return "ok";
    }
    /// SECOND SOURCE for coin lookup (money-path, added 2026-08-07 after the
    /// production primary refused a valid pin). The embedded UTXO view is
    /// built forward from the height the node was started at, so coins older
    /// than that are simply ABSENT from it — the gate then reports
    /// input-missing-or-spent for inputs that are, in fact, perfectly unspent.
    ///
    /// This is NOT a relaxation. The gate still demands the same three facts —
    /// the coin exists, it is unspent, and its value is known so fee==0 can be
    /// COMPUTED rather than assumed — it just accepts a second authoritative
    /// place to learn them (the coin daemon's own UTXO set, when an RPC arm is
    /// wired). A pin whose inputs neither source can resolve is still refused.
    void set_external_coin_lookup(
        std::function<bool(const ::core::coin::Outpoint&, ::core::coin::Coin&)> fn)
    {
        m_external_coin_lookup = std::move(fn);
    }
    bool has_external_coin_lookup() const { return static_cast<bool>(m_external_coin_lookup); }

    PinnedTxGate pinned_tx_admissible(const MutableTransaction& tx,
                                      uint32_t next_height) const {
        // SIZE FIRST. It is the cheapest check and the only one whose failure
        // is certain regardless of chain state — an oversize tx is invalid at
        // every height, against every UTXO view. Checking it before the 1032
        // coin lookups also stops us paying for a verdict we already know.
        if (::pack(tx).get_span().size() > kMaxPinnedTxBytes)
            return PinnedTxGate::TooLarge;
        auto* utxo = m_utxo.load();
        if (utxo == nullptr && !m_external_coin_lookup)
            return PinnedTxGate::UtxoViewUnset;
        constexpr uint32_t kCoinbaseMaturity = 100;
        int64_t in_value = 0;
        for (const auto& vin : tx.vin) {
            ::core::coin::Coin coin;
            ::core::coin::Outpoint op{vin.prevout.hash, vin.prevout.index};
            bool found = utxo != nullptr && utxo->get_coin(op, coin) && !coin.is_spent();
            if (!found && m_external_coin_lookup) {
                coin = ::core::coin::Coin{};
                found = m_external_coin_lookup(op, coin) && !coin.is_spent();
            }
            if (!found)
                return PinnedTxGate::InputMissingOrSpent;
            if (coin.coinbase && next_height < coin.height + kCoinbaseMaturity)
                return PinnedTxGate::ImmatureCoinbaseInput;
            in_value += coin.value;
        }
        int64_t out_value = 0;
        for (const auto& vout : tx.vout) out_value += vout.value;
        if (in_value - out_value != 0) return PinnedTxGate::FeeNotZero;
        return PinnedTxGate::Ok;
    }

    // ── Mutation ────────────────────────────────────────────────────

    /// Add a transaction. Returns false if already known. When `utxo`
    /// is passed (or set_utxo was called), attempts fee computation;
    /// falls back to fee_known=false on missing-input.
    bool add_tx(const MutableTransaction& tx)
    {
        return add_tx(tx, m_utxo.load());
    }

    bool add_tx(const MutableTransaction& tx,
                ::core::coin::UTXOViewCache* utxo)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return add_tx_locked(tx, utxo, /*is_dstx=*/false);
    }

    /// W5-B: dashd's DSTX prioritisation delta — PrioritiseTransaction(hash,
    /// COIN/10) fired by ValidateDSTX on every BLS-verified CoinJoin
    /// broadcast tx BEFORE mempool acceptance (net_processing.cpp:3609).
    static constexpr uint64_t DSTX_FEE_DELTA = 10'000'000;   // 0.1 COIN, duffs

    /// W5-B: admit a BLS-VERIFIED CoinJoin broadcast tx. ONLY caller is
    /// CoinStateMaintainer::on_new_dstx AFTER the operator-signature BLS gate
    /// passed (fail-closed; see the sole-ingestion-path invariant above —
    /// this is a second, explicitly-audited seam: structural validity was
    /// checked at the P2P handler, the tx is a protocol-forced denominated
    /// mixing tx, and finality/script arguments carry over from the same
    /// dashd-relay source).
    ///
    /// Mirrors dashd's ORDER exactly: the delta is recorded BEFORE admission
    /// (mapDeltas pre-dates and survives acceptance), then the tx is admitted
    /// with fee=0 when inputs are unpriceable — reward-SAFE because a DSTX's
    /// protocol shape (vin.size()==vout.size(), all-denominated outputs)
    /// forces fee≈0, and even a hostile signed nonzero-fee DSTX only makes
    /// total_fees UNDERSTATE ⇒ coinbase pays ≤ allowed ⇒ never an invalid
    /// block. If compute_fee_locked CAN price it, the computed base fee is
    /// kept. If the plain MSG_TX body arrived first (already pooled), the
    /// delta is applied RETROACTIVELY — we converge on dashd's STATE (the
    /// prioritised pool), not its message-order accident.
    bool add_dstx(const MutableTransaction& tx,
                  uint64_t fee_delta = DSTX_FEE_DELTA)
    {
        const uint256 txid = dash_txid(tx);
        std::lock_guard<std::mutex> lock(m_mutex);
        record_fee_delta_locked(txid, fee_delta);
        auto it = m_pool.find(txid);
        if (it != m_pool.end()) {
            // Retro-apply: re-key the feerate index under the new modified
            // fee (every index site keys FeeKey{modified_fee(), size, txid}).
            if (it->second.fee_delta != fee_delta) {
                if (it->second.fee_known)
                    m_feerate_index.erase(FeeKey{it->second.modified_fee(),
                                                 it->second.base_size, txid});
                it->second.fee_delta = fee_delta;
                if (it->second.fee_known)
                    m_feerate_index.insert(FeeKey{it->second.modified_fee(),
                                                  it->second.base_size, txid});
                LOG_INFO << "[MEMPOOL] dstx delta retro-applied txid="
                         << txid.GetHex().substr(0, 16)
                         << " delta=" << fee_delta;
            }
            return false;   // already known (same contract as add_tx)
        }
        return add_tx_locked(tx, m_utxo.load(), /*is_dstx=*/true);
    }

private:
    bool add_tx_locked(const MutableTransaction& tx,
                       ::core::coin::UTXOViewCache* utxo,
                       bool is_dstx)
    {
        uint256 txid = dash_txid(tx);
        if (m_pool.count(txid)) return false;

        // #125 — REJECT ALREADY-CONFIRMED TRANSACTIONS AT ADMISSION.
        //
        // A peer can relay a transaction that is ALREADY MINED. The txid-dedup
        // above only catches a tx already in OUR pool (the benign
        // txn-already-in-mempool case); it does NOT catch one that is already
        // in a block but never passed through our pool. Admitting such a tx and
        // then packing it into a template produces an INVALID BLOCK (a lost
        // block), so it must be refused here — upstream of the mempool validity
        // gate, which is correct and untouched.
        //
        // Ported EXACTLY from dashd MemPoolAccept::PreChecks
        // (/tmp/dashsrc/src/validation.cpp:851-857):
        //     if (!m_view.HaveCoin(txin.prevout)) {
        //         for (size_t out = 0; out < tx.vout.size(); out++)
        //             if (coins_cache.HaveCoinInCache(COutPoint(hash, out)))
        //                 return state.Invalid(TX_CONFLICT, "txn-already-known");
        //         return state.Invalid(TX_MISSING_INPUTS, ...);
        //     }
        // The signal: when an input's coin is MISSING from the view but one of
        // the tx's OWN outputs is already a coin in the view, that output can
        // only exist because the identical tx (txid = Hash(tx)) is already in a
        // block. A genuine unconfirmed tx has its inputs PRESENT and its own
        // outputs ABSENT, so it never reaches the own-output scan.
        //
        // ORDERING IS LOAD-BEARING (dashd's !HaveCoin guard): we consult
        // own-outputs ONLY when at least one input is missing. We must NEVER
        // reject a tx whose inputs are all present (a normal unconfirmed tx),
        // and — unlike dashd's else-branch — we do NOT reject on
        // input-missing-alone: CPFP chains, coins older than the node's start
        // height, and orphans are admitted today with fee_known=false and must
        // stay admitted. The reject fires ONLY on own-output-present.
        //
        // FAIL-OPEN (false-negative-safe): the check runs only when a UTXO view
        // is wired; if the forward-built view cannot tell (no view, or a
        // confirmed tx whose outputs were since spent / predate our start
        // height), we ADMIT and let the mempool validity gate / serve path
        // decide. This is deliberate: a false REJECT of a genuinely-unconfirmed
        // valid tx would silently DROP its fees once --embedded-serve-mempool-txs
        // arms. A false positive is impossible here — for an own output
        // (txid:n) to already be a coin, some tx must have produced the
        // identical outpoint, and identical outpoint ⇒ identical txid ⇒
        // identical tx, i.e. the already-confirmed instance, never a distinct
        // unconfirmed tx.
        if (utxo != nullptr) {
            bool any_input_missing = false;
            for (const auto& vin : tx.vin) {
                ::core::coin::Outpoint op(vin.prevout.hash, vin.prevout.index);
                if (!utxo->have_coin(op)) { any_input_missing = true; break; }
            }
            if (any_input_missing) {
                for (size_t out = 0; out < tx.vout.size(); ++out) {
                    ::core::coin::Outpoint own(txid, static_cast<uint32_t>(out));
                    if (utxo->have_coin(own)) {
                        LOG_INFO << "[MEMPOOL] reject txn-already-known txid="
                                 << txid.GetHex().substr(0, 16)
                                 << " (own output " << out
                                 << " already a coin, an input is missing)";
                        return false;
                    }
                }
            }
        }

        MempoolEntry entry;
        entry.tx         = tx;
        entry.txid       = txid;
        auto packed      = ::pack(tx);
        entry.base_size  = static_cast<uint32_t>(packed.size());
        entry.time_added = std::time(nullptr);
        // W5-B: dashd's ONE automatic mapDeltas write that EVERY node performs.
        // CTxMemPool::addUnchecked prioritises every MNHF/EHF-signal tx by
        // +0.1 COIN at admission — src/txmempool.cpp:701-702 (v23.1.7):
        //     if (tx.nType == TRANSACTION_MNHF_SIGNAL)
        //         PrioritiseTransaction(entry.GetTx().GetHash(), 0.1 * COIN);
        // These type-7 EHF-signal txs are ~0-fee on the wire but MUST sort to
        // the very top of the block template; without the delta the embedded
        // ancestor-score selector orders them at their base (≈0) feerate and
        // drops/misplaces them, diverging dashd's tx-set and tx-merkle root.
        // Unlike the DSTX delta (recorded in add_dstx, network-DSTX-only), this
        // one is intrinsic to the tx type, so it is reproduced on EVERY
        // admission path (plain MSG_TX included), exactly as dashd does it in
        // addUnchecked. Recorded into m_fee_deltas (dashd mapDeltas) so the
        // entry.fee_delta read just below picks it up AND it survives /
        // retro-applies identically to the DSTX delta.
        //
        // REWARD-SAFE: the delta only raises modified_fee() — the scoring /
        // ordering / blockMinFeeRate basis (dashd nModFeesWithAncestors). The
        // raw `fee` that feeds total_fees → coinbasevalue is UNTOUCHED, so the
        // coinbase is never overstated and no invalid block can result. A
        // type-7 whose inputs our UTXO fold cannot price stays fee_fold_proven
        // == false → template-excluded (fail-closed), matching the exclusion
        // discipline; the recorded delta simply lets it ride at the correct
        // modified fee once recompute_unknown_fees can price it.
        // TRANSACTION_MNHF_SIGNAL == nType 7 (dashd primitives/transaction.h).
        static constexpr uint16_t TRANSACTION_MNHF_SIGNAL = 7;
        if (tx.type == TRANSACTION_MNHF_SIGNAL)
            record_fee_delta_locked(txid, DSTX_FEE_DELTA);
        // W5-B: a recorded prioritisation delta applies WHENEVER the tx is
        // admitted, on either path (dashd mapDeltas semantics — the delta
        // pre-dates and survives acceptance).
        if (auto dit = m_fee_deltas.find(txid); dit != m_fee_deltas.end())
            entry.fee_delta = dit->second;

        compute_fee_locked(entry, utxo);
        // W5-B: a BLS-verified DSTX whose inputs the view cannot price is
        // admitted at fee=0 (see add_dstx — understate-only, reward-safe);
        // a priceable one keeps its computed base fee.
        //
        // EXCLUSION-DISCIPLINE: this FORCES fee_known=true so the DSTX rides
        // the relay pool / feerate index, but it does NOT set fee_fold_proven
        // — the fold could not vouch for these inputs (or priced in_sum <
        // out_sum). So the template selector, which gates on fee_fold_proven,
        // EXCLUDES this entry: an unpriceable DSTX collects no fee and never
        // risks a lost block, while a fold-priceable DSTX (fee_known already
        // true above) keeps fee_fold_proven=true and rides at its true base
        // fee. This is the ONE in-tree hole the discipline closes.
        if (is_dstx && !entry.fee_known) {
            entry.fee = 0;
            entry.fee_known = true;
            // entry.fee_fold_proven deliberately stays false → template-excluded.
        }

        // LRU eviction if over size cap.
        int evicted = 0;
        while (m_total_bytes + entry.base_size > m_max_bytes
               && !m_time_index.empty()) {
            evict_one_locked(m_time_index.begin()->second);
            ++evicted;
        }

        m_pool[txid] = std::move(entry);
        auto& stored = m_pool[txid];
        m_time_index.emplace(stored.time_added, txid);
        m_total_bytes += stored.base_size;

        // Spent-outputs index for double-spend conflict detection.
        for (const auto& vin : stored.tx.vin) {
            m_spent_outputs[std::make_pair(
                vin.prevout.hash, vin.prevout.index)] = txid;
        }

        // Feerate-sorted index (step 2) — only if fee was known.
        // Unknown-fee txs sit out of the sorted view until
        // recompute_unknown_fees() resolves them after a UTXO update.
        // Keyed by MODIFIED fee (W5-B) — every insert/erase site keys
        // FeeKey{modified_fee(), size, txid}, one invariant; delta==0 for
        // every non-DSTX entry keeps this byte-identical to the base key.
        if (stored.fee_known) {
            m_feerate_index.insert(
                FeeKey{stored.modified_fee(), stored.base_size, txid});
        }

        // Periodic stats — every 100 entries + first 5 + every eviction.
        if (m_pool.size() % 100 == 0 || m_pool.size() <= 5 || evicted > 0) {
            LOG_INFO << "[MEMPOOL] add txid=" << txid.GetHex().substr(0, 16)
                     << " size=" << m_pool.size()
                     << " bytes=" << m_total_bytes << "/" << m_max_bytes
                     << " base=" << stored.base_size
                     << " fee=" << (stored.fee_known
                                    ? std::to_string(stored.fee) : "?")
                     << (evicted > 0 ? " evict=" + std::to_string(evicted) : "");
        }
        return true;
    }

    /// W5-B: bounded mapDeltas (dashd CTxMemPool::mapDeltas). FIFO-evicted
    /// beyond the cap (relay is untrusted input, same posture as the islock
    /// maps); confirmed txids are pruned by remove_for_block.
    void record_fee_delta_locked(const uint256& txid, uint64_t delta)
    {
        while (m_fee_delta_order.size() >= MAX_FEE_DELTAS
               && !m_fee_delta_order.empty()) {
            m_fee_deltas.erase(m_fee_delta_order.front());
            m_fee_delta_order.pop_front();
        }
        auto [it, inserted] = m_fee_deltas.insert_or_assign(txid, delta);
        (void)it;
        if (inserted) m_fee_delta_order.push_back(txid);
    }

public:
    void remove_tx(const uint256& txid)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        remove_tx_locked(txid);
    }

    /// Eviction on block confirm. Two phases:
    ///   1. Remove every confirmed tx by txid.
    ///   2. Remove mempool txs that spend the same outputs as confirmed
    ///      txs (double-spend conflicts).
    void remove_for_block(const dash::coin::BlockType& block)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        int removed = 0, conflicts = 0;

        // Phase 1
        for (const auto& mtx : block.m_txs) {
            uint256 txid = dash_txid(mtx);
            if (m_pool.count(txid)) ++removed;
            remove_tx_locked(txid);
        }

        // Phase 2
        for (const auto& mtx : block.m_txs) {
            for (const auto& vin : mtx.vin) {
                auto key = std::make_pair(vin.prevout.hash,
                                          vin.prevout.index);
                auto it = m_spent_outputs.find(key);
                if (it == m_spent_outputs.end()) continue;
                auto conflict_txid = it->second;
                if (m_pool.count(conflict_txid)) {
                    LOG_INFO << "[MEMPOOL] removing conflict tx "
                             << conflict_txid.GetHex().substr(0, 16)
                             << " (spends same input as confirmed tx "
                             << dash_txid(mtx).GetHex().substr(0, 16) << ")";
                    ++conflicts;
                }
                remove_tx_locked(conflict_txid);
            }
        }

        // G4: an outpoint spent by a CONFIRMED tx is resolved — whatever
        // islock claimed it is now enforced (or moot) by the chain itself, so
        // the tracking entry has done its job. Prune it. Same for the
        // locked-TXID index: a confirmed tx no longer needs its islock to
        // bypass the mining-safety hold (it left the pool). Stale txids left
        // behind in m_islock_txid_order are harmless — the FIFO eviction in
        // add_islock erases them from the (already-pruned) set as it pops.
        for (const auto& mtx : block.m_txs) {
            m_islock_txids.erase(dash_txid(mtx));
            for (const auto& vin : mtx.vin) {
                m_islock_outpoints.erase(
                    std::make_pair(vin.prevout.hash, vin.prevout.index));
            }
        }

        // W5-B: a confirmed tx no longer needs its prioritisation delta
        // (dashd also clears mapDeltas on block connect). Stale txids left
        // in m_fee_delta_order are harmless — the FIFO eviction in
        // record_fee_delta_locked erases them from the (already-pruned)
        // map as it pops.
        for (const auto& mtx : block.m_txs)
            m_fee_deltas.erase(dash_txid(mtx));

        if (removed > 0 || conflicts > 0) {
            LOG_INFO << "[MEMPOOL] block cleanup removed=" << removed
                     << " conflicts=" << conflicts
                     << " remaining=" << m_pool.size();
        }
    }

    // ── G4 (audit): InstantSend-lock conflict tracking ──────────────────
    /// Register an islock: `locked_txid` holds the exclusive InstantSend
    /// right to spend each outpoint in `inputs`. dashd rejects a block
    /// containing any tx that conflicts with a known islock
    /// (validation.cpp:2622 `conflict-tx-lock`), so the template builder
    /// must never pack such a tx. Two defences, mirroring dashd's own
    /// CInstantSendManager::RemoveConflictingLock posture:
    ///   1. eviction NOW: any pool entry already spending one of these
    ///      outpoints under a DIFFERENT txid is removed immediately;
    ///   2. selection guard: get_sorted_txs_with_fees() re-checks every
    ///      candidate vin against this map (belt for txs admitted between
    ///      islock arrival and eviction, and for re-added conflicts).
    ///
    /// RESIDUAL RACE (documented, not closable node-side): an islock that
    /// FORMS (or reaches us) after a template was emitted can invalidate a
    /// share won on that template — the islock-formation window. dashd's
    /// validator itself waives conflict-tx-lock once the block is
    /// chainlocked (validation.cpp:2612 has_chainlock override), so the
    /// exposure is one islock-vs-block race per conflicting spend, the same
    /// race dashd's own miner runs. There is no pre-emit oracle for "an
    /// islock will form for the OTHER spend"; tracking known locks is the
    /// full extent of what any miner can do.
    ///
    /// FEED: dashd-peer relay (the sole-ingestion-path invariant covers
    /// islocks too — they arrive from the same relay peers as the txs), via
    /// the coin-P2P isdlock leg: inv(MSG_ISDLOCK=31) → getdata → isdlock →
    /// Node::new_islock → CoinStateMaintainer::on_islock → here. The BLS sig
    /// is NOT yet verified (see the trust-posture note on message_isdlock,
    /// p2p_messages.hpp), which is why every consumer of this map sits in the
    /// fee-only-safe direction. An un-wired node (no coin-P2P) keeps the map
    /// empty and selection behaves exactly as before (empty map = no
    /// exclusions, hold self-disarmed by the liveness gate).
    void add_islock(const uint256& locked_txid,
                    const std::vector<std::pair<uint256, uint32_t>>& inputs)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        // Locked-TXID index — dashd's IsLocked(txid) equivalent for the IS
        // mining-safety hold: a tx WITH a known islock is safe to mine
        // immediately (TestPackageTransactions skips the 10-min hold for it).
        // Bounded FIFO like the outpoint map below (relay is untrusted input).
        while (m_islock_txid_order.size() >= MAX_ISLOCK_OUTPOINTS
               && !m_islock_txid_order.empty()) {
            m_islock_txids.erase(m_islock_txid_order.front());
            m_islock_txid_order.pop_front();
        }
        if (m_islock_txids.insert(locked_txid).second)
            m_islock_txid_order.push_back(locked_txid);
        // Feed-liveness tick for the hold's ISLOCK_FEED_FRESH_SECS gate.
        m_last_islock_seen = std::time(nullptr);
        for (const auto& in : inputs) {
            // Bound the tracking map (relay is untrusted input): evict the
            // oldest registration once over cap. 100k outpoints ≈ a few MB.
            while (m_islock_order.size() >= MAX_ISLOCK_OUTPOINTS
                   && !m_islock_order.empty()) {
                m_islock_outpoints.erase(m_islock_order.front());
                m_islock_order.pop_front();
            }
            auto [it, inserted] = m_islock_outpoints.insert_or_assign(
                in, locked_txid);
            if (inserted) m_islock_order.push_back(in);
            // Defence 1: evict a conflicting pool entry right away.
            auto sit = m_spent_outputs.find(in);
            if (sit != m_spent_outputs.end() && sit->second != locked_txid
                && m_pool.count(sit->second)) {
                LOG_INFO << "[MEMPOOL] evicting islock-conflicting tx "
                         << sit->second.GetHex().substr(0, 16)
                         << " (outpoint locked to "
                         << locked_txid.GetHex().substr(0, 16) << ")";
                remove_tx_locked(sit->second);
            }
        }
    }

    size_t islock_outpoint_count() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_islock_outpoints.size();
    }

    void evict_expired()
    {
        time_t cutoff = std::time(nullptr) - m_expiry_sec;
        std::lock_guard<std::mutex> lock(m_mutex);
        int evicted = 0;
        while (!m_time_index.empty()
               && m_time_index.begin()->first < cutoff) {
            evict_one_locked(m_time_index.begin()->second);
            ++evicted;
        }
        if (evicted > 0) {
            LOG_INFO << "[MEMPOOL] expiry sweep evicted " << evicted
                     << " entries (older than " << (m_expiry_sec / 3600)
                     << "h), remaining=" << m_pool.size();
        }
    }

    void clear()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pool.clear();
        m_time_index.clear();
        m_spent_outputs.clear();
        m_feerate_index.clear();
        m_islock_outpoints.clear();
        m_islock_order.clear();
        m_islock_txids.clear();
        m_islock_txid_order.clear();
        m_last_islock_seen = 0;
        m_fee_deltas.clear();
        m_fee_delta_order.clear();
        m_total_bytes = 0;
    }

    /// Re-attempt fee computation for entries marked fee_known=false.
    /// Call after a block-connect: the block's outputs are now in
    /// UTXO and may resolve previously-unknown inputs. Returns the
    /// number of newly-resolved entries.
    int recompute_unknown_fees(::core::coin::UTXOViewCache* utxo)
    {
        if (!utxo) return 0;
        std::lock_guard<std::mutex> lock(m_mutex);
        int resolved = 0, still_unknown = 0;
        uint64_t resolved_fees = 0;
        for (auto& [txid, entry] : m_pool) {
            if (entry.fee_known) continue;
            if (compute_fee_locked(entry, utxo)) {
                m_feerate_index.insert(
                    FeeKey{entry.modified_fee(), entry.base_size, txid});
                resolved_fees += entry.fee;
                ++resolved;
            } else {
                ++still_unknown;
            }
        }
        if (resolved > 0 || still_unknown > 0) {
            LOG_INFO << "[MEMPOOL] fee revalidation: resolved=" << resolved
                     << " still_unknown=" << still_unknown
                     << " resolved_fees=" << resolved_fees << " sat"
                     << " pool_size=" << m_pool.size();
        }
        return resolved;
    }

    // ── Queries ────────────────────────────────────────────────────

    bool contains(const uint256& txid) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pool.count(txid) > 0;
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_pool.size();
    }

    size_t byte_size() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_total_bytes;
    }

    uint64_t total_known_fees() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        uint64_t sum = 0;
        for (const auto& [_, e] : m_pool) {
            if (e.fee_known) sum += e.fee;
        }
        return sum;
    }

    std::optional<MempoolEntry> get_entry(const uint256& txid) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return std::nullopt;
        return it->second;
    }

    std::vector<uint256> all_txids() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<uint256> out;
        out.reserve(m_pool.size());
        for (auto& [txid, _] : m_pool) out.push_back(txid);
        return out;
    }

    /// #107 PHASE 2: the pending type-8 (TRANSACTION_ASSET_LOCK) txs currently
    /// resident in the pool. The credit-pool fold (asset_lock_fold.hpp) accrues
    /// these into the embedded CbTx creditPoolBalance so it matches dashd's,
    /// which builds its template from the SAME pending locks. Returns the raw
    /// txs (not entries) — the fold reads only tx.vout / tx.extra_payload, and
    /// validity is re-checked by check_asset_lock_tx, so no fee/UTXO context is
    /// needed here. Deterministic order (std::map is txid-ascending) so the
    /// builder and the emit-gate re-derivation over the same snapshot agree.
    std::vector<MutableTransaction> pending_asset_lock_txs() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<MutableTransaction> out;
        for (const auto& [_, e] : m_pool) {
            if (e.tx.type == 8 /*CAssetLockPayload::SPECIALTX_TYPE*/)
                out.push_back(e.tx);
        }
        return out;
    }

    /// Snapshot of all transactions keyed by txid. Used (eventually)
    /// by BIP 152 compact-block reconstruction + by block-template
    /// builder in Phase C-TEMPLATE.
    std::map<uint256, MutableTransaction> all_txs_map() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::map<uint256, MutableTransaction> out;
        for (const auto& [txid, e] : m_pool) out[txid] = e.tx;
        return out;
    }

    /// Phase C-TEMPLATE prerequisite — fee-aware tx selection.
    /// Returns transactions in TOPOLOGICALLY-VALID feerate order (see G1
    /// below) up to `max_bytes` of base-size budget. Transactions with
    /// unknown fees are EXCLUDED — they'd poison the coinbasevalue if we
    /// included them at fee=0 vs dashd's GBT (which always knows
    /// fees because it sees the full mempool with full UTXO).
    ///
    /// ── ConnectBlock reject-surface audit gaps closed here ─────────────
    /// (frstrtr/the docs/DASH_CONNECTBLOCK_REJECT_SURFACE_AUDIT.md §1)
    ///
    /// G1 `bad-txns-inputs-missingorspent` — TOPOLOGICAL selection. The
    ///   pre-fix selector walked the feerate index strictly descending, so a
    ///   CPFP child that out-feed its parent was packed BEFORE (or without)
    ///   the parent — a consensus-invalid block on a winning share. Now every
    ///   candidate is expanded to its ancestor PACKAGE (all unselected
    ///   in-mempool ancestors, parents-first); the whole package is admitted
    ///   atomically or the child is dropped. A vin is satisfied only by a
    ///   live UTXO coin or by a parent ALREADY IN THE SELECTED SET /
    ///   earlier in this package — never by bare mempool membership.
    ///
    /// G2 `bad-blk-sigops` — sigop accounting (sigops.hpp). Running
    ///   legacy+P2SH sigop count, seeded with dashd's 100-sigop coinbase
    ///   reserve; a package that would reach MaxBlockSigOps (40k) is
    ///   skipped, mirroring dashd miner TestPackage.
    ///
    /// G3 `bad-txns-premature-spend-of-coinbase` — coinbase maturity. When
    ///   the caller supplies `next_height`, a vin resolved from the UTXO
    ///   view must be mature at that height (Coin::is_mature, DASH_LIMITS
    ///   coinbase_maturity=100) or the package is dropped. `next_height==0`
    ///   (legacy callers) skips the check.
    ///
    /// G4 `conflict-tx-lock` — islock conflicts. A vin spending an outpoint
    ///   that a known islock assigns to a DIFFERENT txid drops the package
    ///   (see add_islock for the tracking + the documented residual race).
    ///
    /// Stale-input guard: re-checks each candidate's inputs against
    /// the live UTXO + selected-set parents before including. Catches
    /// the brief window between tip-change and full_block arrival
    /// where remove_for_block hasn't yet evicted now-double-spent
    /// txs.
    ///
    /// Returns (selected, total_fees_sat).
    struct SelectedTx {
        MutableTransaction tx;
        uint64_t           fee{0};
        uint32_t           base_size{0};
    };

    /// dashd policy DEFAULT_ANCESTOR_LIMIT: a candidate whose in-mempool
    /// ancestor package exceeds this is dropped (unminable by dashd's own
    /// miner too — its mempool never admits deeper chains).
    static constexpr size_t MAX_PACKAGE_TXS = 25;

    // exclude_special (C-3): when true, drop every Dash special tx (tx.type != 0
    // — ProRegTx/ProUpServTx/asset-lock/asset-unlock) from the selection. dashd
    // recomputes the coinbase CbTx roots (merkleRootMNList/Quorums) and the
    // DIP-0027 creditPoolBalance by APPLYING the block's own special txs, so
    // including one in the embedded template WITHOUT folding its effect into the
    // CbTx yields bad-cbtx and a rejected block. build_embedded_workdata passes
    // true (safe-minimal: the creditPool accrual then reduces to the platform-
    // reward term only). Default false preserves the mempool's general pricing +
    // selection capability (including the asset-unlock fee path) unchanged.
    // lock_time_cutoff: dashd m_lock_time_cutoff = MTP(pindexPrev)
    // (miner.cpp:223) for the per-member IsFinalTx re-check
    // (TestPackageTransactions, miner.cpp:377). 0 (legacy/test callers) skips
    // the check, preserving the sole-ingestion-path N-A argument unchanged;
    // the embedded GBT passes the tip MTP, which closes that argument's reorg
    // edge (height/MTP can REGRESS across a reorg while the tx stays pooled).
    std::pair<std::vector<SelectedTx>, uint64_t>
    get_sorted_txs_with_fees(uint32_t max_bytes, bool exclude_special = false,
                             uint32_t next_height = 0,
                             int64_t lock_time_cutoff = 0) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<SelectedTx> result;
        std::set<uint256> selected;   // G1: the parent-in-selected-set check
        uint64_t total_fees   = 0;
        uint32_t total_bytes  = 0;
        uint32_t total_sigops = DASH_COINBASE_SIGOPS_RESERVE;   // G2
        auto* utxo = m_utxo.load();

        // IS/CL mining-safety hold (dashd TestPackageTransactions): active
        // only when ARMED (spork2+spork3 via set_instantsend_mining_hold —
        // dashd's !RejectConflictingBlocks()/!IsInstantSendEnabled() skip)
        // AND the isdlock feed is demonstrably ALIVE (c2pool-side liveness
        // gate, see ISLOCK_FEED_FRESH_SECS — a dark feed must degrade to the
        // pre-hold behaviour, never hold every young tx for 10 minutes).
        const time_t now_ts = std::time(nullptr);
        const bool is_hold_active =
            m_is_hold_armed.load(std::memory_order_relaxed)
            && m_last_islock_seen != 0
            && now_ts - m_last_islock_seen <= ISLOCK_FEED_FRESH_SECS;

        // ── D1: static ancestor closure + LOCAL ancestor-score index ─────────
        // The persistent m_feerate_index (keyed by standalone feerate) is left
        // untouched; the ancestor-score index is rebuilt locally per template,
        // so add/remove maintenance can never regress (design-review invariant
        // (6)). Built over fee_known, non-over_limit entries only (R1) so the
        // no-package pure-feerate path stays byte-identical: a tx with no
        // in-pool ancestors has size_wa==base_size, modfee_wa==fee, count_wa==1,
        // so its anc_score_key == its old FeeKey bit-for-bit.
        const AncState anc = build_anc_state_locked();
        std::set<FeeKey> anc_index;
        for (const auto& [txid, e] : m_pool) {
            // EXCLUSION-DISCIPLINE: candidate ONLY if the fold proved the fee
            // (inputs present in our view, in_sum >= out_sum). fee_known alone
            // admits a DSTX force-priced at 0 on inputs the fold could not
            // vouch for — a template MUST NOT select on that. delta==0 for
            // every fee_fold_proven non-DSTX entry, so with no forced entries
            // in the pool this loop is byte-identical to the fee_known form.
            if (!e.fee_fold_proven) continue;
            if (anc.over_limit.count(txid)) continue;
            // W5-B: SCORE on the MODIFIED fee (dashd sorts on
            // GetModFeesWithAncestors); delta==0 ⇒ byte-identical to base.
            anc_index.insert(anc_score_key(e.modified_fee(), e.base_size,
                                           anc.modfee_wa.at(txid),
                                           anc.size_wa.at(txid), txid));
        }

        // ── D2: mapModifiedTx equivalent (dashd miner.cpp:480) ───────────────
        std::map<uint256, ModEntry> mod_by_txid;   // dashd's by-txiter unique index
        std::set<FeeKey>            mod_score;      // dashd's ancestor_score index
        std::set<uint256>           failed;        // dashd failedTx (:482)

        auto mod_key = [](const ModEntry& m) {
            return anc_score_key(m.self_fee, m.self_size,
                                 m.mod_modfee_wa, m.mod_size_wa, m.txid);
        };
        auto erase_mod = [&](const uint256& id) {
            auto it = mod_by_txid.find(id);
            if (it == mod_by_txid.end()) return;
            mod_score.erase(mod_key(it->second));   // recompute-and-erase BEFORE drop (R2)
            mod_by_txid.erase(it);
        };

        // dashd addPackageTxs main loop (miner.cpp:493-641). Two candidate
        // sources — the static ancestor-score index (anc_index / `mi`) and the
        // re-scored mapModifiedTx (mod_score) — scored on the SAME min-of-two
        // basis (FeeKey::operator<), so a CPFP descendant re-competes at its
        // lighter remaining-package feerate once an ancestor is included.
        // PORT 2 (dashd miner.cpp:491): consecutive cap-failure counter — the
        // give-up heuristic that stops scanning once the block is nearly full
        // and nothing is fitting. Reset to 0 on each admitted package (:625).
        int64_t nConsecutiveFailed = 0;

        auto mi = anc_index.begin();
        while (mi != anc_index.end() || !mod_by_txid.empty()) {
            // (a) SKIP GUARD (dashd :507-514): a mapTx entry already staged in
            //     mapModifiedTx / selected / failed carries stale ancestor
            //     state — advance past it.
            if (mi != anc_index.end()) {
                const uint256& mt = mi->txid;
                if (mod_by_txid.count(mt) || selected.count(mt)
                    || failed.count(mt)) {
                    ++mi;
                    continue;
                }
            }

            // (b) PICK BETTER OF TWO (dashd :517-540). FeeKey::operator< IS
            //     CompareTxMemPoolEntryByAncestorFee, and both indices already
            //     hold min-of-two keys, so this is dashd's wrap-mapTx-entry-in-
            //     CTxMemPoolModifiedEntry comparison exactly.
            bool    using_mod = false;
            uint256 txid;
            if (mi == anc_index.end()) {
                txid = mod_score.begin()->txid;          // mapTx exhausted
                using_mod = true;
            } else if (!mod_score.empty() && *mod_score.begin() < *mi) {
                txid = mod_score.begin()->txid;          // modified entry strictly better
                using_mod = true;
            } else {
                txid = mi->txid;
                ++mi;
            }

            // (d) A vanished / already-selected pick is discarded (dashd's
            //     inBlock assert / project<0> guards). Under the lock a pool
            //     miss cannot happen, but keep the belt.
            if (selected.count(txid) || m_pool.find(txid) == m_pool.end()) {
                if (using_mod) erase_mod(txid);
                continue;
            }

            // (d.5) PORT 1: blockMinFeeRate EARLY-RETURN (dashd
            //     miner.cpp:576-587). Take the winning candidate's
            //     WHOLE-ancestor-package feerate — dashd's packageFees =
            //     GetModFeesWithAncestors(), packageSize = GetSizeWithAncestors()
            //     (the modified totals when the pick came from mapModifiedTx) —
            //     and stop the WHOLE loop once it drops below the min feerate.
            //
            //     SOURCE-OF-FEE/SIZE (money-path, get this exactly right): use
            //     the SAME ancestor tables that KEYED the ancestor_score index —
            //       * mapTx pick : anc.modfee_wa/anc.size_wa (full static totals)
            //       * mod pick   : the ModEntry's mod_modfee_wa/mod_size_wa
            //         (static-minus-in-block-ancestors, dashd nModFeesWithAncestors)
            //     NOT collect_package_locked's pkg_fees/pkg_bytes remainder: that
            //     is only the UNSELECTED-ancestor subset, a higher feerate, and
            //     gating on it would drop higher-fee txs = revenue loss.
            //
            //     WHOLE-package feerate, NOT the min-of-two anc_score key: dashd
            //     SORTS by min(self, ancestor-package) but GATES on the whole
            //     ancestor-package feerate. We mirror that split exactly.
            //
            //     `return`, NEVER `continue`: both candidate indices are sorted
            //     by ancestor score descending and `txid` is the best of the two,
            //     so once this pick is sub-floor everything remaining is too —
            //     dashd's "Everything else we might consider has a lower fee
            //     rate". min-fee is POLICY, not consensus: the worst case of
            //     over-including (floor set too low) is a valid, fee-suboptimal
            //     block, never an invalid/orphaned one.
            uint64_t fee_wa;
            uint32_t size_wa;
            {
                if (using_mod) {
                    const ModEntry& me = mod_by_txid.at(txid);
                    fee_wa  = me.mod_modfee_wa;
                    size_wa = me.mod_size_wa;
                } else {
                    fee_wa  = anc.modfee_wa.at(txid);
                    size_wa = anc.size_wa.at(txid);
                }
                if (static_cast<int64_t>(fee_wa)
                        < block_min_fee_for_size(m_block_min_tx_fee, size_wa)) {
                    return {std::move(result), total_fees};
                }
            }

            // (d.6) dashd TestPackage BYTE leg, IN dashd's position (miner.cpp
            //     :592-604 calls TestPackage on packageSize — the ancestor-
            //     score totals, exactly our size_wa — BEFORE the package is
            //     even collected and BEFORE any member-level check), with
            //     dashd's boundary: nBlockSize + packageSize >= nBlockMaxSize
            //     fails AT the cap (miner.cpp:361, `>=`, not the old `>`).
            //     This is the counter-parity half of the audit's ordering
            //     divergence: a package failing BOTH the byte cap and a
            //     member-level check must bump nConsecutiveFailed (dashd bumps
            //     at TestPackage, before TestPackageTransactions ever runs).
            //     size_wa == the collected package's byte remainder whenever
            //     the package is admittable (any mismatch implies a
            //     fee-unknown member, which block (f) drops regardless).
            //     The sigop half of TestPackage stays in (g): dashd tests a
            //     CACHED sigops-with-ancestors we do not maintain (ours is
            //     computed during member validation); a package failing ONLY
            //     the sigop cap still bumps there, so the residual counter
            //     divergence is the dual-fail (sigop-cap AND member-check)
            //     package — vanishingly rare at DASH's 40k-sigop cap.
            if (static_cast<uint64_t>(total_bytes) + size_wa
                    >= static_cast<uint64_t>(max_bytes)) {
                if (using_mod) { erase_mod(txid); failed.insert(txid); }
                ++nConsecutiveFailed;
                if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES
                    && static_cast<int64_t>(total_bytes)
                           > static_cast<int64_t>(max_bytes) - 1000) {
                    break;
                }
                continue;
            }

            // (e) BUILD PACKAGE. collect_package_locked stays the AUTHORITATIVE
            //     topology / ancestor-limit gate (design-review consensus_risks:
            //     over_limit is only a candidate filter, never the sole drop —
            //     its >25 threshold is off-by-one vs collect's >=25). Returns
            //     the unselected-ancestor remainder, parents-first == dashd
            //     CalculateMemPoolAncestors + onlyUnconfirmed + insert(iter).
            //     false = over-deep chain: drop.
            std::vector<const MempoolEntry*> package;
            {
                std::set<uint256> seen;
                if (!collect_package_locked(txid, selected, seen, package, 0)) {
                    if (using_mod) { erase_mod(txid); failed.insert(txid); }
                    continue;
                }
            }

            // Package membership for intra-package vin resolution (a parent
            // earlier in `package` is as good as one already selected).
            std::set<uint256> in_package;
            for (const auto* e : package) in_package.insert(e->txid);

            // ── (f) Validate the WHOLE package; any failing member drops the
            // candidate (never a partial package — that is exactly the
            // childless-parent / parentless-child shape G1 forbids). This block
            // is LIFTED UNCHANGED from the pre-D2 selector. ──────────────────
            bool     ok         = true;
            uint32_t pkg_bytes  = 0;
            uint64_t pkg_fees   = 0;
            uint32_t pkg_sigops = 0;
            for (const auto* e : package) {
                // EXCLUSION-DISCIPLINE: a member is includable ONLY if its fee
                // was fold-proven (inputs present + in_sum >= out_sum). A
                // force-priced DSTX (fee_known, fee_fold_proven==false) drops
                // its WHOLE package here — never packed, never a lost block.
                if (!e->fee_fold_proven) { ok = false; break; }
                if (exclude_special && e->tx.type != 0) { ok = false; break; }

                // ── dashd TestPackageTransactions (node/miner.cpp:374-391),
                // member-level; either failure drops the WHOLE package and —
                // like dashd — does NOT bump nConsecutiveFailed. ────────────
                //
                // (1) IsFinalTx(tx, nHeight, MTP(prev)): the selection-time
                //     finality re-check. Steady-state this is a no-op (the
                //     sole-ingestion-path invariant: relay-admitted txs are
                //     final at admission and finality is monotonic), but
                //     across a REORG next-height/MTP can regress while the tx
                //     stays pooled — this closes that documented edge.
                //     lock_time_cutoff==0 (legacy/test callers) skips.
                if (lock_time_cutoff != 0 && next_height != 0
                    && !is_final_tx(e->tx, next_height, lock_time_cutoff)) {
                    ok = false;
                    break;
                }
                // (2) IS/CL mining-safety hold (WAIT_FOR_ISLOCK_TIMEOUT): a
                //     member WITH vins, with NO known islock, first seen less
                //     than 10 minutes ago is not yet safe to mine — the
                //     islock that eventually forms may lock a CONFLICTING
                //     spend, and a won block carrying this tx then dies
                //     conflict-tx-lock. vin-less members (type-9 asset
                //     unlocks) are exempt exactly as in dashd
                //     (!it->GetTx().vin.empty(), miner.cpp:386). An UNKNOWN
                //     first-seen in dashd yields age 0 => held; time_added is
                //     always set here, so the same posture holds by
                //     construction.
                if (is_hold_active && !e->tx.vin.empty()
                    && !m_islock_txids.count(e->txid)
                    && now_ts - e->time_added < WAIT_FOR_ISLOCK_TIMEOUT_SECS) {
                    ok = false;
                    break;
                }

                // G2: legacy sigops (every scriptSig + every scriptPubKey,
                // multisig = 20), exactly dashd GetLegacySigOpCount.
                uint32_t tx_sigops = 0;
                for (const auto& vout : e->tx.vout) {
                    tx_sigops += count_script_sigops(
                        vout.scriptPubKey.m_data, /*accurate=*/false);
                }

                for (const auto& vin : e->tx.vin) {
                    tx_sigops += count_script_sigops(
                        vin.scriptSig.m_data, /*accurate=*/false);

                    auto opkey = std::make_pair(vin.prevout.hash,
                                                vin.prevout.index);

                    // G4: islock conflict — the outpoint is locked to a
                    // different txid; packing this tx is conflict-tx-lock.
                    auto lk = m_islock_outpoints.find(opkey);
                    if (lk != m_islock_outpoints.end()
                        && lk->second != e->txid) {
                        ok = false;
                        break;
                    }

                    // Resolve the prevout: in-package/selected parent first
                    // (an in-mempool parent output can never be a coinbase,
                    // so no maturity question), then the live UTXO view.
                    auto parent = m_pool.find(vin.prevout.hash);
                    if (parent != m_pool.end()
                        && (in_package.count(vin.prevout.hash)
                            || selected.count(vin.prevout.hash))) {
                        if (vin.prevout.index
                                >= parent->second.tx.vout.size()) {
                            ok = false;
                            break;
                        }
                        const auto& pscript = parent->second.tx
                            .vout[vin.prevout.index].scriptPubKey.m_data;
                        if (is_p2sh_script(pscript)) {
                            tx_sigops += count_p2sh_sigops(
                                vin.scriptSig.m_data);
                        }
                        continue;
                    }
                    if (utxo) {
                        ::core::coin::Outpoint op(vin.prevout.hash,
                                                  vin.prevout.index);
                        ::core::coin::Coin coin;
                        if (!utxo->get_coin(op, coin)) {
                            // Stale input: neither selected-parent nor UTXO.
                            ok = false;
                            break;
                        }
                        // G3: coinbase maturity. dashd CheckTxInputs rejects
                        // a spend of a coinbase younger than 100 confs
                        // (bad-txns-premature-spend-of-coinbase); the Coin
                        // carries is_coinbase+height, so refuse here instead
                        // of shipping the reject. next_height==0 = legacy
                        // caller, check skipped.
                        if (next_height != 0
                            && !coin.is_mature(next_height, DASH_LIMITS)) {
                            ok = false;
                            break;
                        }
                        if (is_p2sh_script(coin.scriptPubKey.m_data)) {
                            tx_sigops += count_p2sh_sigops(
                                vin.scriptSig.m_data);
                        }
                        continue;
                    }
                    // No UTXO view attached (unit-test / cold-start): the
                    // pre-fix selector accepted the vin unchecked; keep that
                    // behaviour for non-mempool prevouts (topological order
                    // and sigop caps above still apply).
                }
                if (!ok) break;

                pkg_bytes  += e->base_size;
                pkg_fees   += e->fee;
                pkg_sigops += tx_sigops;
            }
            if (!ok) {
                if (using_mod) { erase_mod(txid); failed.insert(txid); }
                continue;
            }
            (void)pkg_fees;    // accounted below via per-entry e->fee
            (void)pkg_bytes;   // byte cap now tested pre-collect on size_wa,
                               // dashd TestPackage's position — see (d.6)

            // ── (g) Sigop cap, `>=` (reject AT the cap). The byte half of
            // dashd TestPackage moved to (d.6); this half stays here because
            // dashd tests a CACHED sigops-with-ancestors and ours is computed
            // during the member walk above. Each failure is one dashd
            // TestPackage() failure: only a mapModifiedTx pick is
            // erased+failed (dashd :590-596); a mapTx pick already had `mi`
            // advanced.
            //
            // PORT 2: nConsecutiveFailed cutoff (dashd miner.cpp:598-603). Each
            // cap-fail bumps the counter; once >1000 consecutive fails AND the
            // block is within 1000 bytes of the cap, dashd stops scanning
            // (`break`) — nothing more will fit. `continue` otherwise (a later,
            // smaller candidate may still fit — superset-safe). Near-no-op for
            // DASH's block sizes but ported for exact addPackageTxs parity. The
            // give-up test uses int64 arithmetic so `max_bytes - 1000` cannot
            // underflow when max_bytes < 1000 (dashd's nBlockMaxSize is clamped
            // >=1000, miner.cpp:212; ours is a caller-supplied param).
            if (total_sigops + pkg_sigops >= DASH_MAX_BLOCK_SIGOPS) {
                if (using_mod) { erase_mod(txid); failed.insert(txid); }
                ++nConsecutiveFailed;
                if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES
                    && static_cast<int64_t>(total_bytes)
                           > static_cast<int64_t>(max_bytes) - 1000) {
                    break;
                }
                continue;
            }

            // ── (h) Admit. D3 SortForBlock (ancestor-count asc, txid asc)
            // re-orders the SAME members before emit → within-package
            // hashMerkleRoot parity. This vector order flows unchanged into
            // embedded_gbt.hpp's vtx. ────────────────────────────────────────
            //
            // PORT 2: this package makes it in — reset the consecutive-failure
            // counter ONCE per admitted PACKAGE (dashd miner.cpp:625, before
            // SortForBlock), not per-tx.
            nConsecutiveFailed = 0;
            sort_package_for_block(package, anc);
            for (const auto* e : package) {
                selected.insert(e->txid);
                total_bytes += e->base_size;
                total_fees  += e->fee;
                result.push_back({e->tx, e->fee, e->base_size});
                erase_mod(e->txid);            // dashd :634
            }
            total_sigops += pkg_sigops;

            // ── (i) UpdatePackagesForAdded (dashd :415-440 / :640). For each
            // just-admitted tx, re-score its TRANSITIVE descendants (RC1) on
            // their now-lighter remaining package via mapModifiedTx. Seeded
            // ONCE from static totals, then each in-block ancestor subtracts
            // its own fee/size exactly once (RC2) → static-minus-in-block-
            // ancestors, matching dashd's repeated update_for_parent_inclusion.
            for (const auto* a : package) {
                auto dit = anc.descendants.find(a->txid);
                if (dit == anc.descendants.end()) continue;
                for (const uint256& desc : dit->second) {
                    if (selected.count(desc)) continue;
                    if (anc.over_limit.count(desc)) continue;   // hopeless: collect drops it (RC3)
                    auto it = mod_by_txid.find(desc);
                    if (it == mod_by_txid.end()) {
                        // Seed once from the static ancestor totals. `a` is a
                        // transitive ancestor of desc (desc ∈ descendants[a]),
                        // so the static totals include a's fee/size — the
                        // subtraction below removes it exactly once.
                        const auto& de = m_pool.at(desc);
                        ModEntry m;
                        m.txid          = desc;
                        m.self_fee      = de.modified_fee();   // scoring basis (W5-B)
                        m.self_size     = de.base_size;
                        m.mod_modfee_wa = anc.modfee_wa.at(desc);
                        m.mod_size_wa   = anc.size_wa.at(desc);
                        it = mod_by_txid.emplace(desc, m).first;
                        // key inserted once, after the subtraction below
                    } else {
                        mod_score.erase(mod_key(it->second));   // stale key out first (R2)
                    }
                    it->second.mod_modfee_wa -= a->modified_fee();  // update_for_parent_inclusion
                    it->second.mod_size_wa   -= a->base_size;       // (miner.h:140-141; modified basis, W5-B)
                    mod_score.insert(mod_key(it->second));
                }
            }
        }
        return {std::move(result), total_fees};
    }

private:
    // G4: bound on tracked islock outpoints (relay-fed, so untrusted input;
    // FIFO eviction beyond this — see add_islock).
    static constexpr size_t MAX_ISLOCK_OUTPOINTS = 100'000;

    mutable std::mutex                                 m_mutex;
    std::map<uint256, MempoolEntry>                    m_pool;
    std::multimap<time_t, uint256>                     m_time_index;
    std::map<std::pair<uint256, uint32_t>, uint256>    m_spent_outputs;
    // Step 2: feerate-sorted index. greater<double> means begin() =
    // highest feerate, so iteration is best-first.
    std::set<FeeKey>                                   m_feerate_index;
    // G4: outpoint → txid holding the InstantSend lock on it, plus FIFO
    // insertion order for bounded eviction.
    std::map<std::pair<uint256, uint32_t>, uint256>    m_islock_outpoints;
    std::deque<std::pair<uint256, uint32_t>>           m_islock_order;
    // IS mining-safety hold: txids holding a known islock (dashd
    // IsLocked(txid)) — such a tx bypasses the 10-minute hold. Same bounded-
    // FIFO posture as the outpoint map (relay is untrusted input).
    std::set<uint256>                                  m_islock_txids;
    std::deque<uint256>                                m_islock_txid_order;
    // W5-B: dashd mapDeltas — txid → prioritisation delta (duffs), recorded
    // pre-admission and applied on ANY later admission; bounded FIFO (relay
    // is untrusted input), pruned on block confirm.
    static constexpr size_t MAX_FEE_DELTAS = 10'000;
    std::map<uint256, uint64_t>                        m_fee_deltas;
    std::deque<uint256>                                m_fee_delta_order;
    // Feed-liveness tick (last add_islock wall time; 0 = never) — the hold's
    // ISLOCK_FEED_FRESH_SECS self-disarm reads this under m_mutex.
    time_t                                             m_last_islock_seen{0};
    // Hold arm-bit (spork2+spork3, pushed from the io thread via
    // set_instantsend_mining_hold; read on the serve executor). DEFAULT OFF.
    std::atomic<bool>                                  m_is_hold_armed{false};
    size_t                                             m_total_bytes{0};
    size_t                                             m_max_bytes;
    time_t                                             m_expiry_sec;
    // PORT 1: blockmintxfee-equivalent floor (duff/kB) for the blockMinFeeRate
    // early-return in get_sorted_txs_with_fees. Default = canonical dashd
    // DEFAULT_BLOCK_MIN_TX_FEE. Read under m_mutex (selector holds it); written
    // via set_block_min_tx_fee (also under the lock).
    int64_t                                            m_block_min_tx_fee{DEFAULT_BLOCK_MIN_TX_FEE};
    std::atomic<::core::coin::UTXOViewCache*>          m_utxo{nullptr};
    // Second-source coin lookup for the PINNED-TX gate only (see
    // set_external_coin_lookup). Set once at wiring time, before any template
    // build, and never mutated afterwards — the gate reads it on the template
    // path where m_utxo is already read lock-free.
    std::function<bool(const ::core::coin::Outpoint&, ::core::coin::Coin&)>
                                                      m_external_coin_lookup;

    /// G1: gather `txid` plus every UNSELECTED in-mempool ancestor into
    /// `out`, parents strictly before children (post-order DFS). `seen`
    /// de-duplicates diamond dependencies within one package. Returns false
    /// when the package exceeds MAX_PACKAGE_TXS (drop the candidate; such a
    /// chain is deeper than dashd's own mempool would admit). Caller must
    /// hold m_mutex. Recursion depth is bounded by MAX_PACKAGE_TXS.
    bool collect_package_locked(const uint256& txid,
                                const std::set<uint256>& already_selected,
                                std::set<uint256>& seen,
                                std::vector<const MempoolEntry*>& out,
                                size_t depth) const
    {
        if (depth > MAX_PACKAGE_TXS || out.size() >= MAX_PACKAGE_TXS)
            return false;
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return false;
        if (!seen.insert(txid).second) return true;  // already scheduled
        for (const auto& vin : it->second.tx.vin) {
            if (already_selected.count(vin.prevout.hash)) continue;
            if (m_pool.find(vin.prevout.hash) == m_pool.end()) continue;
            if (!collect_package_locked(vin.prevout.hash, already_selected,
                                        seen, out, depth + 1)) {
                return false;
            }
        }
        if (out.size() >= MAX_PACKAGE_TXS) return false;
        out.push_back(&it->second);
        return true;
    }

    // ── D1/D2/D3: dashd BlockAssembler::addPackageTxs parity ─────────────────
    //
    // The pre-D1 selector walked m_feerate_index by STANDALONE per-tx feerate
    // and only pulled a candidate's unselected-ancestor package on demand, so
    // CPFP re-scoring worked only accidentally and the within-package emit order
    // was a post-order DFS. dashd's BlockAssembler instead:
    //   D1 sorts by ancestor_score = min(self-feerate, whole-ancestor-package
    //      feerate)  — CompareTxMemPoolEntryByAncestorFee / GetModFeeAndSize
    //      (src/txmempool.h:274-312);
    //   D2 maintains mapModifiedTx, re-scoring a tx's descendants on their
    //      now-lighter remaining package as ancestors are included
    //      (src/node/miner.cpp:480,493-640, UpdatePackagesForAdded :415-440);
    //   D3 emits each accepted package ordered by GetCountWithAncestors() asc,
    //      txid asc  — SortForBlock (src/node/miner.cpp:442-451,
    //      src/node/miner.h:104-112).
    // The three together make the embedded template select the same tx SET in
    // the same ORDER as dashd for the same tip+mempool → identical
    // hashMerkleRoot. Reward-safety is unaffected (the #1218 gbt-xcheck guard
    // fails closed to dashd on ANY divergence); this only lowers swap frequency.

    /// Static ancestor/descendant closure over the fee_known pool, built ONCE
    /// per template. Pure mempool topology (independent of `selected`), so the
    /// count/size/modfee totals are the FULL static GetXxxWithAncestors values —
    /// only the mapModifiedTx entries (ModEntry) carry reduced values.
    /// Built over fee_known entries ONLY (design-review R1): a fee_known child
    /// of a fee_unknown parent is unadmittable anyway (collect_package_locked
    /// still pulls the unpriced parent and the validation loop drops the
    /// package), and excluding fee_unknown parents keeps the no-package
    /// pure-feerate path byte-identical to m_feerate_index.
    struct AncState {
        std::map<uint256, uint32_t>              count_wa;    // incl self
        std::map<uint256, uint32_t>              size_wa;     // sum base_size incl self
        std::map<uint256, uint64_t>              modfee_wa;   // sum fee incl self
        std::map<uint256, std::set<uint256>>     descendants; // TRANSITIVE, excl self
        std::set<uint256>                        over_limit;  // closure > MAX_PACKAGE_TXS
    };

    /// mapModifiedTx entry (dashd CTxMemPoolModifiedEntry, miner.h:60-79). Its
    /// ancestor-score key is the min-of-two of (self_fee,self_size) vs the
    /// reduced (mod_modfee_wa,mod_size_wa) — the CPFP re-score.
    struct ModEntry {
        uint256  txid;
        uint64_t self_fee{0};
        uint32_t self_size{0};
        uint64_t mod_modfee_wa{0};
        uint32_t mod_size_wa{0};
    };

    /// dashd CompareTxMemPoolEntryByAncestorFee::GetModFeeAndSize min-of-two
    /// (txmempool.h:297-311): return the (fee,size) of the SMALLER feerate of
    /// {self, whole-ancestor-package}, using the same division-free
    /// cross-multiply as FeeKey::operator< (no pre-divided double).
    /// dashd CFeeRate::GetFee (src/policy/feerate.cpp:23-37): the minimum fee,
    /// in duffs, that `num_bytes` must pay at `sat_per_k` duff/kB. Reproduces
    /// dashd EXACTLY: ceil of the double quotient (nSatoshisPerK*nSize/1000.0),
    /// plus the round-up-to-1 floor when a nonzero size would otherwise truncate
    /// to a zero fee. The int64 product matches dashd's `nSatoshisPerK * nSize`
    /// (evaluated before the /1000.0 promotes to double); block sizes keep it
    /// far from int64 overflow.
    static int64_t block_min_fee_for_size(int64_t sat_per_k, uint64_t num_bytes)
    {
        const int64_t n_size = static_cast<int64_t>(num_bytes);
        int64_t n_fee = static_cast<int64_t>(
            std::ceil(static_cast<double>(sat_per_k * n_size) / 1000.0));
        if (n_fee == 0 && n_size != 0) {
            if (sat_per_k > 0) n_fee = 1;
            else if (sat_per_k < 0) n_fee = -1;
        }
        return n_fee;
    }

    /// dashd IsFinalTx (src/consensus/tx_verify.cpp), exact port over
    /// MutableTransaction: locktime==0 => final; locktime below its
    /// height/time threshold cutoff => final; otherwise final only if EVERY
    /// vin carries SEQUENCE_FINAL (the nLockTime-disable sentinel). Called at
    /// selection with (next_height, MTP(prev)) — dashd's exact
    /// TestPackageTransactions arguments (nHeight, m_lock_time_cutoff).
    static bool is_final_tx(const MutableTransaction& tx, uint32_t block_height,
                            int64_t block_time)
    {
        constexpr int64_t  LOCKTIME_THRESHOLD = 500000000;   // consensus.h
        constexpr uint32_t SEQUENCE_FINAL     = 0xffffffff;  // CTxIn
        if (tx.locktime == 0) return true;
        const int64_t lt = static_cast<int64_t>(tx.locktime);
        if (lt < (lt < LOCKTIME_THRESHOLD
                      ? static_cast<int64_t>(block_height) : block_time)) {
            return true;
        }
        for (const auto& vin : tx.vin) {
            if (vin.sequence != SEQUENCE_FINAL) return false;
        }
        return true;
    }

    static FeeKey anc_score_key(uint64_t self_fee, uint32_t self_size,
                                uint64_t modfee_wa, uint32_t size_wa,
                                const uint256& txid)
    {
        // f1 > f2  ⇔  self feerate > ancestor-package feerate  ⇒ min = ancestor.
        const double f1 = static_cast<double>(self_fee) * size_wa;
        const double f2 = static_cast<double>(modfee_wa) * self_size;
        if (f1 > f2) return FeeKey{modfee_wa, size_wa, txid};   // ancestor pair
        return FeeKey{self_fee, self_size, txid};               // self pair (also on tie)
    }

    /// Build the static ancestor/descendant closure. Memoized transitive
    /// ancestor sets over in-pool fee_known parents; descendants is the reverse
    /// (transitive, design-review RC1). Caller must hold m_mutex.
    AncState build_anc_state_locked() const
    {
        AncState st;
        std::map<uint256, std::set<uint256>> anc;   // transitive ancestors, excl self

        // Memoized DFS. std::map nodes are reference-stable across inserts, so
        // returning a reference into `anc` during recursion is safe. The
        // mempool is a DAG (a tx cannot spend a descendant's output), so no
        // cycle guard is needed.
        std::function<const std::set<uint256>&(const uint256&)> closure =
            [&](const uint256& txid) -> const std::set<uint256>& {
                auto memo = anc.find(txid);
                if (memo != anc.end()) return memo->second;
                std::set<uint256> acc;
                auto it = m_pool.find(txid);
                if (it != m_pool.end() && it->second.fee_fold_proven) {
                    for (const auto& vin : it->second.tx.vin) {
                        const uint256& p = vin.prevout.hash;
                        auto pit = m_pool.find(p);
                        if (pit == m_pool.end() || !pit->second.fee_fold_proven)
                            continue;   // edge leaves the fold-proven pool
                        acc.insert(p);
                        const auto& panc = closure(p);
                        acc.insert(panc.begin(), panc.end());
                    }
                }
                return anc.emplace(txid, std::move(acc)).first->second;
            };

        for (const auto& [txid, e] : m_pool) {
            // EXCLUSION-DISCIPLINE: ancestor aggregates + over_limit are built
            // over fold-proven entries only, so a force-priced DSTX is invisible
            // to scoring/ordering exactly as it is to selection. With no forced
            // entries this is byte-identical to the fee_known form.
            if (!e.fee_fold_proven) continue;
            const auto& a = closure(txid);
            uint32_t cnt = static_cast<uint32_t>(a.size()) + 1;
            uint64_t szf = e.base_size;
            // W5-B: modfee_wa IS dashd's nModFeesWithAncestors — MODIFIED
            // fees (base + delta). Base-fee accounting (total_fees /
            // SelectedTx.fee) never reads these aggregates.
            uint64_t mff = e.modified_fee();
            for (const auto& at : a) {
                const auto& ae = m_pool.at(at);
                szf += ae.base_size;
                mff += ae.modified_fee();
            }
            st.count_wa[txid]  = cnt;
            st.size_wa[txid]   = static_cast<uint32_t>(szf);
            st.modfee_wa[txid] = mff;
            if (cnt > MAX_PACKAGE_TXS) st.over_limit.insert(txid);
            for (const auto& at : a) st.descendants[at].insert(txid);  // reverse, transitive
        }
        return st;
    }

    /// dashd SortForBlock (miner.cpp:442-451) + CompareTxIterByAncestorCount
    /// (miner.h:104-112): order an accepted package by full static
    /// GetCountWithAncestors ascending, then txid ascending. For A depending on
    /// B, count(A) > count(B) (A's ancestor set ⊇ B's ∪ {B}) regardless of
    /// in-block subtraction, so this is always a valid topological emit order.
    void sort_package_for_block(std::vector<const MempoolEntry*>& pkg,
                                const AncState& anc) const
    {
        std::sort(pkg.begin(), pkg.end(),
                  [&](const MempoolEntry* a, const MempoolEntry* b) {
                      auto ia = anc.count_wa.find(a->txid);
                      auto ib = anc.count_wa.find(b->txid);
                      uint32_t ca = ia != anc.count_wa.end() ? ia->second : 1;
                      uint32_t cb = ib != anc.count_wa.end() ? ib->second : 1;
                      if (ca != cb) return ca < cb;
                      return txid_oracle_less(a->txid, b->txid);
                  });
    }

    void evict_one_locked(const uint256& txid)
    {
        remove_tx_locked(txid);
    }

    void remove_tx_locked(const uint256& txid)
    {
        auto it = m_pool.find(txid);
        if (it == m_pool.end()) return;

        // Drop from time index.
        auto trng = m_time_index.equal_range(it->second.time_added);
        for (auto rit = trng.first; rit != trng.second; ++rit) {
            if (rit->second == txid) {
                m_time_index.erase(rit);
                break;
            }
        }

        // Drop from feerate index (only present if fee was known). Same
        // modified-fee key every insert site used (single invariant, W5-B).
        if (it->second.fee_known) {
            m_feerate_index.erase(FeeKey{it->second.modified_fee(),
                                         it->second.base_size, txid});
        }

        // Drop from spent-outputs index.
        for (const auto& vin : it->second.tx.vin) {
            auto key = std::make_pair(vin.prevout.hash, vin.prevout.index);
            auto sit = m_spent_outputs.find(key);
            if (sit != m_spent_outputs.end() && sit->second == txid) {
                m_spent_outputs.erase(sit);
            }
        }

        m_total_bytes -= it->second.base_size;
        m_pool.erase(it);
    }

    /// Compute fee = sum(input_values) - sum(output_values).
    /// Inputs come from UTXO set (confirmed); falls back to parent
    /// mempool tx outputs (CPFP / chain-of-unconfirmed). Sets
    /// entry.fee_known on success.
    bool compute_fee_locked(MempoolEntry& entry,
                            ::core::coin::UTXOViewCache* utxo)
    {
        // DIP-0027 asset-UNLOCK special case (type 9, E2b/#738). An
        // asset-unlock tx mints UTXO from the credit pool and carries NO
        // regular inputs, so the generic in-minus-out path below yields
        // in_sum(0) < out_sum -> permanently fee_known=false, and the
        // conservative selection guard would exclude it forever. Its miner
        // fee is EXPLICIT in the payload (CAssetUnlockPayload.fee — the
        // amount deducted from the unlock total for the miner's coinbase;
        // vendor/assetlock.hpp), exactly what dashd's GBT reports for it.
        // Pricing from the payload needs no UTXO view, so this branch sits
        // ahead of the null-utxo bail-out. TARGETED: only an input-free
        // type-9 body with a well-formed payload qualifies; anything else
        // (including a malformed type-9) falls through to / stays on the
        // conservative unknown-fee path. The general unknown-fee exclusion
        // for every other tx class is untouched.
        if (entry.tx.type == vendor::CAssetUnlockPayload::SPECIALTX_TYPE
            && entry.tx.vin.empty()) {
            vendor::CAssetUnlockPayload payload;
            if (vendor::parse_assetunlock_payload(entry.tx.extra_payload,
                                                  payload)) {
                entry.fee = payload.fee;
                entry.fee_known = true;
                // Explicit, exact miner fee from the DIP-0027 payload (no UTXO
                // fold needed, never overstated) → fold-proven for selection.
                entry.fee_fold_proven = true;
                return true;
            }
            entry.fee_known = false;
            entry.fee_fold_proven = false;
            entry.fee = 0;
            return false;
        }

        if (!utxo) {
            entry.fee_known = false;
            entry.fee_fold_proven = false;
            return false;
        }
        uint64_t in_sum = 0, out_sum = 0;
        for (const auto& vin : entry.tx.vin) {
            ::core::coin::Outpoint op(vin.prevout.hash, vin.prevout.index);
            ::core::coin::Coin coin;
            if (utxo->get_coin(op, coin)) {
                in_sum += static_cast<uint64_t>(coin.value);
                continue;
            }
            // Try parent mempool tx (CPFP).
            auto pit = m_pool.find(vin.prevout.hash);
            if (pit != m_pool.end()
                && vin.prevout.index < pit->second.tx.vout.size()) {
                in_sum += static_cast<uint64_t>(
                    pit->second.tx.vout[vin.prevout.index].value);
                continue;
            }
            entry.fee_known = false;
            entry.fee_fold_proven = false;
            entry.fee = 0;
            return false;
        }
        for (const auto& vout : entry.tx.vout) {
            out_sum += static_cast<uint64_t>(vout.value);
        }
        if (in_sum < out_sum) {
            // Negative fee — invalid tx (spends more than its inputs hold);
            // mark unknown so we don't poison block templates with garbage
            // values. fee_fold_proven stays false → template-excluded even if
            // a DSTX force later flips fee_known (the money-creating hole).
            entry.fee_known = false;
            entry.fee_fold_proven = false;
            entry.fee = 0;
            return false;
        }
        entry.fee = in_sum - out_sum;
        entry.fee_known = true;
        // Every vin priced from our own UTXO view / in-pool parent and
        // in_sum >= out_sum → the fee is fold-exact and inputs are proven
        // present. This is the ONE bit the template selector trusts.
        entry.fee_fold_proven = true;
        return true;
    }
};

} // namespace coin
} // namespace dash