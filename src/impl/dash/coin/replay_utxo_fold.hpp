// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// DASH FULL-HISTORY REPLAY — W3: the standalone UTXO fold (Tier-B state).
//
// Design sources: docs/DASH_FULL_HISTORY_REPLAY_MODE.md (frstrtr/the) §4/§6
// and DASH_REPLAY_SIZING_REPORT.md §Tier-B. This work package builds the
// chainstate half of Tier-B: a strict left fold of every transaction in every
// block into a LevelDB-backed UTXO set (~244 MiB at tip: 4.52M txouts), with
// an undo window over the last 100 blocks and a resumable cursor — the state
// that later lets the template builder price mempool txs with full input
// existence/maturity knowledge instead of the "never guess fees" exclusion.
//
// ── Consumer shape (the W1/W2 seam, mirrored — deliberately NOT included) ──
//
// The replay work packages hand verified block bodies to a consumer as
//
//     bool on_replay_block(uint32_t height, const uint256& hash,
//                          const BlockType& block)
//
// strictly in ascending height order with no gaps; returning false REFUSES
// the block and the transport lane fails closed with a named cause. This
// module exposes exactly that shape (plus a std::function form via
// consumer()) WITHOUT including the W1/W2 headers — the sibling PRs are
// unmerged, and a shared type would couple their landing order. Wiring the
// fold behind the transport's consumer interface is the integration slice
// (W5), one adapter line.
//
// ── Fold rules (dashd ConnectBlock/UpdateCoins equivalence) ────────────────
//
//   * tx[0] is the coinbase: no inputs spent; outputs enter the set with
//     fCoinBase=1 (coinbase-maturity metadata — Coin{height, coinbase} is
//     exactly what dashd's maturity check consumes at spend time).
//   * every other tx: every vin's prevout MUST be an unspent coin — spend it
//     (recording it in the block's undo); a missing prevout is fail-closed
//     REFUSAL, never a skip (a silently incomplete set would only be caught
//     1.49M blocks later by the gate KAT). Special txs need no cases here:
//     ProTx types spend/create like any tx, asset-unlock (type 9) has an
//     empty vin and plain vouts, cbTx (type 5) is the coinbase.
//   * outputs: every non-unspendable script enters the set — INCLUDING
//     zero-value outputs (dashd keeps spendable 0-duff txouts; this is a
//     deliberate divergence from the mempool lane's UTXOViewCache, which
//     drops them as a fee-engine shortcut). OP_RETURN and >MAX_SCRIPT_SIZE
//     scripts are excluded, matching CScript::IsUnspendable().
//   * duplicate-outpoint add (BIP30 shape) is refused — dashd enforces BIP30
//     everywhere post-DIP0001 and Dash history contains no exempt collisions.
//   * genesis (h=0) folds NOTHING: dashd's ConnectBlock short-circuits the
//     genesis block, so its coinbase is never in the chainstate; delivering
//     it here just pins the cursor.
//   * NO historical script verification and no signature checks anywhere —
//     ChainLock-as-assumevalid (spec §4.2): bodies arrive PoW-pinned and
//     merkle-bound from the transport; scripts on the accepted chain are
//     acceptance predicates the network already evaluated. This module never
//     admits a mempool tx and never serves a template — it derives state.
//
// The fold must start at height 1 on an empty store (unlike the W1 MN-list
// fold, which starts at DIP3 h=1028160): coins created before DIP3 are still
// spendable, so a DIP3-anchored UTXO fold could never match dashd. Honesty
// note vs the sizing report: the Tier-B "same ~29 GB download" therefore
// grows by the pre-DIP3 bodies (early blocks are tiny; the header walk to
// genesis is already W2's join-check path).
//
// ── THE GATE (full-chain KAT — run against live dashd, not in CI) ──────────
//
// hash_serialized_2() below serialize-hashes the whole set EXACTLY as dashd
// v23.1.x `gettxoutsetinfo hash_serialized_2` does (kernel/coinstats.cpp,
// transcription notes at apply_hash_group). The graduation gate for this
// module is byte-equality against the live-mainnet anchor:
//
//     hash_serialized_2 =
//       3d14913768a9d492bfa7a42fe9b111cff625b80e35bb4133e1d60cf3991c2319
//     @ h=2,516,758 (4,516,734+ ~= 4.52M txouts, ~244 MiB)
//
// Operator command once a full replay (genesis → 2,516,758) has been folded:
//
//     c2pool-dash --replay-utxo-db <path> --replay-utxo-hash \
//         --replay-utxo-expect 3d14913768a9d492bfa7a42fe9b111cff625b80e35bb4133e1d60cf3991c2319
//
// (exit 0 = GATE PASS, exit 1 = named mismatch, fail-closed). The unit KATs
// in test/test_dash_replay_utxo_fold.cpp prove the fold rules and the hash
// construction on small synthetic chains; only the live anchor proves the
// whole-history fold. Until that gate is green the fold's state must not
// feed any serving decision (and nothing constructs this class outside the
// --replay-utxo-* utility surface — the serve path is byte-identical).
//
// ── Persistence layout (format version 2, fail-loud on mismatch) ───────────
//
//   'V'            → uint32 LE format version (2)
//   'B'            → cursor: best_hash(32) + best_height(4 LE) + undo_floor(4 LE)
//   'C' + txid(32) + vout(4 LE) → serialized Coin (core::coin::serialize_coin)
//   'U' + height(4 BE)          → serialized BlockUndo (last `undo_window` blocks)
//   'H' + height(4 BE)          → block hash(32) (cursor restore on disconnect;
//                                  same retention window as 'U')
//   'G'            → GRADUATION record (W5-A): written ONLY by a PASSING
//                    try_graduate() at the anchor cursor. Absence IS the
//                    ungraduated state — a store whose cursor is past the
//                    anchor with no 'G' record can NEVER graduate (re-fold,
//                    or gate against a fresh operator-supplied anchor).
//                    Layout: format u32 LE | anchor_height u32 LE |
//                    anchor_block_hash(32) | expected_hash(32) |
//                    measured_hash(32) | coins u64 LE | tx_groups u64 LE |
//                    unix_time i64 LE.
//
// Version history: v1 = the pre-graduation layout (no 'G' key class; no
// production store was ever built at v1 — the fold had no feeder until W5-A).
// v2 adds 'G'. Any layout change bumps the version so an old binary fails
// LOUD instead of silently misreading state.
//
// All per-block mutations accumulate in a write-back overlay and are
// committed in ONE WriteBatch per flush (default every 2000 blocks) together
// with the cursor — a crash resumes from the last flushed cursor with the
// set exactly consistent at that height (resume_height()); re-delivered
// already-applied heights are acknowledged idempotently.
//
// Feature-flagged (--replay-utxo-db / --replay-utxo-hash /
// --replay-utxo-expect): absent, nothing here is constructed. DASH-lane
// only; header-only to match the sibling leaves; no serve-path changes.

#include "block.hpp"
#include "transaction.hpp"
#include "utxo_adapter.hpp"   // DASH_LIMITS + dash_txid + core::coin aliases

#include <core/coin/utxo.hpp>
#include <core/hash.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace replay {

// Undo retention for the replay fold: last 100 blocks (~2 MB), per the
// Tier-B sizing (DASH_REPLAY_SIZING_REPORT.md §1 "undo last ~100 blocks").
// Deliberately narrower than the live mempool lane's DASH_MIN_BLOCKS_TO_KEEP
// (288): a replay deeper than 100 blocks behind a reorg re-folds from the
// nearest cursor instead of carrying undo forever.
static constexpr uint32_t REPLAY_UTXO_UNDO_WINDOW = 100;

// On-disk format version ('V' key). Bump on ANY layout change so an old
// binary fails LOUD instead of silently misreading state (standing versioned-
// format trap, DASH_FULL_HISTORY_REPLAY_MODE.md §4.5). v2: 'G' graduation
// record (W5-A) — see the layout table above.
static constexpr uint32_t REPLAY_UTXO_FORMAT_VERSION = 2;

// ── THE GRADUATION ANCHOR (W5-A reward-safety gate) ─────────────────────────
// The live-mainnet anchor the fold must prove byte-equality against before
// its answers may EVER price a mempool fee (see the module header's GATE
// section): dashd `gettxoutsetinfo hash_serialized_2` at h=2,516,758.
// KAT-injectable via ReplayUtxoFoldOptions so synthetic chains can gate at a
// tiny anchor; production wiring (--embedded-utxo-fold-fees) keeps these
// defaults and ADDITIONALLY requires the operator to restate the expected
// hash on the command line (a stale/foreign DB must not graduate on its own
// say-so).
static constexpr uint32_t REPLAY_UTXO_GATE_ANCHOR_HEIGHT = 2'516'758;
inline constexpr const char* REPLAY_UTXO_GATE_ANCHOR_EXPECT =
    "3d14913768a9d492bfa7a42fe9b111cff625b80e35bb4133e1d60cf3991c2319";

// ── dashd serialize.h primitives (exact transcriptions) ────────────────────

/// Bitcoin/dashd `WriteVarInt` (serialize.h): MSB-base-128 with the -1 offset
/// per continuation group. NOT the LEB128-style varint used by
/// core::coin::write_varint — the two encodings agree only below 0x80, and
/// hash_serialized_2 is defined over THIS one.
inline void write_dashd_varint(std::vector<uint8_t>& out, uint64_t n)
{
    unsigned char tmp[10];
    int len = 0;
    while (true) {
        tmp[len] = static_cast<unsigned char>(n & 0x7F) | (len ? 0x80 : 0x00);
        if (n <= 0x7F) break;
        n = (n >> 7) - 1;
        len++;
    }
    do {
        out.push_back(tmp[len]);
    } while (len--);
}

/// Bitcoin/dashd `WriteCompactSize` (serialize.h) — the vector-length prefix
/// used when a CScript is serialized into the hash stream.
inline void write_compact_size(std::vector<uint8_t>& out, uint64_t n)
{
    if (n < 253) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xFFFF) {
        out.push_back(253);
        out.push_back(static_cast<uint8_t>(n & 0xFF));
        out.push_back(static_cast<uint8_t>((n >> 8) & 0xFF));
    } else if (n <= 0xFFFFFFFF) {
        out.push_back(254);
        for (int i = 0; i < 4; ++i)
            out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xFF));
    } else {
        out.push_back(255);
        for (int i = 0; i < 8; ++i)
            out.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xFF));
    }
}

/// One per-txid group of the hash_serialized_2 stream — a byte-exact
/// transcription of dashd v23.1.0 kernel/coinstats.cpp ApplyHash(HashWriter&):
///
///     for (auto it = outputs.begin(); it != outputs.end(); ++it) {
///         if (it == outputs.begin()) {
///             ss << hash;
///             ss << VARINT(it->second.nHeight * 2 + it->second.fCoinBase ? 1u : 0u);
///         }
///         ss << VARINT(it->first + 1);
///         ss << it->second.out.scriptPubKey;
///         ss << VARINT_MODE(it->second.out.nValue, VarIntMode::NONNEGATIVE_SIGNED);
///         if (it == std::prev(outputs.end())) { ss << VARINT(0u); }
///     }
///
/// TRANSCRIPTION NOTE, load-bearing: the second line's ternary binds as
/// `(nHeight * 2 + fCoinBase) ? 1u : 0u` — C++ precedence, `?:` below `+` —
/// so every real coin group contributes the literal VARINT(1) byte 0x01, and
/// the height/coinbase code is NOT actually folded into hash_serialized_2.
/// That is upstream Bitcoin Core's v22-era refactor quirk (fixed there only
/// by the v26 hash_serialized_3 rename); dashd v23.1.x ships the quirked
/// form, and the live anchor hash above was produced by it. Do NOT "fix"
/// this — byte-parity with dashd IS the spec. The unit KAT
/// (ReplayUtxoHash.GroupCodeIsTernaryQuirkLiteralOne) pins it.
inline void apply_hash_group(CHash256& hasher, const uint256& txid,
                             const std::map<uint32_t, ::core::coin::Coin>& outputs)
{
    if (outputs.empty()) return;
    std::vector<uint8_t> buf;
    buf.reserve(64);
    for (auto it = outputs.begin(); it != outputs.end(); ++it) {
        if (it == outputs.begin()) {
            buf.insert(buf.end(), txid.data(), txid.data() + 32);
            const uint64_t code_expr =
                static_cast<uint64_t>(it->second.height) * 2 +
                (it->second.coinbase ? 1u : 0u);
            write_dashd_varint(buf, code_expr ? 1u : 0u);  // the quirk, verbatim
        }
        write_dashd_varint(buf, static_cast<uint64_t>(it->first) + 1);
        write_compact_size(buf, it->second.scriptPubKey.m_data.size());
        buf.insert(buf.end(), it->second.scriptPubKey.m_data.begin(),
                   it->second.scriptPubKey.m_data.end());
        write_dashd_varint(buf, static_cast<uint64_t>(it->second.value));
        if (std::next(it) == outputs.end())
            write_dashd_varint(buf, 0);
    }
    hasher.Write(std::span<const unsigned char>(buf.data(), buf.size()));
}

// ── The fold ───────────────────────────────────────────────────────────────

struct ReplayUtxoFoldOptions {
    uint32_t undo_window = REPLAY_UTXO_UNDO_WINDOW;  // KAT-overridable; ships 100
    uint32_t flush_interval = 2000;  // blocks per WriteBatch (≈ W2 work-ahead)
    size_t   write_buffer_size = 32 * 1024 * 1024;
    size_t   block_cache_size = 64 * 1024 * 1024;
    // ── W5-A graduation gate (KAT-injectable; ships the live anchor) ──────
    uint32_t    gate_anchor_height = REPLAY_UTXO_GATE_ANCHOR_HEIGHT;
    std::string gate_anchor_expect = REPLAY_UTXO_GATE_ANCHOR_EXPECT;
    // Prev-hash linkage check (W5-A live-feed safety): when true, a block at
    // best+1 whose m_previous_block does not equal the cursor's best_hash is
    // REFUSED — the structural tripwire that makes silently folding across a
    // reorg (orphaned tip still in the set) impossible; the adapter disarms
    // fee-pricing on that refusal. Default OFF so pre-existing synthetic-
    // chain KATs (which use synthetic hashes, not linked headers) are byte-
    // identical; FoldFeeSource always arms it.
    bool check_prev_linkage = false;
};

/// The 'G' graduation record (see layout table). Only ever written by a
/// PASSING gate; absence IS the ungraduated state.
struct ReplayUtxoGraduation {
    uint32_t format{0};
    uint32_t anchor_height{0};
    uint256  anchor_block_hash;   // the cursor's best_hash at the anchor
    uint256  expected_hash;       // what the gate compared against
    uint256  measured_hash;       // hash_serialized_2 actually measured (== expected)
    uint64_t coins{0};
    uint64_t tx_groups{0};
    int64_t  unix_time{0};
};

struct ReplayUtxoSetHash {
    uint256  hash;          // hash_serialized_2
    uint256  best_block;    // the hashBlock folded into the stream
    uint32_t best_height{0};
    uint64_t coins{0};      // txouts in the set (live anchor: ~4.52M)
    uint64_t tx_groups{0};  // distinct txids with unspent outputs
};

class ReplayUtxoFold {
public:
    using Coin      = ::core::coin::Coin;
    using Outpoint  = ::core::coin::Outpoint;
    using BlockUndo = ::core::coin::BlockUndo;
    using TxUndo    = ::core::coin::TxUndo;

    ReplayUtxoFold() = default;
    explicit ReplayUtxoFold(ReplayUtxoFoldOptions opts) : m_opts(opts) {}
    ReplayUtxoFold(const ReplayUtxoFold&) = delete;
    ReplayUtxoFold& operator=(const ReplayUtxoFold&) = delete;
    ~ReplayUtxoFold() { close(); }

    /// Open (or create) the fold store. Fails loud on a format-version
    /// mismatch — never silently reinterprets another version's bytes.
    bool open(const std::string& db_path)
    {
        ::core::LevelDBOptions opts;
        opts.write_buffer_size = m_opts.write_buffer_size;
        opts.block_cache_size  = m_opts.block_cache_size;
        m_store = std::make_unique<::core::LevelDBStore>(db_path, opts);
        if (!m_store->open()) {
            LOG_ERROR << "[REPLAY-UTXO] failed to open store at " << db_path;
            m_store.reset();
            return false;
        }
        std::vector<uint8_t> v;
        if (m_store->get(key_version(), v)) {
            const uint32_t ver = le32(v);
            if (v.size() != 4 || ver != REPLAY_UTXO_FORMAT_VERSION) {
                LOG_ERROR << "[REPLAY-UTXO] format version mismatch: store="
                          << ver << " binary=" << REPLAY_UTXO_FORMAT_VERSION
                          << " — refusing (fail-loud versioned format)";
                m_store->close();
                m_store.reset();
                return false;
            }
        } else {
            m_store->put(key_version(), le32_bytes(REPLAY_UTXO_FORMAT_VERSION));
        }
        std::vector<uint8_t> b;
        if (m_store->get(key_cursor(), b) && b.size() >= 40) {
            std::memcpy(m_best_hash.data(), b.data(), 32);
            m_best_height = le32_at(b, 32);
            m_undo_floor  = le32_at(b, 36);
            m_have_cursor = true;
        }
        LOG_INFO << "[REPLAY-UTXO] open db=" << db_path
                 << " version=" << REPLAY_UTXO_FORMAT_VERSION
                 << (m_have_cursor
                         ? " resume_height=" + std::to_string(resume_height())
                         : std::string(" EMPTY (expects height 0 or 1 first)"));
        return true;
    }

    void close()
    {
        if (!m_store) return;
        flush();
        m_store->close();
        m_store.reset();
    }

    bool is_open() const { return static_cast<bool>(m_store); }
    bool have_cursor() const { return m_have_cursor; }
    uint32_t best_height() const { return m_best_height; }
    uint256  best_hash() const { return m_best_hash; }
    uint32_t undo_window() const { return m_opts.undo_window; }
    uint32_t gate_anchor_height() const { return m_opts.gate_anchor_height; }
    const std::string& gate_anchor_expect() const
    {
        return m_opts.gate_anchor_expect;
    }

    /// Next height the fold expects. Empty store: 0 (genesis pin) — though
    /// delivering height 1 first is equally accepted (dashd never folds
    /// genesis txs either way).
    uint32_t resume_height() const { return m_have_cursor ? m_best_height + 1 : 0; }

    /// Named cause of the last refusal (empty when none). "The state says
    /// its own name": every false return sets this.
    const std::string& refusal() const { return m_refusal; }

    // ── The consumer seam (mirrors the W1/W2 shape; see header) ────────────

    bool on_replay_block(uint32_t height, const uint256& hash,
                         const BlockType& block)
    {
        if (!m_store) return refuse("replay-utxo-not-open");
        // A failed graduation gate poisons the fold (W1 self-check idiom): a
        // fold rule that diverged from dashd must not keep extending state.
        if (m_poisoned)
            return refuse("replay-utxo-poisoned (gate FAIL latched): " +
                          m_poison_cause);

        // Idempotent redelivery (resume overlap): already folded, ack.
        if (m_have_cursor && height <= m_best_height)
            return true;

        // Strict in-order, no-gap contract.
        if (m_have_cursor && height != m_best_height + 1)
            return refuse("replay-utxo-gap: got h=" + std::to_string(height) +
                          " want h=" + std::to_string(m_best_height + 1));

        // W5-A prev-hash linkage (opt-in; see ReplayUtxoFoldOptions): the
        // structural reorg tripwire. Folding new-chain h+1 on top of an
        // ORPHANED h would silently corrupt coin state (a wrong value can
        // OVERSTATE a fee → overstated coinbasevalue → invalid found block),
        // so a broken link is refused and the adapter disarms fee-pricing.
        if (m_opts.check_prev_linkage && m_have_cursor && m_best_height >= 1
            && !(block.m_previous_block == m_best_hash))
            return refuse("replay-utxo-prev-mismatch: h=" +
                          std::to_string(height) + " prev=" +
                          block.m_previous_block.GetHex().substr(0, 16) +
                          " cursor=" + m_best_hash.GetHex().substr(0, 16) +
                          " (reorg or mis-fed lane)");
        // Cold start must begin at the chain's origin — a mid-chain UTXO
        // fold can never reach the gate hash (unlike the DIP3-anchored MN
        // fold). Height 0 or 1 both establish the cursor correctly.
        if (!m_have_cursor && height > 1)
            return refuse("replay-utxo-cold-start-above-1: got h=" +
                          std::to_string(height) +
                          " on an empty store (UTXO fold starts at genesis)");

        BlockUndo undo;
        if (height > 0) {  // genesis folds nothing (dashd ConnectBlock short-circuit)
            if (!apply_block_txs(height, block, undo))
                return false;  // m_refusal set, overlay changes rolled back
        }

        m_best_hash = hash;
        m_best_height = height;
        m_have_cursor = true;
        m_pending_undo.emplace_back(height, std::move(undo));
        m_pending_hashes.emplace_back(height, hash);

        if (++m_since_flush >= m_opts.flush_interval)
            return flush();
        return true;
    }

    /// The plain-callback form of the same seam (what W5 hands the transport).
    std::function<bool(uint32_t, const uint256&, const BlockType&)> consumer()
    {
        return [this](uint32_t h, const uint256& hash, const BlockType& b) {
            return on_replay_block(h, hash, b);
        };
    }

    /// Disconnect the tip block using its stored undo record (reorg support
    /// within the undo window). `block` must be the tip body — its vin
    /// outpoints key the spent-coin restore, exactly like dashd's
    /// DisconnectBlock walks the block against CBlockUndo.
    bool disconnect_tip(const BlockType& block)
    {
        if (!m_store) return refuse("replay-utxo-not-open");
        if (!m_have_cursor || m_best_height == 0)
            return refuse("replay-utxo-disconnect-no-tip");
        if (!flush()) return false;  // simplify: operate on a consistent store

        const uint32_t h = m_best_height;
        BlockUndo undo;
        {
            std::vector<uint8_t> u;
            if (!m_store->get(key_undo(h), u) ||
                !::core::coin::deserialize_block_undo(u, undo))
                return refuse("replay-utxo-undo-missing: h=" + std::to_string(h) +
                              " (outside the " + std::to_string(m_opts.undo_window) +
                              "-block undo window?)");
        }
        uint256 prev_hash;
        {
            std::vector<uint8_t> ph;
            if (h >= 1 && m_store->get(key_hash(h - 1), ph) && ph.size() == 32) {
                std::memcpy(prev_hash.data(), ph.data(), 32);
            } else if (h == 1) {
                prev_hash = uint256();  // pre-genesis-pin cursor
            } else {
                return refuse("replay-utxo-disconnect-prev-hash-missing: h=" +
                              std::to_string(h - 1));
            }
        }

        // Remove every output the block added.
        for (const auto& op : undo.added_outpoints)
            m_overlay[op] = std::nullopt;

        // Restore spent inputs, reverse tx order (dashd DisconnectBlock).
        size_t undo_idx = undo.tx_undos.size();
        for (int i = static_cast<int>(block.m_txs.size()) - 1; i >= 1; --i) {
            const auto& tx = block.m_txs[i];
            if (undo_idx == 0)
                return refuse("replay-utxo-disconnect-undo-underrun");
            --undo_idx;
            const auto& tu = undo.tx_undos[undo_idx];
            if (tu.spent_coins.size() != tx.vin.size())
                return refuse("replay-utxo-disconnect-vin-count-mismatch");
            for (size_t j = 0; j < tx.vin.size(); ++j) {
                Outpoint op(tx.vin[j].prevout.hash, tx.vin[j].prevout.index);
                m_overlay[op] = tu.spent_coins[j];
            }
        }

        m_best_height = h - 1;
        m_best_hash = prev_hash;
        m_pending_undo_removals.push_back(h);
        return flush();
    }

    // ── Reads ──────────────────────────────────────────────────────────────

    bool get_coin(const Outpoint& op, Coin& out) const
    {
        auto it = m_overlay.find(op);
        if (it != m_overlay.end()) {
            if (!it->second.has_value()) return false;
            out = *it->second;
            return true;
        }
        std::vector<uint8_t> data;
        if (m_store && m_store->get(key_coin(op), data))
            return ::core::coin::deserialize_coin(data, out);
        return false;
    }

    bool have_coin(const Outpoint& op) const
    {
        Coin c;
        return get_coin(op, c);
    }

    /// Coinbase-maturity predicate over the stored metadata (dashd
    /// consensus.h COINBASE_MATURITY=100 via DASH_LIMITS).
    static bool is_mature(const Coin& coin, uint32_t spend_height)
    {
        return coin.is_mature(spend_height, DASH_LIMITS);
    }

    bool undo_available(uint32_t height)
    {
        if (!m_store) return false;
        for (const auto& [h, u] : m_pending_undo)
            if (h == height) return true;
        return m_store->exists(key_undo(height));
    }

    // ── Persistence ────────────────────────────────────────────────────────

    /// Commit the overlay + pending undo records + cursor in one atomic
    /// WriteBatch, then prune undo/hash records below the window floor.
    bool flush()
    {
        if (!m_store) return refuse("replay-utxo-not-open");
        if (!m_have_cursor) return true;  // nothing folded yet
        if (m_overlay.empty() && m_pending_undo.empty() &&
            m_pending_hashes.empty() && m_pending_undo_removals.empty() &&
            m_since_flush == 0)
            return true;  // no-op flush: cursor already persisted

        auto batch = m_store->create_batch();
        // Disconnect removals FIRST: a WriteBatch applies in insertion order,
        // so a (never-currently-possible, but cheap to make impossible)
        // disconnect+reconnect of the same height within one flush must not
        // let the removal clobber the re-added undo record.
        for (uint32_t h : m_pending_undo_removals) {
            batch.remove(key_undo(h));
            batch.remove(key_hash(h));
        }
        for (const auto& [op, change] : m_overlay) {
            if (change.has_value())
                batch.put(key_coin(op), ::core::coin::serialize_coin(*change));
            else
                batch.remove(key_coin(op));
        }
        for (const auto& [h, undo] : m_pending_undo)
            batch.put(key_undo(h), ::core::coin::serialize_block_undo(undo));
        for (const auto& [h, hash] : m_pending_hashes) {
            std::vector<uint8_t> hb(hash.data(), hash.data() + 32);
            batch.put(key_hash(h), hb);
        }
        // Prune the undo window inside the same batch: keep exactly the last
        // `undo_window` heights [best-window+1 .. best].
        uint32_t new_floor = m_undo_floor;
        if (m_best_height + 1 > m_opts.undo_window) {
            const uint32_t keep_from = m_best_height + 1 - m_opts.undo_window;
            for (uint32_t h = m_undo_floor; h < keep_from; ++h) {
                batch.remove(key_undo(h));
                batch.remove(key_hash(h));
            }
            new_floor = std::max(m_undo_floor, keep_from);
        }
        // Cursor last — committed atomically with everything above.
        {
            std::vector<uint8_t> cur(40);
            std::memcpy(cur.data(), m_best_hash.data(), 32);
            put_le32(cur, 32, m_best_height);
            put_le32(cur, 36, new_floor);
            batch.put(key_cursor(), cur);
        }
        if (!batch.commit())
            return refuse("replay-utxo-flush-commit-failed at h=" +
                          std::to_string(m_best_height));
        m_undo_floor = new_floor;
        m_overlay.clear();
        m_pending_undo.clear();
        m_pending_hashes.clear();
        m_pending_undo_removals.clear();
        m_since_flush = 0;
        return true;
    }

    // ── THE GATE: dashd-compatible serialize-hash of the whole set ─────────

    /// gettxoutsetinfo `hash_serialized_2` equivalence: flushes, then streams
    /// every coin in LevelDB key order ('C' + txid + vout-LE — txid groups
    /// are contiguous and txid-byte-ordered exactly like dashd's
    /// 'C' + txid + VARINT(vout) cursor), grouping per txid into an
    /// ascending-vout map and folding each group via apply_hash_group; the
    /// stream is prefixed with the cursor's best_block and finalized
    /// double-SHA256 (dashd kernel/coinstats.cpp ComputeUTXOStats +
    /// PrepareHash + FinalizeHash). Returns std::nullopt only on a store
    /// error (fail-closed — never a guess).
    std::optional<ReplayUtxoSetHash> hash_serialized_2()
    {
        if (!m_store) { refuse("replay-utxo-not-open"); return std::nullopt; }
        if (!flush()) return std::nullopt;

        ReplayUtxoSetHash out;
        out.best_block = m_best_hash;
        out.best_height = m_best_height;

        CHash256 hasher;
        hasher.Write(std::span<const unsigned char>(m_best_hash.data(), 32));

        uint256 group_txid;
        std::map<uint32_t, Coin> group;
        bool corrupt = false;
        bool scan_ok = m_store->for_each_prefix(
            std::string(1, 'C'),
            [&](const std::string& key, const std::vector<uint8_t>& value) {
                if (key.size() != 37) {
                    corrupt = true;  // foreign key shape under 'C' = corruption
                    return false;
                }
                Outpoint op = ::core::coin::key_to_outpoint(key.substr(1));
                Coin coin;
                if (!::core::coin::deserialize_coin(value, coin)) {
                    corrupt = true;
                    return false;
                }
                if (!group.empty() && !(op.txid == group_txid)) {
                    apply_hash_group(hasher, group_txid, group);
                    ++out.tx_groups;
                    group.clear();
                }
                group_txid = op.txid;
                group[op.index] = std::move(coin);
                ++out.coins;
                return true;
            });
        if (!scan_ok || corrupt) {
            refuse("replay-utxo-hash-scan-failed (store error or corrupt coin)");
            return std::nullopt;
        }
        if (!group.empty()) {
            apply_hash_group(hasher, group_txid, group);
            ++out.tx_groups;
        }
        hasher.Finalize(std::span<unsigned char>(out.hash.data(), 32));
        return out;
    }

    // ── W5-A GRADUATION GATE ───────────────────────────────────────────────
    // The single place fold state can ever EARN fee-pricing trust. Callable
    // ONLY while the cursor stands exactly on the anchor height (hash_
    // serialized_2 hashes the CURRENT set, so any other cursor is a category
    // error, refused). PASS → the 'G' record is written (the durable proof a
    // restart may restore trust from); FAIL → the fold is POISONED (latched:
    // every further on_replay_block refuses) and NOTHING is written — absence
    // of 'G' is the fail state. A crash between the pass and the 'G' put
    // leaves an ungraduated store parked at the anchor; the adapter re-runs
    // the gate at construction in that case (same verdict, pure re-measure).

    bool poisoned() const { return m_poisoned; }

    /// Read the stored graduation record ('G'). nullopt = never graduated.
    std::optional<ReplayUtxoGraduation> graduation()
    {
        if (!m_store) return std::nullopt;
        std::vector<uint8_t> v;
        if (!m_store->get(key_graduation(), v)) return std::nullopt;
        if (v.size() != 4 + 4 + 32 + 32 + 32 + 8 + 8 + 8) {
            refuse("replay-utxo-graduation-record-corrupt: " +
                   std::to_string(v.size()) + " bytes");
            return std::nullopt;
        }
        ReplayUtxoGraduation g;
        size_t at = 0;
        g.format        = le32_at(v, at); at += 4;
        g.anchor_height = le32_at(v, at); at += 4;
        std::memcpy(g.anchor_block_hash.data(), v.data() + at, 32); at += 32;
        std::memcpy(g.expected_hash.data(),     v.data() + at, 32); at += 32;
        std::memcpy(g.measured_hash.data(),     v.data() + at, 32); at += 32;
        g.coins     = le64_at(v, at); at += 8;
        g.tx_groups = le64_at(v, at); at += 8;
        g.unix_time = static_cast<int64_t>(le64_at(v, at));
        return g;
    }

    /// Run the gate at the anchor cursor. Returns true ONLY on a byte-equal
    /// PASS (record written). Any failure is named via refusal(); a HASH
    /// MISMATCH additionally poisons the fold.
    bool try_graduate()
    {
        if (!m_store) return refuse("replay-utxo-not-open");
        if (m_poisoned)
            return refuse("replay-utxo-poisoned: " + m_poison_cause);
        if (!m_have_cursor || m_best_height != m_opts.gate_anchor_height)
            return refuse(
                "replay-utxo-gate-wrong-cursor: h=" +
                std::to_string(m_have_cursor ? m_best_height : 0) +
                " anchor=" + std::to_string(m_opts.gate_anchor_height) +
                " (hash_serialized_2 hashes the CURRENT set — verification"
                " is only possible standing exactly on the anchor)");
        std::string want_hex = m_opts.gate_anchor_expect;
        for (auto& c : want_hex)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (want_hex.size() != 64)
            return refuse("replay-utxo-gate-bad-expect-hex: '" +
                          m_opts.gate_anchor_expect + "'");
        auto measured = hash_serialized_2();   // flushes first
        if (!measured) return false;           // refusal already named
        if (measured->hash.GetHex() != want_hex) {
            m_poisoned = true;
            m_poison_cause = "gate-fail h=" +
                std::to_string(m_opts.gate_anchor_height) +
                " got=" + measured->hash.GetHex() +
                " want=" + want_hex;
            LOG_ERROR << "[REPLAY-UTXO] GATE FAIL h="
                      << m_opts.gate_anchor_height
                      << " got=" << measured->hash.GetHex()
                      << " want=" << want_hex
                      << " coins=" << measured->coins
                      << " — fold POISONED (no further blocks accepted;"
                         " nothing written; fee-pricing stays disarmed)";
            return refuse("replay-utxo-" + m_poison_cause);
        }
        // PASS — write the durable record. expected == measured by
        // definition on this (the only) writing path; both fields are kept
        // so a reader can distinguish "what was demanded" from "what was
        // seen" if the layout ever grows an operator-override arm.
        std::vector<uint8_t> rec;
        rec.reserve(4 + 4 + 32 + 32 + 32 + 8 + 8 + 8);
        append_le32(rec, REPLAY_UTXO_FORMAT_VERSION);
        append_le32(rec, m_opts.gate_anchor_height);
        rec.insert(rec.end(), m_best_hash.data(), m_best_hash.data() + 32);
        rec.insert(rec.end(), measured->hash.data(), measured->hash.data() + 32);
        rec.insert(rec.end(), measured->hash.data(), measured->hash.data() + 32);
        append_le64(rec, measured->coins);
        append_le64(rec, measured->tx_groups);
        append_le64(rec, static_cast<uint64_t>(std::time(nullptr)));
        if (!m_store->put(key_graduation(), rec))
            return refuse("replay-utxo-gate-record-write-failed");
        LOG_INFO << "[REPLAY-UTXO] GATE PASS h=" << m_opts.gate_anchor_height
                 << " hash=" << measured->hash.GetHex()
                 << " coins=" << measured->coins
                 << " tx_groups=" << measured->tx_groups
                 << " — graduation record written";
        return true;
    }

private:
    bool refuse(const std::string& why)
    {
        m_refusal = why;
        LOG_ERROR << "[REPLAY-UTXO] REFUSE: " << why;
        return false;
    }

    /// Spend every input and add every output of the block's txs into the
    /// overlay, strictly. On refusal the overlay is restored to its previous
    /// state (the block contributes nothing).
    bool apply_block_txs(uint32_t height, const BlockType& block, BlockUndo& undo)
    {
        if (block.m_txs.empty())
            return refuse("replay-utxo-empty-block: h=" + std::to_string(height) +
                          " (a parsed body always carries its coinbase)");
        // Rollback journal over the TOUCHED keys only (never a full overlay
        // copy — the overlay carries up to flush_interval blocks of changes,
        // and an O(overlay) copy per block would dominate the whole 1.49M-
        // block fold). Outer optional = "key was present in the overlay";
        // inner optional = the overlay value it had (coin / spent-marker).
        std::vector<std::pair<Outpoint, std::optional<std::optional<Coin>>>> journal;
        auto journal_touch = [&](const Outpoint& op) {
            auto it = m_overlay.find(op);
            journal.emplace_back(
                op, it == m_overlay.end()
                        ? std::optional<std::optional<Coin>>{}
                        : std::optional<std::optional<Coin>>{it->second});
        };
        auto rollback = [&]() {
            for (auto it = journal.rbegin(); it != journal.rend(); ++it) {
                if (it->second.has_value())
                    m_overlay[it->first] = *it->second;
                else
                    m_overlay.erase(it->first);
            }
        };

        bool first = true;
        for (const auto& tx : block.m_txs) {
            const bool is_coinbase = first;
            first = false;
            const uint256 txid = dash_txid(tx);

            if (!is_coinbase) {
                TxUndo tu;
                tu.spent_coins.reserve(tx.vin.size());
                for (const auto& vin : tx.vin) {
                    Outpoint op(vin.prevout.hash, vin.prevout.index);
                    Coin spent;
                    if (!get_coin(op, spent)) {
                        rollback();
                        return refuse(
                            "replay-utxo-missing-input: h=" + std::to_string(height) +
                            " tx=" + txid.GetHex().substr(0, 16) +
                            " prevout=" + op.txid.GetHex().substr(0, 16) + ":" +
                            std::to_string(op.index));
                    }
                    journal_touch(op);
                    m_overlay[op] = std::nullopt;  // spend
                    tu.spent_coins.push_back(std::move(spent));
                }
                undo.tx_undos.push_back(std::move(tu));
            }

            for (uint32_t i = 0; i < static_cast<uint32_t>(tx.vout.size()); ++i) {
                const auto& vout = tx.vout[i];
                // dashd AddCoins: only IsUnspendable() scripts are excluded.
                // Zero-value spendable outputs STAY (mempool-lane divergence
                // — see header).
                if (::core::coin::is_unspendable(vout.scriptPubKey))
                    continue;
                Outpoint op(txid, i);
                if (have_coin(op)) {
                    rollback();
                    return refuse("replay-utxo-bip30-duplicate: h=" +
                                  std::to_string(height) + " outpoint=" +
                                  txid.GetHex().substr(0, 16) + ":" +
                                  std::to_string(i));
                }
                journal_touch(op);
                m_overlay[op] =
                    Coin(vout.value, vout.scriptPubKey, height, is_coinbase);
                undo.added_outpoints.push_back(op);
            }
        }
        return true;
    }

    // ── Keys (see layout table in the header) ──────────────────────────────
    static std::string key_version() { return std::string(1, 'V'); }
    static std::string key_cursor() { return std::string(1, 'B'); }
    static std::string key_coin(const Outpoint& op)
    {
        std::string k;
        k.reserve(37);
        k.push_back('C');
        k.append(::core::coin::outpoint_to_key(op));
        return k;
    }
    static std::string key_be32(char tag, uint32_t h)
    {
        std::string k;
        k.reserve(5);
        k.push_back(tag);
        k.push_back(static_cast<char>((h >> 24) & 0xFF));
        k.push_back(static_cast<char>((h >> 16) & 0xFF));
        k.push_back(static_cast<char>((h >> 8) & 0xFF));
        k.push_back(static_cast<char>(h & 0xFF));
        return k;
    }
    static std::string key_undo(uint32_t h) { return key_be32('U', h); }
    static std::string key_hash(uint32_t h) { return key_be32('H', h); }
    static std::string key_graduation() { return std::string(1, 'G'); }

    static uint32_t le32(const std::vector<uint8_t>& v)
    {
        if (v.size() < 4) return 0;
        return le32_at(v, 0);
    }
    static std::vector<uint8_t> le32_bytes(uint32_t x)
    {
        std::vector<uint8_t> v(4);
        put_le32(v, 0, x);
        return v;
    }
    static uint32_t le32_at(const std::vector<uint8_t>& v, size_t at)
    {
        return uint32_t(v[at]) | (uint32_t(v[at + 1]) << 8) |
               (uint32_t(v[at + 2]) << 16) | (uint32_t(v[at + 3]) << 24);
    }
    static uint64_t le64_at(const std::vector<uint8_t>& v, size_t at)
    {
        return uint64_t(le32_at(v, at)) |
               (uint64_t(le32_at(v, at + 4)) << 32);
    }
    static void append_le32(std::vector<uint8_t>& v, uint32_t x)
    {
        for (int i = 0; i < 4; ++i)
            v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
    }
    static void append_le64(std::vector<uint8_t>& v, uint64_t x)
    {
        for (int i = 0; i < 8; ++i)
            v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xFF));
    }
    static void put_le32(std::vector<uint8_t>& v, size_t at, uint32_t x)
    {
        v[at] = x & 0xFF;
        v[at + 1] = (x >> 8) & 0xFF;
        v[at + 2] = (x >> 16) & 0xFF;
        v[at + 3] = (x >> 24) & 0xFF;
    }

    ReplayUtxoFoldOptions m_opts{};
    std::unique_ptr<::core::LevelDBStore> m_store;

    // Write-back overlay: outpoint → Coin (live) / nullopt (spent-delete).
    std::unordered_map<Outpoint, std::optional<Coin>,
                       ::core::coin::OutpointHasher> m_overlay;
    std::vector<std::pair<uint32_t, BlockUndo>> m_pending_undo;
    std::vector<std::pair<uint32_t, uint256>> m_pending_hashes;
    std::vector<uint32_t> m_pending_undo_removals;

    uint256  m_best_hash;
    uint32_t m_best_height{0};
    uint32_t m_undo_floor{0};
    bool     m_have_cursor{false};
    uint32_t m_since_flush{0};
    std::string m_refusal;
    // W5-A gate poison latch (in-memory: a restart re-measures; the DURABLE
    // fail state is the absence of 'G' past the anchor).
    bool        m_poisoned{false};
    std::string m_poison_cause;
};

} // namespace replay
} // namespace coin
} // namespace dash
