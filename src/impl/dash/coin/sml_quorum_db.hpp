// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 13c: persistent SML + quorum state (the sibling
/// stores credit_pool_db.hpp / mn_state_db.hpp already reference by name).
///
/// The embedded DASH arm's Simplified Masternode List (CSimplifiedMNList,
/// merkleRootMNList source) and active LLMQ quorum set (QuorumManager,
/// merkleRootQuorums source) were IN-MEMORY only: every process restart
/// cold-started a full mnlistdiff(zero, tip) re-sync off the coin-P2P peer.
/// These two stores persist that state so a restart RESUMES incrementally —
/// load the last persisted state, set the getmnlistd base to the persisted
/// tip, and apply only the incremental mnlistdiff from there.
///
/// REUSE, do not hand-roll: both stores wrap core::LevelDBStore exactly like
/// MnStateDb (atomic WriteBatch full-rewrite per accepted mnlistdiff, BEST
/// sentinel for tip tracking, load-on-open). The persistence wire format is
/// INTERNAL-ONLY — never shared on the network — so we serialize the vendored
/// CSimplifiedMNListEntry / CFinalCommitment via pack.hpp directly (the same
/// codec their from-wire parse already round-trips byte-exact).
///
/// FAIL-CLOSED-ON-CORRUPT INVARIANT (the correctness keystone): the store is
/// NEVER trusted blindly. write_*() records the merkle root computed over the
/// state it persists; load_verified() reconstructs the state, RECOMPUTES the
/// root INDEPENDENTLY, and refuses the load unless it matches. A corrupt /
/// stale / partially-written store (bit rot, a torn batch, a downgraded codec)
/// therefore fails closed — the load is rejected and the on-disk store wiped,
/// so the arm falls back to a full mnlistdiff(zero, tip) re-sync rather than
/// ever serving a template built on a WRONG root (which would mine a
/// consensus-invalid block). A self-consistent-but-wrong root cannot be caught
/// by a self-referential check, so on reorg / H-1 heal main_dash also WIPES
/// these stores (see CoinStateMaintainer::set_on_sml_clear) — an orphaned-branch
/// state is self-consistent and would pass the root-verify.
///
/// MN DIFF-LADDER (2026-08-02, DASH_MN_DIFF_LADDER_RECOVERY.md): the store
/// additionally RETAINS the accepted mnlistdiffs and periodic full anchors so a
/// desynced arm has a LOCAL re-seed key instead of an authoritative `protx` RPC
/// it does not have on a daemonless node. Purely ADDITIVE keyspaces: the 'S' /
/// 'B' live-tip state and its full-rewrite path are untouched, so the change
/// cannot regress the warm-restart path, and every ladder failure path lands on
/// exactly today's behaviour (cold mnlistdiff(zero,tip)).
///
/// NOT A NEW TRUST ROOT. Each retained diff's resulting merkleRootMNList was
/// itself supplied by the peer that sent the diff; a consistently-lying peer
/// produces a self-consistent chain of roots that passes every check here. We
/// hold headers, not blocks, so cbTx (dashd's independent root source) is not
/// available. This is the SAME trust exposure the arm already carries live —
/// the ladder does not worsen it — but the ladder must NOT be described as
/// consensus-anchored. (Design doc gate G1.)
///
/// Schemas
///   SMLDb  ('sml_db/'):
///     'S' + proRegTxHash(32B)       -> pack(CSimplifiedMNListEntry)
///     'B'                            -> best_hash(32B) height(4B LE)
///                                        expected_merkleRootMNList(32B)
///     'D' + height(4B BE)            -> pack(CSimplifiedMNListDiff)
///                                        resulting_merkleRootMNList(32B)
///     'A' + height(4B BE)            -> pack(vector<CSimplifiedMNListEntry>)
///                                        merkleRootMNList(32B) block_hash(32B)
///   Heights are BIG-endian so LevelDB's byte-lexicographic key order IS
///   height order (list_keys / the replay scan rely on it).
///   QuorumDb ('quorum_db/'):
///     'Q' + seq(4B BE)               -> pack(CFinalCommitment) mining_height(4B LE)
///     'L' + seq(4B BE)               -> sig(96B) count(4B LE) count*index(2B LE)
///     'B'                            -> best_hash(32B) height(4B LE)
///                                        expected_merkleRootQuorums(32B)

#include <impl/dash/coin/vendor/simplifiedmns.hpp>  // vendor::CSimplifiedMNList(Entry)
#include <impl/dash/coin/vendor/smldiff.hpp>        // vendor::CSimplifiedMNListDiff / apply_diff
#include <impl/dash/coin/quorum_manager.hpp>        // QuorumManager
#include <impl/dash/coin/quorum_root.hpp>           // compute_merkle_root_quorums

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace dash {
namespace coin {

namespace sml_db_detail {

inline void put_u32_le(std::vector<uint8_t>& out, uint32_t v)
{
    out.push_back(static_cast<uint8_t>( v        & 0xFF));
    out.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

inline uint32_t get_u32_le(const uint8_t* p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

// 4-byte BIG-endian sequence key so list_keys() returns a stable order.
inline std::string make_seq_key(char tag, uint32_t seq)
{
    std::string k;
    k.reserve(5);
    k.push_back(tag);
    k.push_back(static_cast<char>((seq >> 24) & 0xFF));
    k.push_back(static_cast<char>((seq >> 16) & 0xFF));
    k.push_back(static_cast<char>((seq >>  8) & 0xFF));
    k.push_back(static_cast<char>( seq        & 0xFF));
    return k;
}

template <typename T>
inline std::vector<uint8_t> pack_bytes(const T& obj)
{
    auto stream = ::pack(obj);
    auto sp = stream.get_span();
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(sp.data()),
        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}

} // namespace sml_db_detail

// ─────────────────────────────────────────────────────────────────────────
// MN DIFF-LADDER SIZING — ⚠ PENDING REVIEW SIZING. THESE ARE PLACEHOLDERS.
// ─────────────────────────────────────────────────────────────────────────
// The design doc (gate G2) leaves both numbers explicitly UNSET: a recommended
// anchor interval and retention window are being computed by the in-flight
// review harness. The values below are STARTING PLACEHOLDERS chosen to be
// obviously-safe rather than tuned, and MUST be revisited before the ladder
// re-seed default is flipped on:
//
//   * MN_LADDER_ANCHOR_INTERVAL mirrors dashd's MINI_SNAPSHOT_INTERVAL (32,
//     evo/deterministicmns.h) purely because that is the one published number
//     in the neighbourhood — it is NOT evidence that 32 is right for us.
//   * MN_LADDER_RETENTION_HEIGHTS (4096 ≈ 7 days at Dash's 2.5 min spacing)
//     bounds the store. The only real-world data point is the contabo smoke
//     rig's two desync events 155 heights apart — a data point of exactly one.
inline constexpr uint32_t MN_LADDER_ANCHOR_INTERVAL   = 32;    // PLACEHOLDER
inline constexpr uint32_t MN_LADDER_RETENTION_HEIGHTS = 4096;  // PLACEHOLDER

/// Why a ladder replay ended. Every non-Ok value must land the caller on
/// TODAY'S behaviour (latch stays set, cold mnlistdiff(zero,tip) re-sync).
enum class LadderOutcome {
    Ok,                  ///< replayed anchor..target, every root recomputed+matched
    StoreClosed,         ///< db not open — nothing to replay
    AnchorMissing,       ///< no 'A' anchor at height <= target
    AnchorDecodeFailed,  ///< 'A' value unreadable / entry deserialize threw
    AnchorRootMismatch,  ///< recomputed anchor merkleRootMNList != stored root
    DiffGap,             ///< a height in (anchor, target] has NO 'D' record
    DiffDecodeFailed,    ///< 'D' value unreadable / diff deserialize threw
    DiffBaseMismatch,    ///< 'D'@h base does not chain onto the previous block
    DiffRootMismatch,    ///< recomputed root after applying 'D'@h != stored root
};

/// Result of SMLDb::replay_from_ladder(). `reason` is the human-facing string
/// the observability law requires: a gate that can silently refuse must say
/// WHY, in a place a human looks.
struct LadderReplay {
    LadderOutcome outcome{LadderOutcome::AnchorMissing};
    uint32_t      target_height{0};
    uint32_t      anchor_height{0};
    uint32_t      failed_height{0};   ///< the height that aborted (0 = n/a)
    uint32_t      replayed{0};        ///< diffs successfully applied
    uint256       block_hash;         ///< block the rebuilt SML is current at
    uint256       root;               ///< recomputed merkleRootMNList
    vendor::CSimplifiedMNList sml;    ///< rebuilt state (only meaningful on Ok)

    bool ok() const { return outcome == LadderOutcome::Ok; }

    std::string reason() const
    {
        switch (outcome) {
        case LadderOutcome::Ok:
            return "ok-replayed-" + std::to_string(replayed) + "-diffs";
        case LadderOutcome::StoreClosed:      return "store-closed";
        case LadderOutcome::AnchorMissing:    return "anchor-missing";
        case LadderOutcome::AnchorDecodeFailed:
            return "anchor-decode-failed-at-h=" + std::to_string(anchor_height);
        case LadderOutcome::AnchorRootMismatch:
            return "anchor-root-mismatch-at-h=" + std::to_string(anchor_height);
        case LadderOutcome::DiffGap:
            return "diff-gap-at-h=" + std::to_string(failed_height);
        case LadderOutcome::DiffDecodeFailed:
            return "diff-decode-failed-at-h=" + std::to_string(failed_height);
        case LadderOutcome::DiffBaseMismatch:
            return "diff-base-mismatch-at-h=" + std::to_string(failed_height);
        case LadderOutcome::DiffRootMismatch:
            return "diff-root-mismatch-at-h=" + std::to_string(failed_height);
        }
        return "unknown";
    }
};

/// One-line ladder depth report (the startup / state banner).
struct LadderStats {
    uint32_t anchors{0};        ///< number of retained 'A' records
    uint32_t diffs{0};          ///< number of retained 'D' records
    uint32_t lowest_diff{0};    ///< lowest retained diff height (0 = none)
    uint32_t highest_diff{0};   ///< highest retained diff height (0 = none)
    uint32_t highest_anchor{0}; ///< highest retained anchor height (0 = none)

    std::string banner() const
    {
        return "anchors=" + std::to_string(anchors)
             + " diffs=" + std::to_string(diffs)
             + " heights=[" + std::to_string(lowest_diff) + ".."
             + std::to_string(highest_diff) + "]"
             + " top_anchor=" + std::to_string(highest_anchor)
             + " interval=" + std::to_string(MN_LADDER_ANCHOR_INTERVAL)
             + " window=" + std::to_string(MN_LADDER_RETENTION_HEIGHTS);
    }
};

// ── SMLDb: persist the CSimplifiedMNList (merkleRootMNList source) ─────────
class SMLDb
{
public:
    explicit SMLDb(const std::string& db_path,
                   const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()
    {
        if (!m_store.open()) return false;
        load_best_state();
        LOG_INFO << "[SML-DB] opened best_height=" << m_best_height
                 << " best_hash=" << m_best_hash.GetHex().substr(0, 16);
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    uint256  get_best_hash() const     { return m_best_hash; }
    uint32_t get_best_height() const   { return m_best_height; }
    uint256  get_expected_root() const { return m_expected_root; }

    // Atomic full-rewrite of the SML entry set + BEST sentinel. The sentinel
    // carries the merkleRootMNList computed HERE (the independent verify anchor
    // load_verified re-derives and compares against).
    //
    // MN DIFF-LADDER (additive): when `accepted` is non-null and best_height is
    // known, the SAME WriteBatch also appends 'D'@best_height (the diff that
    // produced this state + the root it results in), writes 'A'@best_height on
    // an anchor boundary, and prunes both keyspaces below the retention window.
    // ONE batch, still atomic, NO new commit point — the ladder can never be
    // half-written relative to the 'S'/'B' state it describes. Passing nullptr
    // (every pre-existing call site) writes exactly the old bytes.
    bool write_sml(const vendor::CSimplifiedMNList& sml,
                   const uint256& best_hash, uint32_t best_height,
                   const vendor::CSimplifiedMNListDiff* accepted = nullptr)
    {
        const uint256 expected_root = sml.CalcMerkleRoot();

        auto batch = m_store.create_batch();
        for (const auto& k : m_store.list_keys(std::string(1, 'S'), 500000))
            batch.remove(k);
        for (const auto& e : sml.mnList)
            batch.put(make_entry_key(e.proRegTxHash),
                      sml_db_detail::pack_bytes(e));
        batch.put(make_state_key(),
                  encode_best_state(best_hash, best_height, expected_root));

        // ── ladder append + prune, IN THIS BATCH ──────────────────────────
        // best_height == 0 means the caller could not resolve the height (the
        // header is not in the chain yet). A ladder rung with no height cannot
        // be replayed and cannot be gap-checked, so it is simply not written —
        // the replay's density check will then abort at that height, which is
        // the fail-toward-today behaviour we want.
        bool ladder_wrote_anchor = false;
        if (accepted != nullptr && best_height != 0) {
            batch.put(sml_db_detail::make_seq_key('D', best_height),
                      encode_ladder_diff(*accepted, expected_root));
            if (best_height % MN_LADDER_ANCHOR_INTERVAL == 0) {
                batch.put(sml_db_detail::make_seq_key('A', best_height),
                          encode_ladder_anchor(sml, expected_root, best_hash));
                ladder_wrote_anchor = true;
            }
            prune_ladder_into(batch, best_height);
        }

        if (!batch.commit()) {
            LOG_WARNING << "[SML-DB] write_sml batch commit failed";
            return false;
        }
        m_best_hash     = best_hash;
        m_best_height   = best_height;
        m_expected_root = expected_root;
        if (accepted != nullptr && best_height != 0 && ladder_wrote_anchor)
            LOG_INFO << "[MN-LADDER] anchor written @h=" << best_height
                     << " (" << sml.size() << " MNs, root "
                     << expected_root.GetHex().substr(0, 16) << ")";
        return true;
    }

    // ── MN DIFF-LADDER RECOVERY ───────────────────────────────────────────
    // Rebuild the SML at `target_h` from the retained anchor + diffs, with the
    // SAME fail-closed discipline load_verified() uses at EVERY step: the root
    // is RECOMPUTED from the reconstructed state and compared against the root
    // stored alongside the record. Never partial, never "best effort":
    //
    //   1. greatest 'A' anchor at height <= target_h; none  -> AnchorMissing
    //   2. load it, RECOMPUTE the root, mismatch            -> AnchorRootMismatch
    //   3. for h in anchor_h+1 .. target_h:
    //        'D'@h MUST EXIST — a MISSING height ABORTS     -> DiffGap
    //        its baseBlockHash must chain onto the previous -> DiffBaseMismatch
    //        apply, RECOMPUTE the root, compare to stored   -> DiffRootMismatch
    //   4. success -> the rebuilt state is RETURNED; the CALLER decides what to
    //      re-arm. This function never mutates live state and never clears a
    //      latch by itself.
    //
    // DENSITY IS REQUIRED, NOT ASSUMED (design doc gate G1). A diff that
    // legitimately spans several heights (base h, to h+3) leaves h+1/h+2
    // without a 'D' record and is therefore REFUSED even though base-hash
    // continuity would prove it correct. That over-refusal is deliberate: it
    // fails toward today's behaviour, and distinguishing "we never saw those
    // heights" from "one diff covered them" is exactly the semantics question
    // the in-flight reviews must settle before the re-seed default is flipped.
    LadderReplay replay_from_ladder(uint32_t target_h)
    {
        LadderReplay r;
        r.target_height = target_h;
        if (!m_store.is_open()) {
            r.outcome = LadderOutcome::StoreClosed;
            return r;
        }

        // 1) greatest anchor at height <= target_h (keys are BE => ascending).
        uint32_t anchor_h = 0;
        bool     found    = false;
        for (const auto& key : m_store.list_keys(std::string(1, 'A'), 500000)) {
            uint32_t h = 0;
            if (!parse_seq_key(key, 'A', h)) continue;
            if (h > target_h) break;
            anchor_h = h;
            found    = true;
        }
        if (!found) {
            r.outcome = LadderOutcome::AnchorMissing;
            return r;
        }
        r.anchor_height = anchor_h;

        // 2) load + INDEPENDENTLY recompute the anchor's root.
        std::vector<uint8_t> abuf;
        if (!m_store.get(sml_db_detail::make_seq_key('A', anchor_h), abuf)
            || abuf.size() < 64) {
            r.outcome = LadderOutcome::AnchorDecodeFailed;
            return r;
        }
        uint256 stored_root, stored_hash;
        std::memcpy(stored_root.data(), abuf.data() + abuf.size() - 64, 32);
        std::memcpy(stored_hash.data(), abuf.data() + abuf.size() - 32, 32);
        std::vector<vendor::CSimplifiedMNListEntry> entries;
        try {
            std::vector<uint8_t> body(abuf.begin(), abuf.end() - 64);
            ::PackStream ps(body);
            ps >> entries;
        } catch (const std::exception&) {
            r.outcome = LadderOutcome::AnchorDecodeFailed;
            return r;
        }
        vendor::CSimplifiedMNList state(std::move(entries));   // ctor re-sorts
        if (state.CalcMerkleRoot() != stored_root) {
            r.outcome = LadderOutcome::AnchorRootMismatch;
            return r;
        }
        uint256 cur_hash = stored_hash;

        // 3) dense forward replay, root-verified at every single height.
        for (uint32_t h = anchor_h + 1; h <= target_h; ++h) {
            std::vector<uint8_t> dbuf;
            if (!m_store.get(sml_db_detail::make_seq_key('D', h), dbuf)) {
                r.failed_height = h;
                r.outcome = LadderOutcome::DiffGap;
                return r;
            }
            if (dbuf.size() < 32) {
                r.failed_height = h;
                r.outcome = LadderOutcome::DiffDecodeFailed;
                return r;
            }
            uint256 want_root;
            std::memcpy(want_root.data(), dbuf.data() + dbuf.size() - 32, 32);
            vendor::CSimplifiedMNListDiff diff;
            try {
                std::vector<uint8_t> body(dbuf.begin(), dbuf.end() - 32);
                ::PackStream ps(body);
                ps >> diff;
            } catch (const std::exception&) {
                r.failed_height = h;
                r.outcome = LadderOutcome::DiffDecodeFailed;
                return r;
            }
            // Base-continuity: the SAME guard on_mnlistdiff applies live. A
            // ZERO base is a full snapshot and always chains (it replaces).
            if (!diff.baseBlockHash.IsNull() && diff.baseBlockHash != cur_hash) {
                r.failed_height = h;
                r.outcome = LadderOutcome::DiffBaseMismatch;
                return r;
            }
            if (diff.baseBlockHash.IsNull()) state.mnList.clear();
            vendor::apply_diff(state, diff);
            if (state.CalcMerkleRoot() != want_root) {
                r.failed_height = h;
                r.outcome = LadderOutcome::DiffRootMismatch;
                return r;
            }
            cur_hash = diff.blockHash;
            ++r.replayed;
        }

        r.outcome    = LadderOutcome::Ok;
        r.block_hash = cur_hash;
        r.root       = state.CalcMerkleRoot();
        r.sml        = std::move(state);
        return r;
    }

    /// Ladder depth, for the startup / state banner.
    LadderStats ladder_stats()
    {
        LadderStats s;
        if (!m_store.is_open()) return s;
        for (const auto& key : m_store.list_keys(std::string(1, 'A'), 500000)) {
            uint32_t h = 0;
            if (!parse_seq_key(key, 'A', h)) continue;
            ++s.anchors;
            s.highest_anchor = h;
        }
        for (const auto& key : m_store.list_keys(std::string(1, 'D'), 500000)) {
            uint32_t h = 0;
            if (!parse_seq_key(key, 'D', h)) continue;
            if (s.diffs == 0) s.lowest_diff = h;
            ++s.diffs;
            s.highest_diff = h;
        }
        return s;
    }

    /// Drop the ladder only (leaves the 'S'/'B' live-tip state alone).
    /// Design-doc gate G3: the reorg/heal wipe MUST take the ladder with it —
    /// an orphaned-branch ladder is self-consistent and would replay clean.
    bool clear_ladder()
    {
        auto batch = m_store.create_batch();
        size_t n = 0;
        for (const auto& k : m_store.list_keys(std::string(1, 'D'), 500000)) {
            batch.remove(k); ++n;
        }
        for (const auto& k : m_store.list_keys(std::string(1, 'A'), 500000)) {
            batch.remove(k); ++n;
        }
        if (!batch.commit()) return false;
        if (n) LOG_INFO << "[MN-LADDER] cleared " << n << " ladder records";
        return true;
    }

    // FAIL-CLOSED load: reconstruct the SML, recompute merkleRootMNList, and
    // accept ONLY when it equals the persisted root. Any mismatch or parse
    // failure wipes the store and returns false so the caller cold-resyncs.
    // `out` is left EMPTY on any non-warm/failed load.
    bool load_verified(vendor::CSimplifiedMNList& out)
    {
        out.mnList.clear();
        if (m_best_hash.IsNull()) return false;   // no sentinel => cold start

        std::vector<vendor::CSimplifiedMNListEntry> entries;
        for (const auto& key : m_store.list_keys(std::string(1, 'S'), 500000)) {
            if (key.size() != 33 || key[0] != 'S') continue;
            std::vector<uint8_t> data;
            if (!m_store.get(key, data))
                return fail_closed("entry read failed");
            try {
                vendor::CSimplifiedMNListEntry e;
                ::PackStream ps(data);
                ps >> e;
                entries.push_back(std::move(e));
            } catch (const std::exception& ex) {
                return fail_closed(std::string("entry deserialize: ") + ex.what());
            }
        }

        vendor::CSimplifiedMNList sml(std::move(entries));   // ctor re-sorts
        const uint256 root = sml.CalcMerkleRoot();
        if (root != m_expected_root)
            return fail_closed("merkleRootMNList mismatch persisted="
                               + m_expected_root.GetHex().substr(0, 16)
                               + " recomputed=" + root.GetHex().substr(0, 16));

        out = std::move(sml);
        LOG_INFO << "[SML-DB] loaded+verified " << out.size()
                 << " MNs, merkleRootMNList OK @h=" << m_best_height;
        return true;
    }

    // G3 DECISION (design doc, "does the ladder survive the fail-closed wipe?"):
    // clear() takes the LADDER WITH IT. The reorg / H-1 heal case is
    // unambiguous — an orphaned-branch ladder is self-consistent and would
    // replay clean into a wrong-branch state. The corrupt-load case is the one
    // the doc leaves OPEN; we take the conservative side (wipe) so that a store
    // we have just proven untrustworthy cannot supply the re-seed key. That
    // choice costs recovery in exactly the corrupt case and is a candidate for
    // the in-flight reviews to revisit; it is deliberately NOT a silent default.
    bool clear()
    {
        auto batch = m_store.create_batch();
        for (const auto& k : m_store.list_keys(std::string(1, 'S'), 500000))
            batch.remove(k);
        for (const auto& k : m_store.list_keys(std::string(1, 'D'), 500000))
            batch.remove(k);
        for (const auto& k : m_store.list_keys(std::string(1, 'A'), 500000))
            batch.remove(k);
        batch.remove(make_state_key());
        if (!batch.commit()) return false;
        m_best_hash     = uint256{};
        m_best_height   = 0;
        m_expected_root = uint256{};
        LOG_INFO << "[SML-DB] cleared (incl. MN diff-ladder)";
        return true;
    }

private:
    ::core::LevelDBStore m_store;
    uint256              m_best_hash;
    uint256              m_expected_root;
    uint32_t             m_best_height{0};

    // 'D' value = pack(diff) ++ resulting_merkleRootMNList(32B). The root is a
    // FIXED-WIDTH SUFFIX because CSimplifiedMNListDiff's unserializer drains
    // the remaining stream bytes as its opaque quorum tail — the replay hands
    // it a body slice that stops 32 bytes short, never the whole value.
    static std::vector<uint8_t> encode_ladder_diff(
        const vendor::CSimplifiedMNListDiff& diff, const uint256& root)
    {
        auto out = sml_db_detail::pack_bytes(diff);
        out.insert(out.end(), root.data(), root.data() + 32);
        return out;
    }

    // 'A' value = pack(vector<entry>) ++ root(32B) ++ block_hash(32B). The
    // block hash is what lets the replay bind the FIRST diff's baseBlockHash to
    // the anchor instead of trusting the diff chain to start in the right place.
    static std::vector<uint8_t> encode_ladder_anchor(
        const vendor::CSimplifiedMNList& sml, const uint256& root,
        const uint256& block_hash)
    {
        auto stream = ::pack(sml.mnList);
        auto sp = stream.get_span();
        std::vector<uint8_t> out(
            reinterpret_cast<const uint8_t*>(sp.data()),
            reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
        out.insert(out.end(), root.data(), root.data() + 32);
        out.insert(out.end(), block_hash.data(), block_hash.data() + 32);
        return out;
    }

    static bool parse_seq_key(const std::string& key, char tag, uint32_t& out_h)
    {
        if (key.size() != 5 || key[0] != tag) return false;
        out_h = (uint32_t(uint8_t(key[1])) << 24)
              | (uint32_t(uint8_t(key[2])) << 16)
              | (uint32_t(uint8_t(key[3])) <<  8)
              |  uint32_t(uint8_t(key[4]));
        return true;
    }

    // Retention (design doc gate G2): drop 'D'/'A' below the window floor in
    // the SAME batch as the append, so the store cannot grow without limit and
    // the prune can never be observed apart from the write it rides with.
    // Bounded scan: the walk starts at the LOWEST retained height (BE keys are
    // ascending) and stops at the window floor, so in steady state — where at
    // most one record leaves the window per write — a handful of keys are
    // examined. The cap keeps a per-diff write O(1)-ish instead of O(window);
    // a larger backlog (e.g. after the retention constant is lowered) simply
    // drains over the following writes rather than stalling one of them.
    static constexpr size_t kLadderPruneScanLimit = 256;

    void prune_ladder_into(::core::LevelDBStore::BatchWriter& batch,
                           uint32_t tip_height)
    {
        if (tip_height <= MN_LADDER_RETENTION_HEIGHTS) return;
        const uint32_t floor_h = tip_height - MN_LADDER_RETENTION_HEIGHTS;
        for (char tag : {'D', 'A'}) {
            for (const auto& key : m_store.list_keys(std::string(1, tag),
                                                     kLadderPruneScanLimit)) {
                uint32_t h = 0;
                if (!parse_seq_key(key, tag, h)) continue;
                if (h >= floor_h) break;      // BE keys => ascending => done
                batch.remove(key);
            }
        }
    }

    bool fail_closed(const std::string& why)
    {
        LOG_WARNING << "[SML-DB] FAIL-CLOSED (" << why
                    << ") -> wiping store, cold mnlistdiff(zero,tip) re-sync";
        clear();
        return false;
    }

    static std::string make_entry_key(const uint256& proRegTxHash)
    {
        std::string k;
        k.reserve(33);
        k.push_back('S');
        k.append(reinterpret_cast<const char*>(proRegTxHash.data()), 32);
        return k;
    }

    static std::string make_state_key() { return std::string(1, 'B'); }

    static std::vector<uint8_t> encode_best_state(const uint256& hash,
                                                  uint32_t height,
                                                  const uint256& root)
    {
        std::vector<uint8_t> out;
        out.reserve(68);
        out.insert(out.end(), hash.data(), hash.data() + 32);
        sml_db_detail::put_u32_le(out, height);
        out.insert(out.end(), root.data(), root.data() + 32);
        return out;
    }

    void load_best_state()
    {
        std::vector<uint8_t> data;
        if (!m_store.get(make_state_key(), data) || data.size() < 68) return;
        std::memcpy(m_best_hash.data(), data.data(), 32);
        m_best_height = sml_db_detail::get_u32_le(data.data() + 32);
        std::memcpy(m_expected_root.data(), data.data() + 36, 32);
    }
};

// ── QuorumDb: persist the active LLMQ set (merkleRootQuorums source) ───────
class QuorumDb
{
public:
    explicit QuorumDb(const std::string& db_path,
                      const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()
    {
        if (!m_store.open()) return false;
        load_best_state();
        LOG_INFO << "[QUO-DB] opened best_height=" << m_best_height
                 << " best_hash=" << m_best_hash.GetHex().substr(0, 16);
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    uint256  get_best_hash() const     { return m_best_hash; }
    uint32_t get_best_height() const   { return m_best_height; }
    uint256  get_expected_root() const { return m_expected_root; }

    // Atomic full-rewrite of the active quorum set + cached CL sigs + BEST
    // sentinel (carrying merkleRootQuorums, the independent verify anchor).
    bool write_quorums(const QuorumManager& qmgr,
                       const uint256& best_hash, uint32_t best_height)
    {
        const uint256 expected_root = compute_merkle_root_quorums(qmgr);

        auto batch = m_store.create_batch();
        for (const auto& k : m_store.list_keys(std::string(1, 'Q'), 500000))
            batch.remove(k);
        for (const auto& k : m_store.list_keys(std::string(1, 'L'), 500000))
            batch.remove(k);

        uint32_t seq = 0;
        for (const auto& e : qmgr.active_entries()) {
            auto data = sml_db_detail::pack_bytes(e.commitment);
            sml_db_detail::put_u32_le(data, e.mining_height);
            batch.put(sml_db_detail::make_seq_key('Q', seq++), data);
        }
        seq = 0;
        for (const auto& s : qmgr.latest_cl_sigs()) {
            std::vector<uint8_t> v;
            v.insert(v.end(), s.first.begin(), s.first.end());   // 96B BLS sig
            sml_db_detail::put_u32_le(v,
                static_cast<uint32_t>(s.second.size()));
            for (uint16_t idx : s.second) {
                v.push_back(static_cast<uint8_t>( idx       & 0xFF));
                v.push_back(static_cast<uint8_t>((idx >> 8) & 0xFF));
            }
            batch.put(sml_db_detail::make_seq_key('L', seq++), v);
        }
        batch.put(make_state_key(),
                  encode_best_state(best_hash, best_height, expected_root));

        if (!batch.commit()) {
            LOG_WARNING << "[QUO-DB] write_quorums batch commit failed";
            return false;
        }
        m_best_hash     = best_hash;
        m_best_height   = best_height;
        m_expected_root = expected_root;
        return true;
    }

    // FAIL-CLOSED load: warm `out` with the persisted active set + CL sigs,
    // recompute merkleRootQuorums, and accept ONLY when it matches the
    // persisted root. On any mismatch / parse failure the store is wiped, `out`
    // is cleared, and false is returned (cold re-sync).
    bool load_verified(QuorumManager& out)
    {
        out.clear();
        if (m_best_hash.IsNull()) return false;

        std::vector<QuorumManager::Entry> entries;
        for (const auto& key : m_store.list_keys(std::string(1, 'Q'), 500000)) {
            std::vector<uint8_t> data;
            if (!m_store.get(key, data) || data.size() < 4)
                return fail_closed(out, "quorum read failed");
            try {
                QuorumManager::Entry ent;
                ::PackStream ps(data);
                ps >> ent.commitment;
                ent.key = QuorumManager::ActiveKey{
                    ent.commitment.llmqType, ent.commitment.quorumHash};
                ent.mining_height =
                    sml_db_detail::get_u32_le(data.data() + data.size() - 4);
                entries.push_back(std::move(ent));
            } catch (const std::exception& ex) {
                return fail_closed(out,
                    std::string("commitment deserialize: ") + ex.what());
            }
        }

        constexpr size_t SIG = vendor::CFinalCommitment::BLS_SIG_SIZE;
        std::vector<QuorumManager::CLSig> cl_sigs;
        for (const auto& key : m_store.list_keys(std::string(1, 'L'), 500000)) {
            std::vector<uint8_t> data;
            if (!m_store.get(key, data) || data.size() < SIG + 4)
                return fail_closed(out, "clsig read failed");
            QuorumManager::CLSig s;
            std::memcpy(s.first.data(), data.data(), SIG);
            uint32_t n = sml_db_detail::get_u32_le(data.data() + SIG);
            if (data.size() < SIG + 4 + size_t(n) * 2)
                return fail_closed(out, "clsig index underrun");
            s.second.reserve(n);
            for (uint32_t i = 0; i < n; ++i) {
                const uint8_t* p = data.data() + SIG + 4 + size_t(i) * 2;
                s.second.push_back(
                    static_cast<uint16_t>(uint16_t(p[0]) | (uint16_t(p[1]) << 8)));
            }
            cl_sigs.push_back(std::move(s));
        }

        out.replace_state(std::move(entries), std::move(cl_sigs));
        const uint256 root = compute_merkle_root_quorums(out);
        if (root != m_expected_root)
            return fail_closed(out, "merkleRootQuorums mismatch persisted="
                               + m_expected_root.GetHex().substr(0, 16)
                               + " recomputed=" + root.GetHex().substr(0, 16));

        LOG_INFO << "[QUO-DB] loaded+verified " << out.active_count()
                 << " quorums, merkleRootQuorums OK @h=" << m_best_height;
        return true;
    }

    bool clear()
    {
        auto batch = m_store.create_batch();
        for (const auto& k : m_store.list_keys(std::string(1, 'Q'), 500000))
            batch.remove(k);
        for (const auto& k : m_store.list_keys(std::string(1, 'L'), 500000))
            batch.remove(k);
        batch.remove(make_state_key());
        if (!batch.commit()) return false;
        m_best_hash     = uint256{};
        m_best_height   = 0;
        m_expected_root = uint256{};
        LOG_INFO << "[QUO-DB] cleared";
        return true;
    }

private:
    ::core::LevelDBStore m_store;
    uint256              m_best_hash;
    uint256              m_expected_root;
    uint32_t             m_best_height{0};

    bool fail_closed(QuorumManager& out, const std::string& why)
    {
        LOG_WARNING << "[QUO-DB] FAIL-CLOSED (" << why
                    << ") -> wiping store, cold mnlistdiff(zero,tip) re-sync";
        out.clear();
        clear();
        return false;
    }

    static std::string make_state_key() { return std::string(1, 'B'); }

    static std::vector<uint8_t> encode_best_state(const uint256& hash,
                                                  uint32_t height,
                                                  const uint256& root)
    {
        std::vector<uint8_t> out;
        out.reserve(68);
        out.insert(out.end(), hash.data(), hash.data() + 32);
        sml_db_detail::put_u32_le(out, height);
        out.insert(out.end(), root.data(), root.data() + 32);
        return out;
    }

    void load_best_state()
    {
        std::vector<uint8_t> data;
        if (!m_store.get(make_state_key(), data) || data.size() < 68) return;
        std::memcpy(m_best_hash.data(), data.data(), 32);
        m_best_height = sml_db_detail::get_u32_le(data.data() + 32);
        std::memcpy(m_expected_root.data(), data.data() + 36, 32);
    }
};

} // namespace coin
} // namespace dash
