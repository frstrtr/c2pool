// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// ── MN DIFF/SNAPSHOT STORE — the dashd evodb list-diff mechanism, ported ──
///
/// dashd persists, for EVERY connected block, the per-block delta of the
/// deterministic masternode list ("dmn_D4" keyed by blockHash,
/// evo/deterministicmns.cpp:33,:689) plus a full list snapshot every
/// DISK_SNAPSHOT_PERIOD=576 blocks ("dmn_S3", cpp:690), and reconstructs the
/// list for ANY block by walking backward hash-by-hash to the nearest
/// snapshot and replaying the stored diffs forward
/// (GetListForBlockInternal, cpp:778-870). That store is why dashd never
/// has a "payee-queue gap": any list at any height is reconstructable.
///
/// This file is that mechanism over OUR fold state (ReplayMNState,
/// replay_fold_engine.hpp:184), written by the replay fold's per-block
/// commit and read by the gap-repair path (mn_gap_repair.hpp).
///
/// Construct map (dashd → here):
///   * DB_LIST_DIFF "dmn_D4" + blockHash      → 'D' + block_hash(32)
///   * DB_LIST_SNAPSHOT "dmn_S3" + blockHash  → 'S' + block_hash(32)
///     (value = the engine's snapshot-v3 payload, reused unchanged)
///   * EVODB_BEST_BLOCK (evo/evodb.h, validation.cpp:2322/:2707)
///     → 'B' sentinel written in the SAME batch as every 'D'
///   * dmn_D3→D4 migration (cpp:958)          → 'F' format key,
///     wipe-WHOLE-STORE on mismatch (never per-entry migration — the
///     MnStateDb v1→v2 silently-skipped-rows defect is the counterexample,
///     mn_state_db.hpp:200-207)
///   * CDeterministicMNListDiff (deterministicmns.h:580) → MnListDiff
///   * CDeterministicMNStateDiff bitmask, nVersion-first (dmnstate.h:155-260)
///     → MnStateDiff
///   * BuildDiff (cpp:361-395)                → MnListDiff::build
///   * ApplyDiff throws on base-state mismatch (cpp:396-418)
///     → MnListDiff::apply returns a fail-closed REFUSAL (a throw is never
///       a skip; the contract is identical, only the vehicle differs)
///   * diff.nHeight is memory-only, re-stamped from the walk on every read
///     (cpp:697,:822) → NO height is stored in a 'D' record, ever. A trusted
///     stored height silently diverges on reorged hashes.
///
/// Deliberate divergences from the mirror, each forced by our trust model:
///   1. dashd defines "no snapshot AND no diff" as the initial EMPTY list
///      (cpp:813-819) — sound only because its write is consensus-atomic
///      with connect. Our store is populated by a P2P fold and CAN
///      transiently miss rows, so a missing row is REPAIR-REFUSED, never an
///      empty list. This is the single most important inversion and it is
///      what keeps the wipe/demote fail-closed floor intact.
///   2. Each 'D' record carries proof flags (root_matched, payee_verified),
///      the block's committed merkleRootMNList, prev_hash (we have no
///      CBlockIndex to walk) and a sha256d trailer. dashd trusts its rows
///      because write==connect; ours must carry the license that produced
///      them, checkable at repair time.
///   3. UndoBlock evicts caches but keeps disk rows (cpp:736-769); we keep
///      rows on reorg too — hash-keyed rows for orphaned blocks are
///      harmless residue, and wiping diff history on reorg would destroy
///      exactly what repair depends on. The reorg wipe cascade
///      (set_on_sml_clear) is deliberately NOT wired to this store.
///   4. mini-snapshots (cpp:832-847) and the mnListsCache/tip retention +
///      cleanup machinery (cpp:850-956) are NOT ported: they are read-path
///      cache economics for a hot GetListForBlock; our reconstruct runs
///      rarely (gap repair), bounded ≤576 diff applies by the cadence.
///   5. DB_LIST_REPAIRED (cpp:1239) is NOT ported: our startup verify is
///      O(576) and the failure remedy (wipe + repopulate from the live
///      fold) is idempotent and cheap — the store is an accelerator, never
///      consensus-required; its absence degrades to today's wipe/demote.
///
/// Every record is written for EVERY root-matched folded block, EVEN WHEN
/// THE DIFF IS EMPTY: the empty record is proof-of-processing. Skipping
/// empties would make "no change at h" indistinguishable from "h was never
/// folded" — the dashd gotcha, kept verbatim.

#include <impl/dash/coin/replay_fold_engine.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>

#include <core/hash.hpp>
#include <core/leveldb_store.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace replay {

// ═══════════════════════════════════════════════════════════════════════════
// MnStateDiff — mirror of dashd CDeterministicMNStateDiff (evo/dmnstate.h:155)
// ═══════════════════════════════════════════════════════════════════════════
/// Field bitmask over the STATE-level members of ReplayMNState — the same 19
/// bits, same values, same member order as dashd's boost::hana member tuple
/// (dmnstate.h:158-213). The DMN-level members (nType, internalId,
/// collateralOutpoint, nOperatorReward) are immutable after registration in
/// dashd (they live on CDeterministicMN, not CDeterministicMNState) and are
/// therefore NOT diffable here either — they travel only in `added` entries.
///
/// Wire rule kept structurally even though our codec is not byte-compatible
/// with evodb (persistence is internal-only, mn_state_db.hpp:35-38): fields
/// whose wire format depends on the version serialize AFTER the version bit,
/// and a diff that sets pubKeyOperator or netInfo without nVersion is
/// invalid data (dmnstate.h:225-236 and the SERIALIZE_METHODS guard).
struct MnStateDiff
{
    enum Field : uint32_t {
        Field_nVersion                      = 0x0001,
        Field_nRegisteredHeight             = 0x0002,
        Field_nLastPaidHeight               = 0x0004,
        Field_nPoSePenalty                  = 0x0008,
        Field_nPoSeRevivedHeight            = 0x0010,
        Field_nPoSeBanHeight                = 0x0020,
        Field_nRevocationReason             = 0x0040,
        Field_confirmedHash                 = 0x0080,
        Field_confirmedHashWithProRegTxHash = 0x0100,
        Field_keyIDOwner                    = 0x0200,
        Field_pubKeyOperator                = 0x0400,
        Field_keyIDVoting                   = 0x0800,
        Field_netInfo                       = 0x1000,
        Field_scriptPayout                  = 0x2000,
        Field_scriptOperatorPayout          = 0x4000,
        Field_nConsecutivePayments          = 0x8000,
        Field_platformNodeID                = 0x10000,
        Field_platformP2PPort               = 0x20000,
        Field_platformHTTPPort              = 0x40000,
    };
    static constexpr uint32_t kAllFields = 0x7FFFF;

    uint32_t      fields{0};
    /// Only the members named by `fields` are valid — dashd reuses the state
    /// class the same way (dmnstate.h:216-218).
    ReplayMNState state;

    MnStateDiff() = default;

    /// dashd CDeterministicMNStateDiff(a, b) (dmnstate.h:221-241): record
    /// every state member where b differs from a; pubKeyOperator/netInfo
    /// changing forces the nVersion bit.
    MnStateDiff(const ReplayMNState& a, const ReplayMNState& b)
    {
        auto take = [&](uint32_t mask, auto member) {
            if (member(a) != member(b)) {
                fields |= mask;
            }
        };
        take(Field_nVersion,          [](const ReplayMNState& s) { return s.nVersion; });
        take(Field_nRegisteredHeight, [](const ReplayMNState& s) { return s.nRegisteredHeight; });
        take(Field_nLastPaidHeight,   [](const ReplayMNState& s) { return s.nLastPaidHeight; });
        take(Field_nPoSePenalty,      [](const ReplayMNState& s) { return s.nPoSePenalty; });
        take(Field_nPoSeRevivedHeight,[](const ReplayMNState& s) { return s.nPoSeRevivedHeight; });
        take(Field_nPoSeBanHeight,    [](const ReplayMNState& s) { return s.nPoSeBanHeight; });
        take(Field_nRevocationReason, [](const ReplayMNState& s) { return s.nRevocationReason; });
        take(Field_confirmedHash,     [](const ReplayMNState& s) { return s.confirmedHash; });
        take(Field_confirmedHashWithProRegTxHash,
                                      [](const ReplayMNState& s) { return s.confirmedHashWithProRegTxHash; });
        take(Field_keyIDOwner,        [](const ReplayMNState& s) { return s.keyIDOwner; });
        take(Field_pubKeyOperator,    [](const ReplayMNState& s) { return s.pubKeyOperator; });
        take(Field_keyIDVoting,       [](const ReplayMNState& s) { return s.keyIDVoting; });
        if (a.netInfo.ip != b.netInfo.ip || a.netInfo.port_be != b.netInfo.port_be)
            fields |= Field_netInfo;
        if (a.scriptPayout.m_data != b.scriptPayout.m_data)
            fields |= Field_scriptPayout;
        if (a.scriptOperatorPayout.m_data != b.scriptOperatorPayout.m_data)
            fields |= Field_scriptOperatorPayout;
        take(Field_nConsecutivePayments,
                                      [](const ReplayMNState& s) { return s.nConsecutivePayments; });
        take(Field_platformNodeID,    [](const ReplayMNState& s) { return s.platformNodeID; });
        take(Field_platformP2PPort,   [](const ReplayMNState& s) { return s.platformP2PPort; });
        take(Field_platformHTTPPort,  [](const ReplayMNState& s) { return s.platformHTTPPort; });

        if (fields != 0) state = b;   // masked members read from b's copy
        // pubKeyOperator and netInfo need nVersion (dmnstate.h:237-241).
        if ((fields & Field_pubKeyOperator) || (fields & Field_netInfo)) {
            state.nVersion = b.nVersion;
            fields |= Field_nVersion;
        }
    }

    /// dashd CDeterministicMNState::ApplyDiff via UpdateMN: copy exactly the
    /// masked members onto the target state; everything else keeps.
    void apply_to(ReplayMNState& t) const
    {
        if (fields & Field_nVersion)                      t.nVersion = state.nVersion;
        if (fields & Field_nRegisteredHeight)             t.nRegisteredHeight = state.nRegisteredHeight;
        if (fields & Field_nLastPaidHeight)               t.nLastPaidHeight = state.nLastPaidHeight;
        if (fields & Field_nPoSePenalty)                  t.nPoSePenalty = state.nPoSePenalty;
        if (fields & Field_nPoSeRevivedHeight)            t.nPoSeRevivedHeight = state.nPoSeRevivedHeight;
        if (fields & Field_nPoSeBanHeight)                t.nPoSeBanHeight = state.nPoSeBanHeight;
        if (fields & Field_nRevocationReason)             t.nRevocationReason = state.nRevocationReason;
        if (fields & Field_confirmedHash)                 t.confirmedHash = state.confirmedHash;
        if (fields & Field_confirmedHashWithProRegTxHash) t.confirmedHashWithProRegTxHash = state.confirmedHashWithProRegTxHash;
        if (fields & Field_keyIDOwner)                    t.keyIDOwner = state.keyIDOwner;
        if (fields & Field_pubKeyOperator)                t.pubKeyOperator = state.pubKeyOperator;
        if (fields & Field_keyIDVoting)                   t.keyIDVoting = state.keyIDVoting;
        if (fields & Field_netInfo)                       t.netInfo = state.netInfo;
        if (fields & Field_scriptPayout)                  t.scriptPayout = state.scriptPayout;
        if (fields & Field_scriptOperatorPayout)          t.scriptOperatorPayout = state.scriptOperatorPayout;
        if (fields & Field_nConsecutivePayments)          t.nConsecutivePayments = state.nConsecutivePayments;
        if (fields & Field_platformNodeID)                t.platformNodeID = state.platformNodeID;
        if (fields & Field_platformP2PPort)               t.platformP2PPort = state.platformP2PPort;
        if (fields & Field_platformHTTPPort)              t.platformHTTPPort = state.platformHTTPPort;
    }

    /// Masked serialization, member order = dashd's tuple order, nVersion
    /// FIRST (dmnstate.h "Bumped for nVersion-first format" — the very
    /// reason dmn_D3 became dmn_D4).
    void write_to(::PackStream& s) const
    {
        WriteCompactSize(s, fields);
        if (fields & Field_nVersion)                      s << state.nVersion;
        if (fields & Field_nRegisteredHeight)             s << state.nRegisteredHeight;
        if (fields & Field_nLastPaidHeight)               s << state.nLastPaidHeight;
        if (fields & Field_nPoSePenalty)                  s << state.nPoSePenalty;
        if (fields & Field_nPoSeRevivedHeight)            s << state.nPoSeRevivedHeight;
        if (fields & Field_nPoSeBanHeight)                s << state.nPoSeBanHeight;
        if (fields & Field_nRevocationReason)             s << state.nRevocationReason;
        if (fields & Field_confirmedHash)                 s << state.confirmedHash;
        if (fields & Field_confirmedHashWithProRegTxHash) s << state.confirmedHashWithProRegTxHash;
        if (fields & Field_keyIDOwner)                    s << state.keyIDOwner;
        if (fields & Field_pubKeyOperator)
            s.write(std::as_bytes(std::span{state.pubKeyOperator}));
        if (fields & Field_keyIDVoting)                   s << state.keyIDVoting;
        if (fields & Field_netInfo)                       s << state.netInfo;
        if (fields & Field_scriptPayout)                  s << state.scriptPayout;
        if (fields & Field_scriptOperatorPayout)          s << state.scriptOperatorPayout;
        if (fields & Field_nConsecutivePayments)          s << state.nConsecutivePayments;
        if (fields & Field_platformNodeID)                s << state.platformNodeID;
        if (fields & Field_platformP2PPort)               s << state.platformP2PPort;
        if (fields & Field_platformHTTPPort)              s << state.platformHTTPPort;
    }

    /// Throws std::ios_base::failure on malformed data (unknown bits, the
    /// nVersion rule) — the caller converts to a whole-record refusal.
    void read_from(::PackStream& s)
    {
        fields = static_cast<uint32_t>(ReadCompactSize(s));
        if (fields & ~kAllFields)
            throw std::ios_base::failure("MnStateDiff: unknown field bits");
        // dashd SERIALIZE_METHODS guard (dmnstate.h:249-252), verbatim rule.
        if (((fields & Field_pubKeyOperator) || (fields & Field_netInfo))
            && !(fields & Field_nVersion))
            throw std::ios_base::failure(
                "Invalid data, nVersion unset when pubKeyOperator or netInfo set");
        if (fields & Field_nVersion)                      s >> state.nVersion;
        if (fields & Field_nRegisteredHeight)             s >> state.nRegisteredHeight;
        if (fields & Field_nLastPaidHeight)               s >> state.nLastPaidHeight;
        if (fields & Field_nPoSePenalty)                  s >> state.nPoSePenalty;
        if (fields & Field_nPoSeRevivedHeight)            s >> state.nPoSeRevivedHeight;
        if (fields & Field_nPoSeBanHeight)                s >> state.nPoSeBanHeight;
        if (fields & Field_nRevocationReason)             s >> state.nRevocationReason;
        if (fields & Field_confirmedHash)                 s >> state.confirmedHash;
        if (fields & Field_confirmedHashWithProRegTxHash) s >> state.confirmedHashWithProRegTxHash;
        if (fields & Field_keyIDOwner)                    s >> state.keyIDOwner;
        if (fields & Field_pubKeyOperator)
            s.read(std::as_writable_bytes(std::span{state.pubKeyOperator}));
        if (fields & Field_keyIDVoting)                   s >> state.keyIDVoting;
        if (fields & Field_netInfo)                       s >> state.netInfo;
        if (fields & Field_scriptPayout)                  s >> state.scriptPayout;
        if (fields & Field_scriptOperatorPayout)          s >> state.scriptOperatorPayout;
        if (fields & Field_nConsecutivePayments)          s >> state.nConsecutivePayments;
        if (fields & Field_platformNodeID)                s >> state.platformNodeID;
        if (fields & Field_platformP2PPort)               s >> state.platformP2PPort;
        if (fields & Field_platformHTTPPort)              s >> state.platformHTTPPort;
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// MnListDiff — mirror of dashd CDeterministicMNListDiff (deterministicmns.h)
// ═══════════════════════════════════════════════════════════════════════════
struct MnListDiff
{
    using Entries = DmlFoldEngine::Entries;

    /// Sorted ASCENDING by internalId (BuildDiff, deterministicmns.cpp:383-386:
    /// "added MNs need to be sorted by internalId so that these are added in
    /// correct order when the diff is applied later; otherwise internalIds
    /// will not match with the original list").
    std::vector<std::pair<uint256, ReplayMNState>> added;
    /// Keyed by internalId, exactly as dashd's updatedMNs map.
    std::map<uint64_t, MnStateDiff>                updated;
    /// internalIds, exactly as dashd's removedMns set.
    std::set<uint64_t>                             removed;

    bool empty() const
    {
        return added.empty() && updated.empty() && removed.empty();
    }

    /// dashd CDeterministicMNList::BuildDiff (deterministicmns.cpp:361-395),
    /// including the removal-scan early-out arithmetic.
    static MnListDiff build(const Entries& from, const Entries& to)
    {
        MnListDiff d;
        for (const auto& [protx, to_st] : to) {
            auto it = from.find(protx);
            if (it == from.end()) {
                d.added.emplace_back(protx, to_st);
            } else {
                MnStateDiff sd(it->second, to_st);
                if (sd.fields) d.updated.emplace(to_st.internalId, std::move(sd));
            }
        }
        if (from.size() + d.added.size() != to.size()) {
            for (const auto& [protx, from_st] : from) {
                if (to.find(protx) == to.end()) {
                    d.removed.insert(from_st.internalId);
                    if (from.size() + d.added.size() - d.removed.size()
                            == to.size())
                        break;
                }
            }
        }
        std::sort(d.added.begin(), d.added.end(),
                  [](const auto& a, const auto& b) {
                      return a.second.internalId < b.second.internalId;
                  });
        return d;
    }

    /// dashd CDeterministicMNList::ApplyDiff (deterministicmns.cpp:396-418)
    /// with exception→refusal: any internalId miss, duplicate proTxHash /
    /// internalId / collateralOutpoint refuses the WHOLE apply and the list
    /// is left in an unspecified partial state the caller must DISCARD. The
    /// contract is identical to dashd's throw — a refusal is never a skip;
    /// it is the tripwire for "diff applied to a list that is not its true
    /// parent".
    bool apply(Entries& list, std::string& err) const
    {
        err.clear();
        std::map<uint64_t, uint256> by_id;
        std::set<std::pair<uint256, uint32_t>> collaterals;
        for (const auto& [protx, st] : list) {
            by_id[st.internalId] = protx;
            collaterals.emplace(st.collateralOutpoint.hash,
                                st.collateralOutpoint.index);
        }
        // Order mirrors ApplyDiff: removed, added, updated.
        for (uint64_t id : removed) {
            auto it = by_id.find(id);
            if (it == by_id.end()) {
                err = "can't find a removed masternode, id=" + std::to_string(id);
                return false;
            }
            auto lit = list.find(it->second);
            collaterals.erase({lit->second.collateralOutpoint.hash,
                               lit->second.collateralOutpoint.index});
            list.erase(lit);
            by_id.erase(it);
        }
        for (const auto& [protx, st] : added) {
            // dashd AddMN's uniqueness proofs (deterministicmns.cpp:420-447):
            // duplicate proTxHash, duplicate internalId, duplicate
            // collateralOutpoint each throw there and refuse here. The other
            // unique properties (netInfo entries, keys) are covered
            // transitively by the caller's final SML-root check.
            if (list.find(protx) != list.end()) {
                err = "can't add a masternode with a duplicate proTxHash="
                    + protx.GetHex().substr(0, 16);
                return false;
            }
            if (by_id.find(st.internalId) != by_id.end()) {
                err = "can't add a masternode with a duplicate internalId="
                    + std::to_string(st.internalId);
                return false;
            }
            if (!collaterals.emplace(st.collateralOutpoint.hash,
                                     st.collateralOutpoint.index).second) {
                err = "can't add a masternode with a duplicate "
                      "collateralOutpoint (proTxHash="
                    + protx.GetHex().substr(0, 16) + ")";
                return false;
            }
            by_id[st.internalId] = protx;
            list.emplace(protx, st);
        }
        for (const auto& [id, sd] : updated) {
            auto it = by_id.find(id);
            if (it == by_id.end()) {
                err = "can't find an updated masternode, id=" + std::to_string(id);
                return false;
            }
            sd.apply_to(list.at(it->second));
        }
        return true;
    }

    void write_to(::PackStream& s) const
    {
        WriteCompactSize(s, added.size());
        for (const auto& [protx, st] : added) {
            s << protx;
            s << st;
        }
        WriteCompactSize(s, updated.size());
        for (const auto& [id, sd] : updated) {
            WriteCompactSize(s, id);
            sd.write_to(s);
        }
        WriteCompactSize(s, removed.size());
        for (uint64_t id : removed) WriteCompactSize(s, id);
    }

    void read_from(::PackStream& s)
    {
        added.clear(); updated.clear(); removed.clear();
        const uint64_t na = ReadCompactSize(s);
        for (uint64_t i = 0; i < na; ++i) {
            uint256 protx;
            ReplayMNState st;
            s >> protx >> st;
            added.emplace_back(protx, std::move(st));
        }
        const uint64_t nu = ReadCompactSize(s);
        for (uint64_t i = 0; i < nu; ++i) {
            const uint64_t id = ReadCompactSize(s);
            MnStateDiff sd;
            sd.read_from(s);
            if (!updated.emplace(id, std::move(sd)).second)
                throw std::ios_base::failure("MnListDiff: duplicate updated id");
        }
        const uint64_t nr = ReadCompactSize(s);
        for (uint64_t i = 0; i < nr; ++i) {
            if (!removed.insert(ReadCompactSize(s)).second)
                throw std::ios_base::failure("MnListDiff: duplicate removed id");
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// MnDiffRecord — the 'D' row value
// ═══════════════════════════════════════════════════════════════════════════
/// One per folded block, keyed by that block's hash. Carries what dashd's row
/// does NOT need to carry (see the header's divergence list): prev_hash for
/// a CBlockIndex-free walk, the block's own committed merkleRootMNList, the
/// proof flags of the fold that produced it, and a sha256d trailer
/// (MnBridgeCursorStore digest posture — refuse-whole-record on mismatch).
/// NO height field — the walker stamps height from the header-chain walk
/// (dashd cpp:697,:822 rule, kept verbatim).
struct MnDiffRecord
{
    static constexpr uint8_t kVersion           = 1;
    static constexpr uint8_t kFlagRootMatched   = 0x01;
    static constexpr uint8_t kFlagPayeeVerified = 0x02;

    uint8_t    record_version{kVersion};
    uint256    prev_hash;
    uint256    merkle_root_mn_list;   // committed root from THIS block's CbTx
    uint8_t    flags{0};
    /// POST-block totalRegisteredCount — makes internalId assignment
    /// restart-reproducible across a repair reseed. u64 mirroring the
    /// engine's counter (the plan sketched u32; truncating a monotonic id
    /// source is exactly the kind of silent wrap this store must not have).
    uint64_t   total_registered_count{0};
    MnListDiff diff;

    bool root_matched() const   { return (flags & kFlagRootMatched) != 0; }
    bool payee_verified() const { return (flags & kFlagPayeeVerified) != 0; }

    std::vector<uint8_t> encode() const
    {
        ::PackStream s;
        s << record_version;
        s << prev_hash;
        s << merkle_root_mn_list;
        s << flags;
        s << total_registered_count;
        diff.write_to(s);
        auto sp = s.get_span();
        uint256 digest;
        CHash256()
            .Write(std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
            .Finalize(std::span<unsigned char>(digest.data(), 32));
        s << digest;
        auto full = s.get_span();
        return std::vector<uint8_t>(
            reinterpret_cast<const uint8_t*>(full.data()),
            reinterpret_cast<const uint8_t*>(full.data()) + full.size());
    }

    /// Fail-closed decode: digest first, then version, then payload; any
    /// trailing bytes refuse. On false the out-param is unspecified.
    static bool decode(const std::vector<uint8_t>& bytes, MnDiffRecord& out,
                       std::string& err)
    {
        err.clear();
        if (bytes.size() < 1 + 32 + 32 + 1 + 8 + 3 + 32) {
            err = "diff record too short (" + std::to_string(bytes.size())
                + " bytes)";
            return false;
        }
        const size_t payload_len = bytes.size() - 32;
        uint256 want, got;
        std::memcpy(want.data(), bytes.data() + payload_len, 32);
        CHash256()
            .Write(std::span<const unsigned char>(bytes.data(), payload_len))
            .Finalize(std::span<unsigned char>(got.data(), 32));
        if (want != got) {
            err = "diff record digest mismatch — corrupted or truncated";
            return false;
        }
        try {
            std::vector<uint8_t> payload(bytes.begin(),
                                         bytes.begin() + payload_len);
            ::PackStream s(payload);
            s >> out.record_version;
            if (out.record_version != kVersion) {
                err = "diff record version " + std::to_string(out.record_version)
                    + " != supported " + std::to_string(kVersion);
                return false;
            }
            s >> out.prev_hash;
            s >> out.merkle_root_mn_list;
            s >> out.flags;
            s >> out.total_registered_count;
            out.diff.read_from(s);
            if (!s.empty()) {
                err = "diff record carries trailing bytes — format drift";
                return false;
            }
            return true;
        } catch (const std::exception& ex) {
            err = std::string("diff record deserialize failed: ") + ex.what();
            return false;
        }
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// MnDiffStore — the LevelDB store + the reconstruct walk
// ═══════════════════════════════════════════════════════════════════════════
class MnDiffStore
{
public:
    /// dashd DISK_SNAPSHOT_PERIOD (evo/deterministicmns.cpp:690), verbatim.
    static constexpr uint32_t kSnapshotPeriod = 576;
    /// Store format version ('F'). Mismatch clears the WHOLE store — the
    /// MnStateDb open() idiom (mn_state_db.hpp:207-230), never per-entry
    /// migration.
    static constexpr uint32_t kFormatVersion = 1;

    /// PoW-validated header-chain lookup: hash -> (height, prev_hash).
    /// nullopt = the hash is not on OUR chain; the walk refuses. The record's
    /// own prev_hash is cross-checked against this at EVERY hop — the record
    /// is self-spanning but never trusted alone.
    using HeaderLookupFn = std::function<
        std::optional<std::pair<uint32_t, uint256>>(const uint256& hash)>;

    explicit MnDiffStore(const std::string& db_path,
                         const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()
    {
        if (!m_store.open()) return false;
        const uint32_t stored = load_u32(make_format_key());
        if (stored != kFormatVersion) {
            if (stored != 0 || !m_store.list_keys("D", /*limit=*/1).empty()
                || !m_store.list_keys("S", /*limit=*/1).empty()) {
                LOG_INFO << "[MN-DIFF-DB] format v" << stored << " -> v"
                         << kFormatVersion
                         << ": clearing WHOLE store (dmn_D3->D4 idiom — "
                            "never per-entry migration); the live fold "
                            "repopulates it";
                if (!clear()) return false;
            }
            store_u32(make_format_key(), kFormatVersion);
        }
        load_best();
        LOG_INFO << "[MN-DIFF-DB] opened best_height=" << m_best_height
                 << " best_hash=" << m_best_hash.GetHex().substr(0, 16);
        return true;
    }

    void close()        { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    uint256  best_hash() const   { return m_best_hash; }
    uint32_t best_height() const { return m_best_height; }

    /// One folded block = one atomic batch: 'D' (+ optionally 'S') + 'B',
    /// force-synced — money-path rows must survive a host blackout
    /// (LevelDBOptions.sync_writes defaults false; HeaderBackfill precedent).
    /// Mirrors dashd writing DB_LIST_DIFF and DB_LIST_SNAPSHOT inside the
    /// same connect (deterministicmns.cpp:689-694) with EVODB_BEST_BLOCK
    /// discipline (validation.cpp:2322).
    bool put_block(const uint256& block_hash, uint32_t height,
                   const MnDiffRecord& rec,
                   const std::vector<uint8_t>* snapshot_bytes)
    {
        if (!m_store.is_open()) return false;
        auto batch = m_store.create_batch();
        batch.put(make_key('D', block_hash), rec.encode());
        if (snapshot_bytes)
            batch.put(make_key('S', block_hash), *snapshot_bytes);
        batch.put(make_best_key(), encode_best(block_hash, height));
        if (!batch.commit_sync()) {
            LOG_WARNING << "[MN-DIFF-DB] put_block batch commit failed at h="
                        << height;
            return false;
        }
        m_best_hash   = block_hash;
        m_best_height = height;
        return true;
    }

    /// Standalone snapshot write (the SEED/anchor snapshot — dashd's "extra
    /// snapshot after the initial-snapshot block", cpp:690-691 second
    /// disjunct). The seed snapshot is what grounds every backward walk: our
    /// inversion demands an explicit stored snapshot, never "row absent".
    bool put_snapshot(const uint256& block_hash,
                      const std::vector<uint8_t>& snapshot_bytes)
    {
        if (!m_store.is_open()) return false;
        auto batch = m_store.create_batch();
        batch.put(make_key('S', block_hash), snapshot_bytes);
        return batch.commit_sync();
    }

    bool get_diff(const uint256& block_hash, MnDiffRecord& out,
                  std::string& err)
    {
        std::vector<uint8_t> bytes;
        if (!m_store.get(make_key('D', block_hash), bytes)) {
            err = "no diff record for block "
                + block_hash.GetHex().substr(0, 16);
            return false;
        }
        return MnDiffRecord::decode(bytes, out, err);
    }

    bool has_diff(const uint256& block_hash)
    {
        return m_store.exists(make_key('D', block_hash));
    }

    bool has_snapshot(const uint256& block_hash)
    {
        return m_store.exists(make_key('S', block_hash));
    }

    bool get_snapshot(const uint256& block_hash, std::vector<uint8_t>& out)
    {
        return m_store.get(make_key('S', block_hash), out);
    }

    /// Every stored snapshot hash. Streaming (for_each_prefix) — list_keys
    /// is capped at its limit param and a 576/day store blows past any cap
    /// silently. A false return is fail-closed at the caller.
    bool for_each_snapshot_hash(const std::function<bool(const uint256&)>& fn)
    {
        return m_store.for_each_prefix("S",
            [&](const std::string& key, const std::vector<uint8_t>&) {
                if (key.size() != 33) return true;   // not ours; skip
                uint256 h;
                std::memcpy(h.data(), key.data() + 1, 32);
                return fn(h);
            });
    }

    bool clear()
    {
        // Streaming enumerate + batched remove; list_keys' cap would leave
        // rows behind silently on a store this write rate fills.
        std::vector<std::string> keys;
        if (!m_store.for_each_prefix("",
                [&](const std::string& k, const std::vector<uint8_t>&) {
                    keys.push_back(k);
                    return true;
                }))
            return false;
        auto batch = m_store.create_batch();
        for (const auto& k : keys) batch.remove(k);
        if (!batch.commit_sync()) return false;
        m_best_hash   = uint256{};
        m_best_height = 0;
        LOG_INFO << "[MN-DIFF-DB] cleared (" << keys.size() << " rows)";
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────
    // reconstruct — dashd GetListForBlockInternal (deterministicmns.cpp:
    // 778-870) as a COLD repair path: backward hash-walk to the nearest
    // snapshot, forward replay of the stored diffs, then verify.
    // ─────────────────────────────────────────────────────────────────────
    /// On success `out`/`out_total_registered` are the list AT `target_hash`
    /// and the DIP-4 root of `out` equals the merkleRootMNList that block's
    /// own cbTx committed. Refusals (false + err) are TOTAL — never a
    /// partial list, never an empty-list default:
    ///   * target not on our header chain
    ///   * any missing 'D' or 'S' row on the path      (THE inversion:
    ///     dashd's "initial empty list" default, cpp:813-819, is unsound
    ///     for a P2P-fed store)
    ///   * record digest / version mismatch
    ///   * record prev_hash != the header chain's prev at that hop
    ///   * walk depth > kSnapshotPeriod
    ///   * any record on the path missing root_matched OR payee_verified —
    ///     merkleRootMNList does not commit nLastPaidHeight (G9 semantics),
    ///     so an unverified diff's queue-order claim is unprovable and
    ///     poisons the whole range
    ///   * any apply refusal (internalId miss, duplicate unique property)
    ///   * final recomputed SML root != the committed root at target
    ///
    /// `skip_snapshot_at_target`: the startup pair-verify grounds the walk
    /// one snapshot EARLIER so the newest snapshot is re-derived instead of
    /// read (RecalculateAndRepairDiffs' VerifySnapshotPair analogue,
    /// cpp:1130-1419, reduced to the newest pair).
    bool reconstruct(const uint256& target_hash,
                     const HeaderLookupFn& header_lookup,
                     DmlFoldEngine::Entries& out,
                     uint64_t& out_total_registered,
                     std::string& err,
                     bool skip_snapshot_at_target = false)
    {
        err.clear();
        out.clear();
        out_total_registered = 0;
        if (!m_store.is_open()) { err = "diff store is not open"; return false; }
        if (!header_lookup)     { err = "no header-chain lookup wired"; return false; }

        // ── Backward walk (cpp:790-829, hash-keyed, CBlockIndex-free) ────
        std::vector<std::pair<uint256, MnDiffRecord>> path; // newest→oldest
        DmlFoldEngine base{FoldConfig{}};   // snapshot codec host, folds nothing
        uint256 cur = target_hash;
        for (;;) {
            const auto hdr = header_lookup(cur);
            if (!hdr) {
                err = "block " + cur.GetHex().substr(0, 16)
                    + " is not on our PoW-validated header chain — REFUSED";
                return false;
            }
            const bool skip_snap =
                skip_snapshot_at_target && cur == target_hash;
            if (!skip_snap && has_snapshot(cur)) {
                std::vector<uint8_t> bytes;
                if (!get_snapshot(cur, bytes)) {
                    err = "snapshot row for " + cur.GetHex().substr(0, 16)
                        + " vanished between exists() and get() — REFUSED";
                    return false;
                }
                std::string serr;
                if (!base.load_snapshot(bytes, serr)) {
                    err = "stored snapshot at " + cur.GetHex().substr(0, 16)
                        + " failed to load: " + serr;
                    return false;
                }
                if (base.block_hash() != cur) {
                    err = "stored snapshot at " + cur.GetHex().substr(0, 16)
                        + " claims block " + base.block_hash().GetHex().substr(0, 16)
                        + " — key/payload divergence, REFUSED";
                    return false;
                }
                break;
            }
            // ── THE FAIL-CLOSED INVERSION. dashd (cpp:813-819) treats "no
            // snapshot AND no diff" as the initial EMPTY list — sound only
            // when the write is consensus-atomic with connect. Ours is fed
            // by a P2P fold that CAN transiently miss rows: a missing row
            // is a GAP WE CANNOT REPAIR, never an empty list.
            MnDiffRecord rec;
            std::string derr;
            if (!get_diff(cur, rec, derr)) {
                err = "walk broken at " + cur.GetHex().substr(0, 16) + ": "
                    + derr + " — a missing row is REPAIR-REFUSED, never an "
                      "empty list (fail-closed inversion of dashd's initial-"
                      "snapshot default)";
                return false;
            }
            // Self-spanning but never trusted alone: the record's prev must
            // BE the header chain's prev at this hop.
            if (rec.prev_hash != hdr->second) {
                err = "record prev_hash "
                    + rec.prev_hash.GetHex().substr(0, 16)
                    + " != header-chain prev "
                    + hdr->second.GetHex().substr(0, 16) + " at "
                    + cur.GetHex().substr(0, 16) + " — REFUSED";
                return false;
            }
            // Whole-range proof-flag requirement (G9 semantics): a block
            // whose payee the engine could not verify poisons the range.
            if (!rec.root_matched() || !rec.payee_verified()) {
                err = "record at " + cur.GetHex().substr(0, 16)
                    + " lacks proof flags (root_matched="
                    + std::to_string(rec.root_matched())
                    + " payee_verified=" + std::to_string(rec.payee_verified())
                    + ") — merkleRootMNList does not commit nLastPaidHeight, "
                      "so an unverified diff cannot back a payment queue; "
                      "REFUSED";
                return false;
            }
            path.emplace_back(cur, std::move(rec));
            if (path.size() > kSnapshotPeriod) {
                err = "walk exceeded " + std::to_string(kSnapshotPeriod)
                    + " diffs without hitting a snapshot — REFUSED";
                return false;
            }
            cur = path.back().second.prev_hash;
        }

        // ── Forward replay, oldest-first (cpp:846-848) ───────────────────
        out                  = base.entries();
        out_total_registered = base.total_registered_count();
        for (auto it = path.rbegin(); it != path.rend(); ++it) {
            std::string aerr;
            if (!it->second.diff.apply(out, aerr)) {
                out.clear();
                err = "diff apply REFUSED at " + it->first.GetHex().substr(0, 16)
                    + ": " + aerr + " — diff applied to a list that is not "
                      "its true parent";
                return false;
            }
            out_total_registered = it->second.total_registered_count;
        }

        // ── Verify before trusting: DIP-4 SML root vs the committed root
        // at target. This proves the SET; the ORDER (nLastPaidHeight) is
        // licensed transitively by payee_verified on every constituent diff
        // (checked above). Note the SML entry commits isValid, so consensus
        // PoSe bans/revives inside the range ARE under this root.
        uint256 committed;
        if (!path.empty()) {
            committed = path.front().second.merkle_root_mn_list;
        } else {
            // target IS the grounding snapshot. Prefer its own 'D' record's
            // committed root when present; a seed-anchor snapshot without a
            // 'D' row is digest-pinned and was written only after the
            // engine's own root match — accepted on that license.
            MnDiffRecord rec;
            std::string derr;
            if (get_diff(target_hash, rec, derr)) {
                committed = rec.merkle_root_mn_list;
            } else {
                return true;
            }
        }
        std::vector<vendor::CSimplifiedMNListEntry> ents;
        ents.reserve(out.size());
        for (const auto& [protx, st] : out)
            ents.push_back(st.to_sml_entry(protx));
        vendor::CSimplifiedMNList sml(std::move(ents));
        const uint256 got = sml.CalcMerkleRoot();
        if (got != committed) {
            out.clear();
            err = "reconstructed list re-hashes to " + got.GetHex()
                + " but block " + target_hash.GetHex().substr(0, 16)
                + " committed " + committed.GetHex()
                + " — REFUSED (verify-then-trust)";
            return false;
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Startup verify — dashd VerifyBestBlock + VerifySnapshotPair, reduced
    // ─────────────────────────────────────────────────────────────────────
    /// Two checks, wipe-ALONE-and-repopulate on failure (our "reindex" is
    /// cheap: the store is an accelerator, not consensus-required — its
    /// absence degrades to today's wipe/demote floor):
    ///   1. 'B' sentinel cross-check (validation.cpp:2322/:2707 posture):
    ///      the last-written 'D' row must exist and decode.
    ///   2. Newest-pair verify (RecalculateAndRepairDiffs /
    ///      VerifySnapshotPair, cpp:1130-1419, scope-reduced to the NEWEST
    ///      pair): re-derive the newest snapshot from the previous one via
    ///      the stored diffs and require the reconstruction to succeed —
    ///      which includes the SML-root equality at the newest snapshot's
    ///      block. Verify-then-wipe, never verify-then-patch (dashd
    ///      rebuilds diffs from raw blocks; we store no raw blocks).
    /// Returns true when the store is usable (possibly after a wipe, which
    /// is reported through `note`).
    bool startup_verify(const HeaderLookupFn& header_lookup, std::string& note)
    {
        note.clear();
        if (!m_store.is_open()) { note = "store not open"; return false; }

        // (1) 'B' sentinel vs the rows it promises.
        if (!m_best_hash.IsNull()) {
            MnDiffRecord rec;
            std::string derr;
            if (!get_diff(m_best_hash, rec, derr)) {
                note = "best-block sentinel names "
                     + m_best_hash.GetHex().substr(0, 16)
                     + " but its diff row is unusable (" + derr
                     + ") — wiping store, live fold repopulates";
                clear();
                store_u32(make_format_key(), kFormatVersion);
                return true;
            }
        }

        // (2) newest snapshot pair, dated via the header chain (orphaned
        // snapshots simply do not date and are skipped — hash-keyed rows
        // for dead branches are harmless residue, cpp:736-769 posture).
        if (!header_lookup) return true;
        uint32_t best_h = 0, second_h = 0;
        uint256  best, second;
        bool have_best = false, have_second = false;
        const bool scan_ok = for_each_snapshot_hash([&](const uint256& h) {
            const auto e = header_lookup(h);
            if (!e) return true;
            if (!have_best || e->first > best_h) {
                second_h = best_h; second = best; have_second = have_best;
                best_h = e->first; best = h; have_best = true;
            } else if (!have_second || e->first > second_h) {
                second_h = e->first; second = h; have_second = true;
            }
            return true;
        });
        if (!scan_ok) {
            note = "snapshot enumeration failed (store/iterator error) — "
                   "wiping store, live fold repopulates";
            clear();
            store_u32(make_format_key(), kFormatVersion);
            return true;
        }
        if (!have_best || !have_second) return true;   // <2 dated: nothing to pair-verify

        DmlFoldEngine::Entries reconstructed;
        uint64_t trc = 0;
        std::string rerr;
        if (!reconstruct(best, header_lookup, reconstructed, trc, rerr,
                         /*skip_snapshot_at_target=*/true)) {
            note = "newest snapshot pair FAILED verify (h="
                 + std::to_string(second_h) + "->" + std::to_string(best_h)
                 + "): " + rerr + " — wiping store, live fold repopulates";
            clear();
            store_u32(make_format_key(), kFormatVersion);
            return true;
        }
        // Reconstruction reaching the ROOT equality at `best` already proves
        // the pair agrees on every SML-committed field; compare the stored
        // snapshot's full entries too (stricter than dashd's IsEqual — our
        // diffs carry internalId explicitly, so full equality must hold).
        std::vector<uint8_t> bytes;
        DmlFoldEngine snap{FoldConfig{}};
        std::string serr;
        if (!get_snapshot(best, bytes) || !snap.load_snapshot(bytes, serr)) {
            note = "newest snapshot unreadable after pair walk (" + serr
                 + ") — wiping store, live fold repopulates";
            clear();
            store_u32(make_format_key(), kFormatVersion);
            return true;
        }
        if (!(snap.entries() == reconstructed)
            || snap.total_registered_count() != trc) {
            note = "newest snapshot pair DISAGREES beyond the root (entry or "
                   "counter drift) — wiping store, live fold repopulates";
            clear();
            store_u32(make_format_key(), kFormatVersion);
            return true;
        }
        note = "newest snapshot pair verified (h=" + std::to_string(second_h)
             + "->" + std::to_string(best_h) + ", "
             + std::to_string(reconstructed.size()) + " MNs)";
        return true;
    }

private:
    ::core::LevelDBStore m_store;
    uint256              m_best_hash;
    uint32_t             m_best_height{0};

    static std::string make_key(char prefix, const uint256& hash)
    {
        std::string k;
        k.reserve(33);
        k.push_back(prefix);
        k.append(reinterpret_cast<const char*>(hash.data()), 32);
        return k;
    }
    static std::string make_best_key()   { return std::string(1, 'B'); }
    static std::string make_format_key() { return std::string(1, 'F'); }

    uint32_t load_u32(const std::string& key)
    {
        std::vector<uint8_t> d;
        if (!m_store.get(key, d) || d.size() < 4) return 0;
        return uint32_t(d[0]) | (uint32_t(d[1]) << 8)
             | (uint32_t(d[2]) << 16) | (uint32_t(d[3]) << 24);
    }

    void store_u32(const std::string& key, uint32_t v)
    {
        std::vector<uint8_t> d(4);
        d[0] = uint8_t(v); d[1] = uint8_t(v >> 8);
        d[2] = uint8_t(v >> 16); d[3] = uint8_t(v >> 24);
        m_store.put(key, d);
    }

    static std::vector<uint8_t> encode_best(const uint256& hash, uint32_t h)
    {
        std::vector<uint8_t> d(36);
        std::memcpy(d.data(), hash.data(), 32);
        d[32] = uint8_t(h); d[33] = uint8_t(h >> 8);
        d[34] = uint8_t(h >> 16); d[35] = uint8_t(h >> 24);
        return d;
    }

    void load_best()
    {
        std::vector<uint8_t> d;
        if (!m_store.get(make_best_key(), d) || d.size() < 36) return;
        std::memcpy(m_best_hash.data(), d.data(), 32);
        m_best_height = uint32_t(d[32]) | (uint32_t(d[33]) << 8)
                      | (uint32_t(d[34]) << 16) | (uint32_t(d[35]) << 24);
    }
};

// ═══════════════════════════════════════════════════════════════════════════
// MnDiffWriter — the write side (dashd ProcessBlock's store write, cpp:689)
// ═══════════════════════════════════════════════════════════════════════════
/// Hooks the fold consumer's per-block commit AFTER the root match succeeded
/// (the only path that calls on_folded). Only the ENGINE produces records —
/// the maintainer's live MnStateMachine path writes nothing (it holds
/// neither ReplayMNState nor the roots).
///
/// Keeps a copy of the previous block's entries so BuildDiff has its
/// oldList; dashd gets that for free from its COW lists
/// (GetListForBlockInternal(pindex->pprev), cpp:689).
class MnDiffWriter
{
public:
    MnDiffWriter(MnDiffStore& store, const DmlFoldEngine& engine)
        : m_store(store), m_engine(engine) {}

    /// Arm at the engine's CURRENT (seeded) cursor: writes the seed/anchor
    /// snapshot — dashd's extra snapshot at the initial-snapshot block
    /// (cpp:690-691). Our backward walk must ground on an explicit stored
    /// snapshot, never on "row absent", so this is what makes the very
    /// first repair possible.
    bool arm()
    {
        if (m_engine.block_hash().IsNull() || m_engine.size() == 0) {
            LOG_WARNING << "[MN-DIFF-DB] writer NOT armed: engine has no "
                           "seeded state";
            return false;
        }
        const auto bytes = m_engine.save_snapshot();
        if (!m_store.put_snapshot(m_engine.block_hash(), bytes)) {
            LOG_WARNING << "[MN-DIFF-DB] writer NOT armed: seed snapshot "
                           "write failed";
            return false;
        }
        m_prev     = m_engine.entries();
        m_prev_trc = m_engine.total_registered_count();
        m_armed    = true;
        LOG_INFO << "[MN-DIFF-DB] writer ARMED: seed snapshot at h="
                 << m_engine.height() << " block "
                 << m_engine.block_hash().GetHex().substr(0, 16)
                 << " mns=" << m_engine.size();
        return true;
    }

    bool armed() const { return m_armed; }

    /// Called by the fold consumer for every block whose fold COMPLETED
    /// (root self-check passed — fold_block only returns ok on equality).
    /// Written UNCONDITIONALLY, even when the diff is empty: the empty
    /// record is proof-of-processing (dashd gotcha, kept verbatim).
    void on_folded(uint32_t height, const uint256& block_hash,
                   const dash::coin::BlockType& block, const FoldResult& r)
    {
        if (!m_armed) return;
        // The engine's cursor must BE the height just folded — a mismatch
        // means this writer's oldList is not the true parent, and a wrong
        // parent produces a wrong diff. Disarm; a disarmed writer leaves a
        // missing row, which every reader REFUSES on (fail-closed).
        if (m_engine.height() != height) {
            LOG_WARNING << "[MN-DIFF-DB] writer DISARMED at h=" << height
                        << ": engine cursor h=" << m_engine.height()
                        << " is not the folded height — refusing to write a "
                           "diff off a wrong parent";
            m_armed = false;
            return;
        }
        MnDiffRecord rec;
        rec.prev_hash           = block.m_previous_block;
        rec.merkle_root_mn_list = r.committed_root;
        rec.flags               = MnDiffRecord::kFlagRootMatched;
        if (r.payee_paid_verified)
            rec.flags |= MnDiffRecord::kFlagPayeeVerified;
        rec.total_registered_count = m_engine.total_registered_count();
        rec.diff = MnListDiff::build(m_prev, m_engine.entries());

        // Snapshot cadence: height % 576 == 0 (DISK_SNAPSHOT_PERIOD,
        // cpp:690). The seed snapshot was written by arm().
        std::vector<uint8_t> snap;
        const bool want_snap = (height % MnDiffStore::kSnapshotPeriod) == 0;
        if (want_snap) snap = m_engine.save_snapshot();

        if (!m_store.put_block(block_hash, height, rec,
                               want_snap ? &snap : nullptr)) {
            LOG_WARNING << "[MN-DIFF-DB] write failed at h=" << height
                        << " — writer DISARMED (a hole in the store refuses "
                           "at read time; it never fakes continuity)";
            m_armed = false;
            return;
        }
        ++m_written;
        if (want_snap) ++m_snapshots;
        m_prev     = m_engine.entries();
        m_prev_trc = m_engine.total_registered_count();
    }

    uint64_t written()   const { return m_written; }
    uint64_t snapshots() const { return m_snapshots; }

private:
    MnDiffStore&           m_store;
    const DmlFoldEngine&   m_engine;
    DmlFoldEngine::Entries m_prev;
    uint64_t               m_prev_trc{0};
    bool                   m_armed{false};
    uint64_t               m_written{0};
    uint64_t               m_snapshots{0};
};

} // namespace replay
} // namespace coin
} // namespace dash
