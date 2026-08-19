// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// W1 of the DASH FULL-HISTORY REPLAY mode (the/docs/
/// DASH_FULL_HISTORY_REPLAY_MODE.md §3, §4.5, §6): the DML fold engine +
/// versioned full-state snapshot.
///
/// This is a NEW, feature-gated engine — it is wired into NOTHING. The serve
/// path, the projection (mn_state_machine.hpp), the checkpoint lane and every
/// existing gate are untouched; W5 does the source inversion. Until then the
/// only callers are the KATs and whatever future work package takes it up.
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHAT THIS IS
/// ─────────────────────────────────────────────────────────────────────────
/// A per-block fold of the deterministic masternode list, transcribed from
/// dashd v23.1.x `CSpecialTxProcessor::RebuildListFromBlock`
/// (evo/specialtxman.cpp:185-520) with the field semantics of
/// `CDeterministicMNState` (evo/dmnstate.h) — the *validator's* picture of
/// the DML, derived from chain bytes, instead of the projection stitched
/// from wire snapshots that produced the 2026-08-05 divergence incidents
/// (h=2516595 bad-cb-payee operator split; h=2516756 merkleRootMNList
/// SERVED-MISMATCH; 2516412/2516435 PoSe case-D refusals).
///
/// Fold order per block, dashd-exact (§3 of the design doc):
///
///   0. payee = GetMNPayee(list@H−1)      — computed BEFORE any mutation
///   1. confirmedHash pass                — (H−1)−nRegisteredHeight ≥ 15 ⇒
///                                          confirmedHash = hash(H−1),
///                                          confirmedHashWithProRegTxHash =
///                                          SHA256(proTxHash‖confirmedHash)
///                                          (SINGLE sha256, dmnstate.h:141)
///   2. DecreaseScores                    — every non-banned MN with
///                                          nPoSePenalty > 0 decrements by 1
///   3. per-tx pass over vtx[1..]:
///        type 1 ProRegTx                 — internalId = totalRegisteredCount++,
///                                          collateral resolution (null hash →
///                                          own output), collateral-replacement
///                                          removal, state from payload,
///                                          nRegisteredHeight = H, EMPTY
///                                          netInfo ⇒ registers BANNED
///        type 2 ProUpServTx              — netInfo + scriptOperatorPayout +
///                                          platform fields; banned && all
///                                          keys set ⇒ Revive(H) (the
///                                          h=2516756 event)
///        type 3 ProUpRegTx               — voting key + scriptPayout;
///                                          operator-key change ⇒
///                                          ResetOperatorFields + ban
///        type 4 ProUpRevTx               — ResetOperatorFields + ban +
///                                          nRevocationReason
///        type 6 qfcommit                 — per invalid-marked member of a
///                                          mined non-null commitment:
///                                          PoSePunish(CalcPenalty(66));
///                                          crossing CalcMaxPoSePenalty ⇒ ban
///   4. collateral-spend scan             — any vin spending a tracked
///                                          collateral outpoint removes the MN
///   5. payee bookkeeping                 — nLastPaidHeight = H on the pass-0
///                                          payee (if still present); EvoNode
///                                          nConsecutivePayments bump/reset
///
/// ─────────────────────────────────────────────────────────────────────────
/// THE SELF-CHECK (design doc §4.2 layer 3 — the property that makes replay
/// checkable against consensus at EVERY block)
/// ─────────────────────────────────────────────────────────────────────────
/// After each fold the engine computes the DIP-4 merkleRootMNList of the
/// folded list and compares it against the root COMMITTED IN THE BLOCK'S OWN
/// cbTx. Every mainnet block since DIP3 carries this answer key. A mismatch
/// is a HARD STOP: the fold names the height and both roots, poisons itself,
/// and refuses every further fold — a wrong fold rule, a corrupted body or a
/// wrong seed desyncs AT the block where it happens, never silently.
///
/// Coverage honesty (§4.2): the committed root proves the SML-serialized
/// fields (confirmedHash, keys, netInfo, isValid, type). nPoSePenalty,
/// nLastPaidHeight, payout scripts, nOperatorReward and the height fields are
/// NOT under the root; they are falsified behaviorally (a wrong penalty model
/// flips isValid within one DKG cycle; a wrong payee model trips the payee
/// cross-check within one payment cycle — both land in the root / coinbase of
/// later blocks).
///
/// ─────────────────────────────────────────────────────────────────────────
/// WHAT THE FOLD DELIBERATELY SKIPS, AND WHY THAT IS SAFE (§4.2)
/// ─────────────────────────────────────────────────────────────────────────
/// No script execution, no UTXO set, no signature checks: every UTXO/script
/// read on dashd's special-tx surface is an ACCEPTANCE PREDICATE — it can
/// only reject a block, never alter what an accepted block folds to. A
/// replay over blocks the network accepted skips only checks those blocks
/// passed. The collateral-spend removal needs no UTXO set either: it is a
/// pure vin-vs-known-outpoint scan (specialtxman.cpp:464-482).
///
/// Unlike the projection's tolerant parsing (mn_state_machine skips
/// unparseable ProTx payloads), the fold FAILS CLOSED on any special-tx
/// payload it cannot parse: replay claims byte-exactness, and a skipped
/// mutation is a silent desync that the root check would attribute to the
/// wrong cause. Same posture for ExtAddr (ProTx nVersion ≥ 3):
/// DEPLOYMENT_V24 is NEVER_ACTIVE on mainnet (chainparams.cpp:212-214); the
/// branch is unimplemented and the fold refuses rather than drifts.
///
/// ─────────────────────────────────────────────────────────────────────────
/// SNAPSHOT FORMAT v3 (full state — versioned, digest-pinned)
/// ─────────────────────────────────────────────────────────────────────────
/// Version lineage, so the number means something:
///   v1 — `c2pool-dash-mn-checkpoint/1` (mn_checkpoint.hpp): the release
///        payee-state anchor. OMITS confirmedHash / netInfo / nPoSePenalty /
///        internalId — insufficient to compute the SML root or fold
///        penalties (design doc §4.5).
///   v2 — MnStateDb store schema (mn_state_db.hpp kFormatVersion = 2):
///        projection persistence, same field gaps.
///   v3 — THIS: the full `CDeterministicMNList`-equivalent state. Binary,
///        magic + version header (an old binary fails LOUD on either),
///        SHA256d digest trailer over the payload (truncation / corruption
///        fails loud), resume cursor (height + block hash +
///        totalRegisteredCount) included.
///
/// Layout (PackStream, all integers LE):
///   bytes[24]  magic  "C2POOL-DASH-DML-SNAP/v03"
///   u32        version                  == 3
///   string     network                  ("mainnet" / "testnet" / ...)
///   u32        height                   fold cursor: state is AT this height
///   uint256    block_hash               chain block hash at `height`
///   u64        total_registered_count   internalId source for the next AddMN
///   u64        count
///   count ×    { uint256 proTxHash, ReplayMNState }
///   uint256    sha256d over every preceding byte
///
/// Trust posture: a v3 snapshot is the SAME trust class as the v1 checkpoint
/// (assumevalid-for-MN-state) but far better checked — the per-block root
/// self-check validates its SML-committed fields against consensus at
/// anchor+1, so a wrong anchor desyncs in ONE block (§4.5 Phase 1). Phase 2
/// (genesis replay, W2/W4/W5) retires the anchor entirely.

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/vendor/simplifiedmns.hpp>
#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/opscript.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <functional>
#include <limits>
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

// Strict weak ordering for the internal collateral index (uint256 CompareTo +
// index). INTERNAL only — never compared against dashd wire data. Mirrors
// mn_state_machine.hpp's TxPrevOutLess.
struct ReplayOutpointLess {
    bool operator()(const bitcoin_family::coin::TxPrevOut& a,
                    const bitcoin_family::coin::TxPrevOut& b) const
    {
        if (a.hash != b.hash) return a.hash < b.hash;
        return a.index < b.index;
    }
};

/// Full per-MN state, mirroring dashd `CDeterministicMN` +
/// `CDeterministicMNState` field-for-field for everything the fold reads or
/// writes. Height fields use dashd's SIGNED int semantics with the -1
/// "never" sentinel VERBATIM (nPoSeBanHeight == -1 ⇔ not banned ⇔
/// SML isValid) — NOT the projection's uint32/0 convention, whose
/// UINT32_MAX-sentinel repair (mn_state_machine.hpp payee_score) exists
/// precisely because the conventions were mixed once before.
struct ReplayMNState
{
    static constexpr int32_t NEVER = -1;

    // ── CDeterministicMN level (immutable after registration) ────────────
    uint16_t                                     nType{vendor::MnType::REGULAR};
    uint64_t                                     internalId{0};
    bitcoin_family::coin::TxPrevOut              collateralOutpoint;
    uint16_t                                     nOperatorReward{0};

    // ── CDeterministicMNState ────────────────────────────────────────────
    uint16_t                                     nVersion{vendor::ProTxVersion::LEGACY_BLS};
    int32_t                                      nRegisteredHeight{NEVER};
    int32_t                                      nLastPaidHeight{0};
    int32_t                                      nConsecutivePayments{0};
    int32_t                                      nPoSePenalty{0};
    int32_t                                      nPoSeRevivedHeight{NEVER};
    int32_t                                      nPoSeBanHeight{NEVER};
    uint16_t                                     nRevocationReason{vendor::CProUpRevTx::REASON_NOT_SPECIFIED};
    uint256                                      confirmedHash;
    uint256                                      confirmedHashWithProRegTxHash;
    uint160                                      keyIDOwner;
    std::array<uint8_t, vendor::BLS_PUBKEY_SIZE> pubKeyOperator{};
    uint160                                      keyIDVoting;
    vendor::LegacyNetService                     netInfo;
    OPScript                                     scriptPayout;
    OPScript                                     scriptOperatorPayout;
    uint160                                      platformNodeID;
    uint16_t                                     platformP2PPort{0};
    uint16_t                                     platformHTTPPort{0};

    bool IsBanned() const { return nPoSeBanHeight != NEVER; }

    void BanIfNotBanned(int32_t height)
    {
        if (!IsBanned()) nPoSeBanHeight = height;
    }

    /// dashd dmnstate.h:135-140 — the h=2516756 transition.
    void Revive(int32_t height)
    {
        nPoSePenalty       = 0;
        nPoSeBanHeight     = NEVER;
        nPoSeRevivedHeight = height;
    }

    /// dashd dmnstate.h:112-120. Note nVersion drops to LegacyBLS and
    /// netInfo empties — the caller (ProUpRegTx key-change branch) then
    /// re-raises nVersion from the payload, exactly as dashd does.
    void ResetOperatorFields()
    {
        nVersion             = vendor::ProTxVersion::LEGACY_BLS;
        pubKeyOperator       = {};
        netInfo              = vendor::LegacyNetService{};
        scriptOperatorPayout = OPScript{};
        nRevocationReason    = vendor::CProUpRevTx::REASON_NOT_SPECIFIED;
        platformNodeID       = uint160{};
    }

    /// dashd dmnstate.h:141-148 — SINGLE SHA256, not SHA256d.
    void UpdateConfirmedHash(const uint256& proTxHash, const uint256& newConfirmedHash)
    {
        confirmedHash = newConfirmedHash;
        CSHA256 h;
        h.Write(proTxHash.data(), 32);
        h.Write(confirmedHash.data(), 32);
        unsigned char out[CSHA256::OUTPUT_SIZE];
        h.Finalize(out);
        std::memcpy(confirmedHashWithProRegTxHash.data(), out, 32);
    }

    bool operator_pubkey_null() const
    {
        for (auto b : pubKeyOperator) if (b != 0) return false;
        return true;
    }

    bool netinfo_empty() const
    {
        if (netInfo.port_be != 0) return false;
        for (auto b : netInfo.ip) if (b != 0) return false;
        return true;
    }

    /// dashd CDeterministicMN::to_sml_entry (deterministicmns.cpp:45-52):
    /// the DIP-4 entry whose CalcHash feeds the committed merkleRootMNList.
    /// isValid ≡ !IsBanned(); nType is the DMN-level registration type;
    /// per-entry nVersion gates the BasicBLS+ fields exactly as on the wire.
    vendor::CSimplifiedMNListEntry to_sml_entry(const uint256& proTxHash) const
    {
        vendor::CSimplifiedMNListEntry e;
        e.nVersion         = nVersion;
        e.proRegTxHash     = proTxHash;
        e.confirmedHash    = confirmedHash;
        e.netAddress       = netInfo.ip;
        e.netPort          = netInfo.port_be;
        e.pubKeyOperator   = pubKeyOperator;
        e.keyIDVoting      = keyIDVoting;
        e.isValid          = !IsBanned();
        e.nType            = nType;
        e.platformHTTPPort = platformHTTPPort;
        e.platformNodeID   = platformNodeID;
        return e;
    }

    // Snapshot-v3 wire codec. INTERNAL persistence only (never network) —
    // but versioned + digest-pinned at the container level so a field change
    // here MUST bump kSnapshotVersion (an old binary then fails loud instead
    // of skipping entries one by one — the MnStateDb v1→v2 lesson).
    C2POOL_SERIALIZE_METHODS(ReplayMNState)
    {
        READWRITE(obj.nType,
                  obj.internalId,
                  obj.collateralOutpoint,
                  obj.nOperatorReward,
                  obj.nVersion,
                  obj.nRegisteredHeight,
                  obj.nLastPaidHeight,
                  obj.nConsecutivePayments,
                  obj.nPoSePenalty,
                  obj.nPoSeRevivedHeight,
                  obj.nPoSeBanHeight,
                  obj.nRevocationReason,
                  obj.confirmedHash,
                  obj.confirmedHashWithProRegTxHash,
                  obj.keyIDOwner,
                  Using<vendor::RawBytesFormat<vendor::BLS_PUBKEY_SIZE>>(obj.pubKeyOperator),
                  obj.keyIDVoting,
                  obj.netInfo,
                  obj.scriptPayout,
                  obj.scriptOperatorPayout,
                  obj.platformNodeID,
                  obj.platformP2PPort,
                  obj.platformHTTPPort);
    }

    bool operator==(const ReplayMNState& r) const
    {
        return nType == r.nType
            && internalId == r.internalId
            && collateralOutpoint.hash == r.collateralOutpoint.hash
            && collateralOutpoint.index == r.collateralOutpoint.index
            && nOperatorReward == r.nOperatorReward
            && nVersion == r.nVersion
            && nRegisteredHeight == r.nRegisteredHeight
            && nLastPaidHeight == r.nLastPaidHeight
            && nConsecutivePayments == r.nConsecutivePayments
            && nPoSePenalty == r.nPoSePenalty
            && nPoSeRevivedHeight == r.nPoSeRevivedHeight
            && nPoSeBanHeight == r.nPoSeBanHeight
            && nRevocationReason == r.nRevocationReason
            && confirmedHash == r.confirmedHash
            && confirmedHashWithProRegTxHash == r.confirmedHashWithProRegTxHash
            && keyIDOwner == r.keyIDOwner
            && pubKeyOperator == r.pubKeyOperator
            && keyIDVoting == r.keyIDVoting
            && netInfo.ip == r.netInfo.ip
            && netInfo.port_be == r.netInfo.port_be
            && scriptPayout.m_data == r.scriptPayout.m_data
            && scriptOperatorPayout.m_data == r.scriptOperatorPayout.m_data
            && platformNodeID == r.platformNodeID
            && platformP2PPort == r.platformP2PPort
            && platformHTTPPort == r.platformHTTPPort;
    }
};

/// Mainnet height gates the fold versions on (design doc §3). Defaults are
/// Dash MAINNET; tests override for synthetic vectors.
struct FoldGates
{
    int32_t dip0003_height{1028160};   // fold start — no DML below this
    // DIP3 has TWO distinct heights (dashd deploymentstatus.h:52 comment:
    // "'active' and 'enforced' are different statuses for DIP0003"). The
    // deterministic MN list is BUILT from activation (dip0003_height); the
    // coinbase paying GetMNPayee(list) is only ENFORCED from here on. dashd
    // mainnet chainparams.cpp:186 DIP0003EnforcementHeight = 1047200.
    int32_t dip0003_enforcement_height{1047200};
    int32_t v19_height{1899072};       // basic BLS (per-entry nVersion wrapper)
    int32_t mn_rr_height{2128896};     // MN reward reallocation (Evo 4-in-a-row OFF)
    int32_t masternode_min_confirmations{15};
    // DEPLOYMENT_V24 / ExtAddr is NEVER_ACTIVE on mainnet
    // (chainparams.cpp:212-214). The branch is NOT implemented; setting this
    // true makes every fold refuse — fail closed, never drift (§3).
    bool    v24_active{false};

    bool v19_active(int32_t h) const   { return h >= v19_height; }
    bool mn_rr_active(int32_t h) const { return h >= mn_rr_height; }
    // dashd deploymentstatus.h:53 DeploymentDIP0003Enforced(h) == h >= EnfHeight.
    // Gates the coinbase payee cross-check: below this dashd's own consensus
    // rule (CMNPaymentsProcessor::IsTransactionValid, payments.cpp:114) returns
    // valid WITHOUT checking the det payee, so the coinbase pays the legacy
    // masternode winner, not GetMNPayee(list) — a cross-check here would be
    // stricter than dashd and false-poison a correct fold.
    bool dip0003_enforced(int32_t h) const { return h >= dip0003_enforcement_height; }
};

/// Feature flag for the whole engine. `enabled` MUST be set explicitly —
/// a default-constructed config refuses every fold, so nothing can reach
/// this engine by accident before W5 wires it behind a node option.
struct FoldConfig
{
    bool      enabled{false};
    FoldGates gates{};
    // Log per-MN transitions (registrations, bans, revives, punishes).
    bool      debug_logs{false};
};

struct FoldResult
{
    bool        ok{false};
    // On !ok: a sentence naming the height and the blocking condition.
    std::string error;
    uint32_t    height{0};

    // THE self-check (both always filled on a completed fold).
    uint256     computed_root;
    uint256     committed_root;

    // Transition counters, for diagnostics and KAT assertions.
    size_t      registered{0};
    size_t      updated{0};             // ProUpServ/ProUpReg applied
    size_t      revoked{0};             // ProUpRevTx
    size_t      revived{0};             // ProUpServTx PoSe-revive applied
    size_t      punished{0};            // qfcommit invalid-member punishes
    size_t      banned{0};              // bans applied this block (any cause)
    size_t      decayed{0};             // MNs whose penalty decremented
    size_t      confirmed{0};           // confirmedHash set this block
    size_t      collateral_replaced{0}; // ProRegTx re-using a tracked collateral
    size_t      collateral_spent{0};    // MNs removed by the vin scan
    // The pass-0 projected payee (present whenever the pre-block list was
    // non-empty) and whether it was still present to be marked paid.
    std::optional<uint256> payee;
    bool        payee_marked{false};
    // THE SECOND self-check (pass 0b): the pre-block scriptPayout of the
    // projected payee was found among this block's own coinbase outputs.
    // False ONLY when the pre-block list was empty (nothing to project) —
    // a projection that is NOT paid fails the fold closed, it never leaves
    // this flag quietly clear.
    bool        payee_paid_verified{false};
    // True when the payee cross-check was SKIPPED because this height is below
    // DIP3 enforcement (dashd does not commit the det payee to the coinbase
    // there either). The SET self-check (merkleRootMNList) still ran; only the
    // payee AXIS is not coinbase-committed yet. Diagnostic only — the fold is
    // still fully derived and self-consistent (nLastPaidHeight accumulates on
    // the projected payee exactly as dashd BuildNewListFromBlock does).
    bool        payee_check_preenforcement_skipped{false};
    // True when the projected payee carried nOperatorReward==10000 with a
    // non-empty scriptOperatorPayout, so dashd (payments.cpp GetBlockTxOuts)
    // zeroed masternodeReward and emitted ONLY the operator output — the
    // payee cross-check therefore required scriptOperatorPayout, NOT
    // scriptPayout. Diagnostic: distinguishes a full-operator-reward payment
    // from the ordinary owner-paid case at h=1439234 and its sub-class.
    bool        payee_operator_full_reward{false};
};

class DmlFoldEngine
{
public:
    /// Quorum-commitment member resolver: the ORDERED member list of the
    /// quorum (llmqType, quorumHash), index-aligned with the commitment's
    /// validMembers bitset. W1 injects this (KATs use captured member sets);
    /// W4 (quorum lane) derives it from the replayed list at the quorum work
    /// block — design doc §3 "rotated-quorum member sets are self-derivable".
    /// Returning nullopt fails the fold closed at the named height: a
    /// commitment we cannot attribute members to would silently skip PoSe
    /// punishes and desync the penalty model.
    using MembersFn = std::function<std::optional<std::vector<uint256>>(
        uint8_t llmqType, const uint256& quorumHash)>;

    static constexpr uint32_t    kSnapshotVersion = 3;
    static constexpr const char* kSnapshotMagic   = "C2POOL-DASH-DML-SNAP/v03";
    static constexpr size_t      kSnapshotMagicLen = 24;

    explicit DmlFoldEngine(FoldConfig cfg) : m_cfg(std::move(cfg)) {}

    void set_members_fn(MembersFn fn) { m_members_fn = std::move(fn); }

    /// Seed the engine from an anchor (Phase-1 trusted-anchor replay). The
    /// state is declared to be the DML AT `height` (i.e. AFTER folding block
    /// `height`); the only block fold_block accepts next is height+1.
    void seed(std::vector<std::pair<uint256, ReplayMNState>> entries,
              uint64_t total_registered_count,
              uint32_t height,
              const uint256& block_hash,
              std::string network = "mainnet")
    {
        m_entries.clear();
        m_collateral_index.clear();
        for (auto& [protx, st] : entries) {
            m_collateral_index[st.collateralOutpoint] = protx;
            m_entries.emplace(protx, std::move(st));
        }
        m_total_registered_count = total_registered_count;
        m_height                 = height;
        m_block_hash             = block_hash;
        m_network                = std::move(network);
        m_poisoned               = false;
        m_poison_reason.clear();
        reset_sml_cache();
    }

    // ── Accessors ────────────────────────────────────────────────────────
    size_t             size() const                   { return m_entries.size(); }
    uint32_t           height() const                 { return m_height; }
    const uint256&     block_hash() const             { return m_block_hash; }
    uint64_t           total_registered_count() const { return m_total_registered_count; }
    const std::string& network() const                { return m_network; }
    bool               poisoned() const               { return m_poisoned; }
    const std::string& poison_reason() const          { return m_poison_reason; }

    using Entries = std::map<uint256, ReplayMNState>;
    const Entries& entries() const { return m_entries; }

    /// Dash block identity = X11(80-byte header) — same as header_chain.hpp.
    /// PUBLIC because a feeder that hands blocks to fold_block must be able to
    /// name them the SAME way: the quorum lane keys derived member cycles by
    /// block hash, and a caller that passed a null placeholder there made W4
    /// lose the cycle and the fold fail closed at the next punishing
    /// commitment (live-observed, h=2512821 llmqType=2).
    static uint256 block_header_hash(const dash::coin::BlockType& block)
    {
        const bitcoin_family::coin::BlockHeaderType& hdr = block;
        ::PackStream s;
        s << hdr;
        auto sp = s.get_span();
        return dash::crypto::hash_x11(
            reinterpret_cast<const unsigned char*>(sp.data()), sp.size());
    }

    const ReplayMNState* find(const uint256& proTxHash) const
    {
        auto it = m_entries.find(proTxHash);
        return it == m_entries.end() ? nullptr : &it->second;
    }

    /// dashd CalcMaxPoSePenalty (deterministicmns.cpp:292-298): dynamic,
    /// max(100, number of registered MNs in the list — banned included).
    int32_t calc_max_pose_penalty() const
    {
        return std::max<int32_t>(100, static_cast<int32_t>(m_entries.size()));
    }

    /// dashd CalcPenalty (deterministicmns.cpp:300-304), integer math.
    int32_t calc_penalty(int32_t percent) const
    {
        return (calc_max_pose_penalty() * percent) / 100;
    }

    /// DIP-4 merkleRootMNList of the CURRENT state — the value the
    /// self-check compares against each block's committed cbTx root.
    ///
    /// INCREMENTAL (dashd CDeterministicMNListDiff parity). The profiled
    /// dominant fold cost was rebuilding ALL ~4900 CSimplifiedMNListEntry,
    /// serializing+SHA256d'ing each leaf, sorting and merkling the whole tree
    /// EVERY block. dashd instead caches each CDeterministicMN's SML entry
    /// hash and re-hashes only the entries a diff actually changed. This
    /// mirrors that:
    ///   • m_leaf_hash_cache — per-proTxHash CalcHash, invalidated ONLY for
    ///     entries whose SML-serialized fields changed this block. The
    ///     mutation sites that touch an SML field call mark_sml_dirty; the
    ///     ones that do NOT (nLastPaidHeight/nConsecutivePayments in pass 5,
    ///     the nPoSePenalty decrement in pass 2, a punish that does not cross
    ///     into a ban) never dirty — those fields are not under CalcHash.
    ///   • m_sml_tree — a cached merkle tree over the memcmp-sorted leaf
    ///     hashes. On a FIELD-ONLY block (leaf set unchanged, positions
    ///     stable) each changed leaf updates the O(log N) nodes on its path.
    /// A STRUCTURAL block (ProRegTx add, collateral remove) shifts every
    /// sorted position after the mutation, which reshuffles all pairings in
    /// the positional duplicate-last-on-odd Bitcoin/Dash merkle — O(log N) is
    /// UNSAFE there, so the tree is rebuilt from the (still-valid) leaf-hash
    /// cache. HYBRID: incremental path on field-only blocks, recompute from
    /// cached leaves on structural blocks. The result is byte-identical to
    /// compute_sml_root_full() at every block (KAT-proven across add / remove
    /// / isValid-flip / confirmedHash / operator-key change), so the
    /// self-check against the committed cbTx root is UNCHANGED and still
    /// poisons on mismatch.
    uint256 compute_sml_root() const
    {
        if (m_entries.empty()) {
            m_sml_tree.clear();
            m_sml_sorted_protx.clear();
            m_sml_tree_valid      = true;
            m_sml_structure_dirty = false;
            m_sml_dirty_leaves.clear();
            return uint256::ZERO;
        }
        if (!m_sml_tree_valid || m_sml_structure_dirty)
            rebuild_sml_tree();
        else if (!m_sml_dirty_leaves.empty())
            apply_sml_field_updates();
        return m_sml_tree.back().front();
    }

    /// Reference FULL recompute — the pre-incremental path, kept as the KAT
    /// oracle (the incremental root MUST equal this at every block) and as a
    /// cache-independent belt any caller can reach.
    uint256 compute_sml_root_full() const
    {
        std::vector<vendor::CSimplifiedMNListEntry> ents;
        ents.reserve(m_entries.size());
        for (const auto& [protx, st] : m_entries)
            ents.push_back(st.to_sml_entry(protx));
        vendor::CSimplifiedMNList sml(std::move(ents));
        return sml.CalcMerkleRoot();
    }

    /// TEST-ONLY. Simulate a MISSED SML invalidation: a mutation that changed
    /// an entry's SML-serialized fields but failed to mark its proTxHash
    /// dirty. Corrupts the cached leaf so the next compute_sml_root() returns
    /// a STALE root — the fold self-check then mismatches the committed cbTx
    /// root and poisons. Proves the incremental path cannot silently serve a
    /// wrong list. Never called in production.
    void test_only_corrupt_incremental_cache(const uint256& protx)
    {
        (void)compute_sml_root();               // materialise the tree
        uint256 bogus;
        auto it = m_leaf_hash_cache.find(protx);
        if (it != m_leaf_hash_cache.end()) bogus = it->second;
        bogus.data()[0] ^= 0xff;                // cannot equal a real CalcHash
        m_leaf_hash_cache[protx] = bogus;
        // Force a rebuild that REUSES the corrupted cached leaf (present, not
        // dirty) — models a leaf whose recompute was skipped.
        m_sml_structure_dirty = true;
        m_sml_dirty_leaves.clear();
    }

    /// dashd CDeterministicMNList::GetMNPayee (deterministicmns.cpp:183-215)
    /// projected for block `next_height` from the CURRENT list (which must be
    /// the list at next_height−1). Includes the v19-and-not-MN_RR EvoNode
    /// 4-in-a-row branch so a genesis replay (Phase 2) crosses the
    /// 1899072..2128896 window correctly.
    std::optional<uint256> project_payee(int32_t next_height) const
    {
        if (m_entries.empty()) return std::nullopt;

        const bool evo_bonus = m_cfg.gates.v19_active(next_height)
                            && !m_cfg.gates.mn_rr_active(next_height);
        if (evo_bonus) {
            for (const auto& [protx, st] : m_entries) {
                if (st.IsBanned()) continue;
                if (st.nLastPaidHeight != static_cast<int32_t>(m_height)) continue;
                if (st.nType == vendor::MnType::EVO
                    && st.nConsecutivePayments < kEvoVotingWeight) {
                    return protx;
                }
            }
        }

        const uint256* best   = nullptr;
        int32_t        best_h = 0;
        const ReplayMNState* best_st = nullptr;
        for (const auto& [protx, st] : m_entries) {
            if (st.IsBanned()) continue;
            const int32_t h = compare_by_last_paid_height(st);
            if (best == nullptr || payee_before(h, protx, best_h, *best)) {
                best   = &protx;
                best_h = h;
                best_st = &st;
            }
        }
        (void)best_st;
        if (!best) return std::nullopt;
        return *best;
    }

    // ─────────────────────────────────────────────────────────────────────
    // fold_block — the per-block DML fold + THE self-check
    // ─────────────────────────────────────────────────────────────────────
    FoldResult fold_block(const dash::coin::BlockType& block, uint32_t height)
    {
        FoldResult r;
        r.height = height;

        // Feature flag: default-constructed config folds nothing.
        if (!m_cfg.enabled) {
            r.error = "DML fold engine is not enabled (FoldConfig.enabled "
                      "is the W1 feature flag; W5 wires it)";
            return r;
        }
        // HARD STOP is sticky: after a root mismatch nothing folds again
        // until the operator re-seeds — serving from a state that has
        // ALREADY diverged from consensus is the one unforgivable outcome.
        if (m_poisoned) {
            r.error = "DML fold engine is POISONED (" + m_poison_reason
                    + ") — re-seed required";
            return r;
        }
        if (m_cfg.gates.v24_active) {
            r.error = "fold refused at h=" + std::to_string(height)
                    + ": DEPLOYMENT_V24/ExtAddr is active but the ExtAddr "
                      "fold branch is not implemented (fail closed, never "
                      "drift — design doc §3)";
            return r;
        }
        if (static_cast<int32_t>(height) < m_cfg.gates.dip0003_height) {
            r.error = "fold refused at h=" + std::to_string(height)
                    + ": below DIP0003 activation h="
                    + std::to_string(m_cfg.gates.dip0003_height);
            return r;
        }
        // Forward-contiguous cursor: exactly height == cursor + 1. A gap
        // means skipped folds (stale payment cursor); out-of-order means a
        // duplicate delivery. Both refuse the WHOLE fold, no mutation.
        if (height != m_height + 1) {
            r.error = "fold refused at h=" + std::to_string(height)
                    + ": cursor is at h=" + std::to_string(m_height)
                    + " and the fold is forward-contiguous (only h="
                    + std::to_string(m_height + 1) + " is foldable)";
            return r;
        }
        if (block.m_txs.empty()) {
            r.error = "fold refused at h=" + std::to_string(height)
                    + ": block has no transactions (no coinbase, no cbTx "
                      "root to self-check against)";
            return r;
        }
        // The committed answer key, read FIRST: a block whose cbTx cannot
        // be parsed cannot be self-checked, so it cannot be folded.
        vendor::CCbTx cbtx;
        if (block.m_txs[0].type != 5
            || !vendor::parse_cbtx(block.m_txs[0].extra_payload, cbtx)) {
            r.error = "fold refused at h=" + std::to_string(height)
                    + ": coinbase carries no parseable CCbTx "
                      "(merkleRootMNList unavailable for the self-check)";
            return r;
        }
        r.committed_root = cbtx.merkleRootMNList;

        const int32_t H = static_cast<int32_t>(height);
        const uint256 prev_hash = block.m_previous_block;

        // ── Pass 0: payee, from the PRE-block list ──────────────────────
        r.payee = project_payee(H);

        // ── Pass 0b: capture the payee's PRE-BLOCK payment tuple ────────
        // dashd built this block's coinbase from the list at H-1, which is
        // exactly the list being held right now. A ProUpRegTx later in this
        // same block may rewrite scriptPayout, and a collateral spend may
        // remove the masternode outright, so the tuple is captured HERE and
        // adjudicated in pass 6 — after the special-tx folds, so that a block
        // with a genuinely broken payload still reports ITS OWN blocking
        // condition rather than this one.
        //
        // The full tuple is (scriptPayout, scriptOperatorPayout, bps): dashd
        // GetBlockTxOuts (masternode/payments.cpp:64-77) does NOT always emit
        // scriptPayout. When nOperatorReward==10000 and scriptOperatorPayout
        // is set, the operator reward eats the entire MN share, masternodeReward
        // becomes exactly 0, and the ONLY MN vout dashd emits is the operator
        // script. Capturing all three lets pass 6 mirror that branch exactly
        // instead of unconditionally demanding scriptPayout (which false-poisons
        // a byte-correct fold at every 100%-operator-reward payment — h=1439234).
        std::vector<unsigned char> payee_script_pre;
        std::vector<unsigned char> payee_op_script_pre;
        uint16_t                   payee_bps_pre = 0;
        if (r.payee) {
            const ReplayMNState* pst = find(*r.payee);
            if (pst == nullptr) {
                r.error = "fold refused at h=" + std::to_string(height)
                        + ": projected payee " + r.payee->GetHex()
                        + " is not in the pre-block list (internal invariant "
                          "violated) — HARD STOP, engine poisoned";
                poison(r.error);
                LOG_ERROR << "[DML-FOLD] " << r.error;
                return r;
            }
            payee_script_pre    = pst->scriptPayout.m_data;
            payee_op_script_pre = pst->scriptOperatorPayout.m_data;
            payee_bps_pre       = pst->nOperatorReward;
        }

        // ── Pass 1: confirmedHash (specialtxman.cpp:205-218) ────────────
        // Walks every MN, BANNED INCLUDED. Confirmation compares against
        // H−1 (the prev block's height), and the recorded hash is hash(H−1)
        // — which is this block's own hashPrevBlock.
        for (auto& [protx, st] : m_entries) {
            if (!st.confirmedHash.IsNull()) continue;
            const int32_t confs = (H - 1) - st.nRegisteredHeight;
            if (confs >= m_cfg.gates.masternode_min_confirmations) {
                st.UpdateConfirmedHash(protx, prev_hash);
                mark_sml_dirty(protx);  // confirmedHash is an SML field
                ++r.confirmed;
            }
        }

        // ── Pass 2: DecreaseScores (deterministicmns.cpp:334-359) ───────
        for (auto& [protx, st] : m_entries) {
            if (st.IsBanned()) continue;
            if (st.nPoSePenalty > 0) {
                --st.nPoSePenalty;
                ++r.decayed;
            }
        }

        // ── Pass 3: special txs, in tx order (specialtxman.cpp:228-460) ─
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            // dashd: IsSpecialTxVersion() == (nVersion == 3); only then is
            // nType meaningful.
            if (tx.version != 3 || tx.type == 0) continue;

            std::string err;
            switch (tx.type) {
            case vendor::CProRegTx::SPECIALTX_TYPE:
                err = fold_proreg(tx, H, r);
                break;
            case vendor::CProUpServTx::SPECIALTX_TYPE:
                err = fold_proupserv(tx, H, r);
                break;
            case vendor::CProUpRegTx::SPECIALTX_TYPE:
                err = fold_proupreg(tx, H, r);
                break;
            case vendor::CProUpRevTx::SPECIALTX_TYPE:
                err = fold_prouprev(tx, H, r);
                break;
            case 6: // TRANSACTION_QUORUM_COMMITMENT
                err = fold_qfcommit(tx, H, r);
                break;
            default:
                // Types 5 (cbTx, coinbase-only), 8/9 (asset lock/unlock —
                // credit-pool lane, not DML), MNHF: no DML effect.
                //
                // Types 8/9 are NOT discarded by the replay pipeline: the
                // CreditPool INDEX follower (credit_pool_idx.hpp, Variant B
                // #143) ingests them as a SECOND IReplayBlockConsumer through
                // the TeeReplayConsumer seam (replay_bulk_fetch.hpp), which
                // hands it the full body BEFORE drain_buffer() prunes it.
                // Folding them HERE as well would double-ingest; the DML fold
                // stays type-8/9-blind on purpose.
                break;
            }
            if (!err.empty()) {
                r.error = "fold FAILED at h=" + std::to_string(height)
                        + " tx[" + std::to_string(i) + "]: " + err;
                poison(r.error);
                return r;
            }
        }

        // ── Pass 4: collateral spends (specialtxman.cpp:464-482) ────────
        // Pure vin-vs-known-outpoint scan over every non-coinbase tx —
        // AFTER pass 3, so a same-block registration can be spent by a
        // later tx of the same block (dashd order).
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            for (const auto& in : block.m_txs[i].vin) {
                auto ci = m_collateral_index.find(in.prevout);
                if (ci == m_collateral_index.end()) continue;
                remove_mn(ci->second);
                ++r.collateral_spent;
            }
        }

        // ── Pass 5: payee bookkeeping (specialtxman.cpp:484-515) ────────
        const bool is_mn_rr = m_cfg.gates.mn_rr_active(H);
        if (r.payee) {
            auto it = m_entries.find(*r.payee);
            if (it != m_entries.end()) {
                it->second.nLastPaidHeight = H;
                r.payee_marked = true;
                if (it->second.nType == vendor::MnType::EVO && !is_mn_rr) {
                    ++it->second.nConsecutivePayments;
                }
            }
            // Payee removed this very block: dashd pays it one last time
            // anyway (the coinbase was built from the H−1 list) but the
            // list no longer carries it — nothing to mark. Mirrored.
        }
        // Reset nConsecutivePayments on non-paid EvoNodes (under MN_RR:
        // on ALL EvoNodes — the payee's bump is gated off above too).
        for (auto& [protx, st] : m_entries) {
            if (st.nType != vendor::MnType::EVO) continue;
            if (r.payee && protx == *r.payee && !is_mn_rr) continue;
            st.nConsecutivePayments = 0;
        }

        // ── THE SELF-CHECK (design doc §4.2 layer 3) ────────────────────
        // Every mainnet block since DIP3 commits the root of the very list
        // this fold must produce. Equality here is the whole point of
        // replay: a wrong fold rule, wrong body or wrong seed HARD-STOPS at
        // the named height instead of serving wrong bytes.
        r.computed_root = compute_sml_root();
        if (r.computed_root != r.committed_root) {
            r.error = "DML FOLD ROOT MISMATCH at h=" + std::to_string(height)
                    + ": folded merkleRootMNList " + r.computed_root.GetHex()
                    + " != committed cbTx root " + r.committed_root.GetHex()
                    + " — HARD STOP, engine poisoned, re-seed required";
            poison(r.error);
            LOG_ERROR << "[DML-FOLD] " << r.error;
            return r;
        }

        // ── THE SECOND SELF-CHECK: the payee axis ───────────────────────
        //
        // The root check above proves the masternode SET. It cannot prove the
        // payment ORDER, because merkleRootMNList commits the DIP-4 SML entry
        // — proRegTxHash, confirmedHash, netInfo, pubKeyOperator, keyIDVoting,
        // isValid, nType, platform ports — and NOT nLastPaidHeight, which is
        // the field GetMNPayee orders by. Pass 5 just wrote nLastPaidHeight=H
        // onto the masternode THIS ENGINE projected; if that projection was
        // wrong, two entries are now mis-dated, the error is carried forward
        // by every later block, and a run of N byte-exact roots says nothing
        // about it. "4753/4753 byte-exact, DIVERGED=none" has been quoted as
        // if it proved both axes. It proves one.
        //
        // Every block carries the answer key for the other axis too: its own
        // coinbase, which dashd built from the list at H-1. So check it, and
        // fail closed on exactly the same footing as a root mismatch.
        //
        // MEASURED (contabo, 2026-08-05): a fold reporting 4755/4755 roots and
        // DIVERGED=none published its list, and the next block answered
        //     [MNS-SM] PAYEE DESYNC h=2516956: coinbase does not pay
        //              projected MN 8ef71d8296c6e516
        //
        // HONEST LIMIT, stated where the check lives: this proves the payee's
        // SCRIPT is paid, not that this exact proTxHash was the one dashd
        // picked. Payout scripts are shared — at h=2516955 FORTY masternodes
        // share the script block 2516956 pays. So it falsifies a projection
        // that drifts ACROSS payout groups (which is the observed failure,
        // and the one that mints a rejected coinbase) and cannot separate
        // members WITHIN a group. A within-group swap is invisible to the
        // coinbase and therefore invisible to any consumer of it, including
        // dashd's own validation of our block.
        //
        // DIP3-ENFORCEMENT GATE (dashd parity, DIP3-genesis regime fix):
        // dashd builds the deterministic list from DIP3 ACTIVATION (1028160)
        // but only ENFORCES the coinbase paying GetMNPayee(list) from
        // DIP0003EnforcementHeight (1047200) — CMNPaymentsProcessor::
        // IsTransactionValid (payments.cpp:114) returns valid WITHOUT checking
        // the payee when !DeploymentDIP0003Enforced(h). In the [activation,
        // enforcement) window the historical coinbase pays the LEGACY
        // masternode winner, not the det projection, so this cross-check —
        // which is correct at tip — is STRICTER THAN DASHD there and false-
        // poisons a byte-correct fold (observed: h=1028163, merkleRootMNList
        // MATCHED, payee projection sound, coinbase simply pays the legacy
        // winner). Mirror dashd's gate exactly. The SET self-check above stays
        // UNCONDITIONAL; the payee projection + nLastPaidHeight bookkeeping
        // (passes 0/5) also run unconditionally, so the payee axis stays fully
        // derived and self-consistent across the window and is correct the
        // instant enforcement begins. Production (tip ~2.5M) is far above
        // enforcement, so the money-path check is UNCHANGED.
        //
        // WHICH SCRIPT dashd requires (masternode/payments.cpp GetBlockTxOuts
        // :64-77, IsTransactionValid :109-139): the coinbase's REQUIRED MN
        // output set is NOT unconditionally {scriptPayout}. dashd computes
        //     if (nOperatorReward != 0 && scriptOperatorPayout != CScript()) {
        //         operatorReward = (masternodeReward * nOperatorReward) / 10000;
        //         masternodeReward -= operatorReward;
        //     }
        //     if (masternodeReward > 0) emplace(masternodeReward, scriptPayout);
        //     if (operatorReward  > 0) emplace(operatorReward,  scriptOperatorPayout);
        // and its validator requires PRECISELY the vouts it emitted — never
        // scriptPayout when masternodeReward folded to 0.
        //
        // At nOperatorReward==10000 with a set scriptOperatorPayout, the
        // operator reward eats the WHOLE MN share: masternodeReward becomes
        // exactly 0, so dashd emits NO scriptPayout output and the only
        // required MN vout is scriptOperatorPayout. A check that demands
        // scriptPayout there is STRICTER THAN DASHD and false-poisons a
        // byte-correct fold (observed h=1439234: proTxHash 71ed3bf5…, bps=10000,
        // owner==operator self-host; roots matched 411073/411073, coinbase paid
        // the operator script for the full share, no owner remainder).
        //
        // For 0 < bps < 10000, masternodeReward = mnShare − floor(mnShare·bps/
        // 10000) is provably > 0 (floor of a strict-fraction of mnShare is
        // strictly below mnShare), so scriptPayout IS emitted and required —
        // today's behaviour. The operator output's exact amount needs the fee
        // reward, which the fold's fee-unknown (W5) gap cannot price, so we
        // NEVER poison on the operator axis for a partial split — only the
        // owner axis, which is always required and always priceable.
        //
        // The required script is therefore the SINGLE owner-or-operator script
        // dashd guarantees to emit; we fail closed on its absence exactly as a
        // root mismatch, and stay STRICTLY equal to dashd's requirement, never
        // weaker.
        const bool full_operator_reward =
            payee_bps_pre == 10000 && !payee_op_script_pre.empty();
        const std::vector<unsigned char>& required_script =
            full_operator_reward ? payee_op_script_pre : payee_script_pre;
        if (r.payee) r.payee_operator_full_reward = full_operator_reward;

        if (r.payee && !required_script.empty()
            && !m_cfg.gates.dip0003_enforced(H)) {
            r.payee_check_preenforcement_skipped = true;
        }
        if (r.payee && !required_script.empty()
            && m_cfg.gates.dip0003_enforced(H)) {
            bool paid = false;
            if (!block.m_txs.empty()) {
                for (const auto& out : block.m_txs[0].vout) {
                    if (out.scriptPubKey.m_data == required_script) {
                        paid = true;
                        break;
                    }
                }
            }
            if (!paid) {
                const auto hx = [](const std::vector<unsigned char>& v) {
                    static const char* d = "0123456789abcdef";
                    std::string s; s.reserve(v.size() * 2);
                    for (unsigned char b : v) { s += d[b >> 4]; s += d[b & 0xf]; }
                    return s;
                };
                r.error = "DML FOLD PAYEE MISMATCH at h=" + std::to_string(height)
                        + ": this block's coinbase does not pay the projected "
                          "masternode " + r.payee->GetHex()
                        + " — required " + (full_operator_reward
                              ? "scriptOperatorPayout (nOperatorReward=10000, "
                                "masternodeReward folds to 0 so dashd emits only "
                                "the operator output)"
                              : "scriptPayout")
                        + " {scriptPayout=" + hx(payee_script_pre)
                        + ", scriptOperatorPayout=" + hx(payee_op_script_pre)
                        + ", bps=" + std::to_string(payee_bps_pre)
                        + "} — the merkleRootMNList self-check PASSED at this "
                          "height, which is exactly why this check exists: "
                          "nLastPaidHeight is not committed by any block, so "
                          "a wrong payment order folds to the right root — "
                          "HARD STOP, engine poisoned, re-seed required";
                poison(r.error);
                LOG_ERROR << "[DML-FOLD] " << r.error;
                return r;
            }
            r.payee_paid_verified = true;
        }

        // Fold accepted — advance the cursor.
        m_height     = height;
        m_block_hash = block_header_hash(block);
        r.ok = true;
        return r;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Snapshot v3 — save / load / resume
    // ─────────────────────────────────────────────────────────────────────
    std::vector<uint8_t> save_snapshot() const
    {
        ::PackStream s;
        s.write(std::as_bytes(
            std::span<const char>(kSnapshotMagic, kSnapshotMagicLen)));
        s << kSnapshotVersion;
        s << m_network;
        s << m_height;
        s << m_block_hash;
        s << m_total_registered_count;
        s << static_cast<uint64_t>(m_entries.size());
        for (const auto& [protx, st] : m_entries) {
            s << protx;
            s << st;
        }
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

    /// Load a v3 snapshot and RESUME from its cursor: the next foldable
    /// block is height+1. Fail-closed on wrong magic, wrong VERSION (an old
    /// or newer binary must fail LOUD, not skip-and-limp — the versioned-
    /// format standing trap), truncated payload or digest mismatch. On any
    /// failure the engine state is left UNTOUCHED.
    bool load_snapshot(const std::vector<uint8_t>& bytes, std::string& error)
    {
        error.clear();
        if (bytes.size() < kSnapshotMagicLen + 4 + 32) {
            error = "snapshot too short (" + std::to_string(bytes.size())
                  + " bytes) — truncated or not a DML snapshot";
            return false;
        }
        if (std::memcmp(bytes.data(), kSnapshotMagic, kSnapshotMagicLen) != 0) {
            error = "snapshot magic mismatch — not a C2POOL-DASH-DML "
                    "snapshot";
            return false;
        }
        // Digest trailer: SHA256d over everything before the last 32 bytes.
        const size_t payload_len = bytes.size() - 32;
        uint256 want, got;
        std::memcpy(want.data(), bytes.data() + payload_len, 32);
        CHash256()
            .Write(std::span<const unsigned char>(bytes.data(), payload_len))
            .Finalize(std::span<unsigned char>(got.data(), 32));
        if (want != got) {
            error = "snapshot digest mismatch — corrupted or truncated "
                    "payload";
            return false;
        }
        try {
            std::vector<uint8_t> payload(bytes.begin() + kSnapshotMagicLen,
                                         bytes.begin() + payload_len);
            ::PackStream s(payload);
            uint32_t version = 0;
            s >> version;
            if (version != kSnapshotVersion) {
                error = "snapshot format v" + std::to_string(version)
                      + " != supported v" + std::to_string(kSnapshotVersion)
                      + " — refusing to load (versioned fail-loud, no "
                        "silent migration)";
                return false;
            }
            std::string network;
            uint32_t    height = 0;
            uint256     block_hash;
            uint64_t    total_registered = 0, count = 0;
            s >> network >> height >> block_hash >> total_registered >> count;
            Entries entries;
            std::map<bitcoin_family::coin::TxPrevOut, uint256,
                     ReplayOutpointLess> collateral;
            for (uint64_t i = 0; i < count; ++i) {
                uint256 protx;
                ReplayMNState st;
                s >> protx >> st;
                collateral[st.collateralOutpoint] = protx;
                entries.emplace(protx, std::move(st));
            }
            if (!s.empty()) {
                error = "snapshot carries " + std::to_string(s.cursor_size())
                      + " trailing bytes — format drift, refusing";
                return false;
            }
            if (entries.size() != count) {
                error = "snapshot declared " + std::to_string(count)
                      + " entries but carried "
                      + std::to_string(entries.size())
                      + " unique proTxHashes";
                return false;
            }
            m_entries                = std::move(entries);
            m_collateral_index       = std::move(collateral);
            m_network                = std::move(network);
            m_height                 = height;
            m_block_hash             = block_hash;
            m_total_registered_count = total_registered;
            m_poisoned               = false;
            m_poison_reason.clear();
            reset_sml_cache();
            return true;
        } catch (const std::exception& ex) {
            error = std::string("snapshot deserialize failed: ") + ex.what();
            return false;
        }
    }

    bool save_snapshot_file(const std::string& path, std::string& error) const
    {
        error.clear();
        auto bytes = save_snapshot();
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) { error = "cannot open '" + path + "' for write"; return false; }
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        if (!f) { error = "short write to '" + path + "'"; return false; }
        return true;
    }

    bool load_snapshot_file(const std::string& path, std::string& error)
    {
        error.clear();
        std::ifstream f(path, std::ios::binary);
        if (!f) { error = "cannot open '" + path + "'"; return false; }
        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                                   std::istreambuf_iterator<char>());
        return load_snapshot(bytes, error);
    }

private:
    // dashd dmn_types::Evo.voting_weight — the 4-in-a-row EvoNode bonus.
    static constexpr int32_t kEvoVotingWeight = 4;

    FoldConfig m_cfg;
    MembersFn  m_members_fn;

    Entries m_entries;
    std::map<bitcoin_family::coin::TxPrevOut, uint256, ReplayOutpointLess>
        m_collateral_index;
    uint64_t    m_total_registered_count{0};
    uint32_t    m_height{0};
    uint256     m_block_hash;
    std::string m_network{"mainnet"};
    bool        m_poisoned{false};
    std::string m_poison_reason;

    // ─────────────────────────────────────────────────────────────────────
    // Incremental SML merkle-root cache (see compute_sml_root doc). mutable:
    // compute_sml_root() is const (external callers hold const refs) but
    // memoizes; single-io-thread discipline like the rest of the engine — no
    // locks.
    // ─────────────────────────────────────────────────────────────────────
    mutable std::map<uint256, uint256>        m_leaf_hash_cache;   // protx→CalcHash
    mutable std::vector<uint256>              m_sml_sorted_protx;  // memcmp-sorted keys
    mutable std::vector<std::vector<uint256>> m_sml_tree;          // [0]=leaves … root
    mutable bool                              m_sml_tree_valid{false};
    mutable bool                              m_sml_structure_dirty{true};
    mutable std::set<uint256>                 m_sml_dirty_leaves;  // field-changed protx

    // dashcore sorts SML entries by proRegTxHash.Compare (memcmp of the raw
    // 32 bytes) — see vendor/simplifiedmns.hpp CSimplifiedMNList::sort. The
    // incremental tree MUST use the SAME order or the leaves interleave wrong.
    static bool protx_memcmp_less(const uint256& a, const uint256& b)
    {
        return std::memcmp(a.data(), b.data(), 32) < 0;
    }

    static uint256 sml_merkle_pair(const uint256& a, const uint256& b)
    {
        uint256 out;
        CHash256()
            .Write(std::span<const unsigned char>(a.data(), 32))
            .Write(std::span<const unsigned char>(b.data(), 32))
            .Finalize(std::span<unsigned char>(out.data(), 32));
        return out;
    }

    // Called ONLY at mutation sites that touch an SML-serialized field
    // (nVersion, confirmedHash, netInfo ip/port, pubKeyOperator, keyIDVoting,
    // isValid via ban/revive, platformHTTPPort/NodeID). Position unchanged.
    void mark_sml_dirty(const uint256& protx) { m_sml_dirty_leaves.insert(protx); }

    // The leaf SET changed (add/remove): positions shift → rebuild next compute.
    void mark_sml_structural() { m_sml_structure_dirty = true; }

    // Fresh list (seed / snapshot load): a proTxHash could even carry
    // different fields than a prior life, so drop the whole cache.
    void reset_sml_cache() const
    {
        m_leaf_hash_cache.clear();
        m_sml_sorted_protx.clear();
        m_sml_tree.clear();
        m_sml_dirty_leaves.clear();
        m_sml_tree_valid      = false;
        m_sml_structure_dirty = true;
    }

    // Leaf hash for protx, memoized. Recomputes when forced (field changed).
    const uint256& sml_leaf_hash(const uint256& protx, bool force) const
    {
        auto it = m_leaf_hash_cache.find(protx);
        if (!force && it != m_leaf_hash_cache.end()) return it->second;
        const uint256 h = m_entries.at(protx).to_sml_entry(protx).CalcHash();
        return m_leaf_hash_cache[protx] = h;
    }

    // Standard Bitcoin/Dash SHA256d-pairwise levels, duplicate-last-on-odd —
    // byte-identical to vendor compute_merkle_root_local, but every level is
    // KEPT so a field-only update can walk the path.
    void build_sml_levels(std::vector<uint256> leaves) const
    {
        m_sml_tree.clear();
        m_sml_tree.push_back(std::move(leaves));
        while (m_sml_tree.back().size() > 1) {
            const std::vector<uint256>& cur = m_sml_tree.back();
            const size_t sz = cur.size();
            std::vector<uint256> next;
            next.reserve((sz + 1) / 2);
            for (size_t i = 0; i < sz; i += 2) {
                const uint256& a = cur[i];
                const uint256& b = (i + 1 < sz) ? cur[i + 1] : cur[i];
                next.push_back(sml_merkle_pair(a, b));
            }
            m_sml_tree.push_back(std::move(next));
        }
    }

    // Full rebuild from m_entries: re-sort keys (memcmp), recompute dirty /
    // absent leaves (reuse the rest from cache), rebuild every tree level.
    void rebuild_sml_tree() const
    {
        m_sml_sorted_protx.clear();
        m_sml_sorted_protx.reserve(m_entries.size());
        for (const auto& [protx, st] : m_entries)
            m_sml_sorted_protx.push_back(protx);
        std::sort(m_sml_sorted_protx.begin(), m_sml_sorted_protx.end(),
                  protx_memcmp_less);

        std::vector<uint256> leaves;
        leaves.reserve(m_sml_sorted_protx.size());
        for (const uint256& protx : m_sml_sorted_protx) {
            const bool force = m_sml_dirty_leaves.count(protx) != 0;
            leaves.push_back(sml_leaf_hash(protx, force));
        }
        build_sml_levels(std::move(leaves));
        m_sml_tree_valid      = true;
        m_sml_structure_dirty = false;
        m_sml_dirty_leaves.clear();
    }

    // Field-only update: same leaf set / positions, some leaf hashes changed.
    // Recompute each dirty leaf, then propagate ONLY the affected O(log N)
    // path nodes up the cached tree (dedup shared ancestors). If a dirty
    // proTxHash is somehow absent (should be impossible on the field-only
    // path) fall back to a full rebuild — never serve a stale root.
    void apply_sml_field_updates() const
    {
        std::set<size_t> dirty_idx;
        for (const uint256& protx : m_sml_dirty_leaves) {
            auto lo = std::lower_bound(m_sml_sorted_protx.begin(),
                                       m_sml_sorted_protx.end(), protx,
                                       protx_memcmp_less);
            if (lo == m_sml_sorted_protx.end() || *lo != protx) {
                m_sml_structure_dirty = true;
                rebuild_sml_tree();
                return;
            }
            const size_t idx =
                static_cast<size_t>(lo - m_sml_sorted_protx.begin());
            m_sml_tree[0][idx] = sml_leaf_hash(protx, /*force=*/true);
            dirty_idx.insert(idx);
        }
        for (size_t level = 0; level + 1 < m_sml_tree.size(); ++level) {
            const std::vector<uint256>& cur = m_sml_tree[level];
            const size_t sz = cur.size();
            std::set<size_t> next_dirty;
            for (size_t idx : dirty_idx) {
                const size_t pidx  = idx / 2;
                const size_t left  = pidx * 2;
                const size_t right = (left + 1 < sz) ? left + 1 : left;
                m_sml_tree[level + 1][pidx] =
                    sml_merkle_pair(cur[left], cur[right]);
                next_dirty.insert(pidx);
            }
            dirty_idx = std::move(next_dirty);
        }
        m_sml_dirty_leaves.clear();
    }

    void poison(const std::string& why)
    {
        m_poisoned      = true;
        m_poison_reason = why;
    }

    void remove_mn(const uint256& protx)
    {
        auto it = m_entries.find(protx);
        if (it == m_entries.end()) return;
        m_collateral_index.erase(it->second.collateralOutpoint);
        m_entries.erase(it);
        m_leaf_hash_cache.erase(protx);   // proTxHash is never reused
        m_sml_dirty_leaves.erase(protx);  // leaf no longer exists
        mark_sml_structural();            // a leaf left the sorted set
    }

    /// dashd CompareByLastPaid_GetHeight (deterministicmns.cpp:157-166),
    /// int semantics with the -1 sentinels VERBATIM.
    static int32_t compare_by_last_paid_height(const ReplayMNState& st)
    {
        int32_t h = st.nLastPaidHeight;
        if (st.nPoSeRevivedHeight != ReplayMNState::NEVER
            && st.nPoSeRevivedHeight > h) {
            h = st.nPoSeRevivedHeight;
        } else if (h == 0) {
            h = st.nRegisteredHeight;
        }
        return h;
    }

    /// dashd CompareByLastPaid tiebreak: proTxHash memcmp ascending
    /// (LE-byte wire order — dashd uint256 operator<, NOT c2pool CompareTo).
    static bool payee_before(int32_t a_h, const uint256& a,
                             int32_t b_h, const uint256& b)
    {
        if (a_h != b_h) return a_h < b_h;
        return std::memcmp(a.data(), b.data(), 32) < 0;
    }

    // Mirrors mn_state_machine.hpp compute_tx_hash: dashd
    // CTransaction::GetHash() = SHA256d(serialized tx); Dash has no segwit.
    static uint256 compute_tx_hash(const MutableTransaction& tx)
    {
        ::PackStream s;
        s << tx;
        auto sp = s.get_span();
        uint256 h;
        CHash256()
            .Write(std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
            .Finalize(std::span<unsigned char>(h.data(), 32));
        return h;
    }

    // ── Special-tx folds. Return "" on success, an error sentence on the ─
    // ── fail-closed paths (unparseable payload, ExtAddr, missing MN).    ─

    std::string fold_proreg(const MutableTransaction& tx, int32_t H,
                            FoldResult& r)
    {
        vendor::CProRegTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p))
            return "unparseable ProRegTx payload (replay folds byte-exact "
                   "or not at all)";
        if (p.nVersion >= vendor::ProTxVersion::EXT_ADDR)
            return "ProRegTx nVersion=" + std::to_string(p.nVersion)
                 + " (ExtAddr) — branch not implemented, failing closed";

        const uint256 proTxHash = compute_tx_hash(tx);

        ReplayMNState st;
        st.nType      = p.nType;
        st.internalId = m_total_registered_count;
        // Internal collateral: null payload hash refers to the ProRegTx's
        // own output `n` (specialtxman.cpp:246-251).
        if (p.collateralOutpoint.hash.IsNull()) {
            st.collateralOutpoint.hash  = proTxHash;
            st.collateralOutpoint.index = p.collateralOutpoint.index;
        } else {
            st.collateralOutpoint = p.collateralOutpoint;
        }
        // Collateral replacement (specialtxman.cpp:266-278): an external
        // collateral being re-registered REMOVES the old MN; the new one
        // enters like a fresh registration at the bottom of the queue.
        auto rep = m_collateral_index.find(st.collateralOutpoint);
        if (rep != m_collateral_index.end()) {
            if (m_cfg.debug_logs) {
                LOG_INFO << "[DML-FOLD] h=" << H << " MN "
                         << rep->second.GetHex().substr(0, 16)
                         << " removed: collateral re-registered by "
                         << proTxHash.GetHex().substr(0, 16);
            }
            remove_mn(rep->second);
            ++r.collateral_replaced;
        }
        // State built entirely from the payload
        // (CDeterministicMNState(CProRegTx), dmnstate.h:68-79).
        st.nVersion          = p.nVersion;
        st.keyIDOwner        = p.keyIDOwner;
        st.pubKeyOperator    = p.pubKeyOperator;
        st.keyIDVoting       = p.keyIDVoting;
        st.netInfo           = p.netInfo;
        st.scriptPayout      = p.scriptPayout;
        st.platformNodeID    = p.platformNodeID;
        st.platformP2PPort   = p.platformP2PPort;
        st.platformHTTPPort  = p.platformHTTPPort;
        st.nOperatorReward   = p.nOperatorReward;
        st.nRegisteredHeight = H;
        // Empty netInfo ⇒ registers BANNED until a ProUpServTx arrives
        // (specialtxman.cpp:297-304).
        if (st.netinfo_empty()) {
            st.BanIfNotBanned(H);
            ++r.banned;
        }

        m_collateral_index[st.collateralOutpoint] = proTxHash;
        m_entries[proTxHash] = std::move(st);
        mark_sml_structural();  // a new leaf enters the sorted set
        ++m_total_registered_count;
        ++r.registered;
        if (m_cfg.debug_logs) {
            LOG_INFO << "[DML-FOLD] h=" << H << " ProRegTx "
                     << proTxHash.GetHex().substr(0, 16)
                     << " internalId=" << (m_total_registered_count - 1);
        }
        return {};
    }

    std::string fold_proupserv(const MutableTransaction& tx, int32_t H,
                               FoldResult& r)
    {
        vendor::CProUpServTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p))
            return "unparseable ProUpServTx payload";
        if (p.nVersion >= vendor::ProTxVersion::EXT_ADDR)
            return "ProUpServTx nVersion=" + std::to_string(p.nVersion)
                 + " (ExtAddr) — branch not implemented, failing closed";

        auto it = m_entries.find(p.proTxHash);
        if (it == m_entries.end())
            return "ProUpServTx names proTxHash "
                 + p.proTxHash.GetHex().substr(0, 16)
                 + " this list does not hold — state divergence "
                   "(an accepted block cannot reference a missing MN)";
        auto& st = it->second;
        if (p.nType != st.nType)
            return "ProUpServTx nType mismatch for "
                 + p.proTxHash.GetHex().substr(0, 16);

        // v24-only: nVersion update from the payload — DEAD on mainnet
        // (fold refuses when v24_active; branch kept for the record).
        st.netInfo              = p.netInfo;
        st.scriptOperatorPayout = p.scriptOperatorPayout;
        if (p.nType == vendor::MnType::EVO) {
            st.platformNodeID   = p.platformNodeID;
            st.platformP2PPort  = p.platformP2PPort;
            st.platformHTTPPort = p.platformHTTPPort;
        }
        // The h=2516756 transition (specialtxman.cpp:368-377): revive only
        // when banned AND all keys set.
        if (st.IsBanned()) {
            if (!st.operator_pubkey_null() && !st.keyIDVoting.IsNull()
                && !st.keyIDOwner.IsNull()) {
                st.Revive(H);
                ++r.revived;
                if (m_cfg.debug_logs) {
                    LOG_INFO << "[DML-FOLD] h=" << H << " MN "
                             << p.proTxHash.GetHex().substr(0, 16)
                             << " REVIVED (ProUpServTx)";
                }
            }
        }
        mark_sml_dirty(p.proTxHash);  // netInfo/platform, and Revive flips isValid
        ++r.updated;
        return {};
    }

    std::string fold_proupreg(const MutableTransaction& tx, int32_t H,
                              FoldResult& r)
    {
        vendor::CProUpRegTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p))
            return "unparseable ProUpRegTx payload";

        auto it = m_entries.find(p.proTxHash);
        if (it == m_entries.end())
            return "ProUpRegTx names proTxHash "
                 + p.proTxHash.GetHex().substr(0, 16)
                 + " this list does not hold — state divergence";
        auto& st = it->second;

        // Operator-key change ⇒ reset all operator fields + ban until a
        // ProUpServTx revives (specialtxman.cpp:395-405).
        if (st.pubKeyOperator != p.pubKeyOperator) {
            const bool was_banned = st.IsBanned();
            st.ResetOperatorFields();
            st.BanIfNotBanned(H);
            if (!was_banned) ++r.banned;
            // dashd: never downgrade past BasicBLS when updating the key.
            st.nVersion = st.nVersion > vendor::ProTxVersion::BASIC_BLS
                        ? st.nVersion : p.nVersion;
            // netInfo stays the empty MakeNetInfo(nVersion) from the reset.
            st.pubKeyOperator = p.pubKeyOperator;
            if (m_cfg.debug_logs) {
                LOG_INFO << "[DML-FOLD] h=" << H << " MN "
                         << p.proTxHash.GetHex().substr(0, 16)
                         << " operator key changed — operator fields reset"
                            " + banned";
            }
        }
        st.keyIDVoting  = p.keyIDVoting;
        st.scriptPayout = p.scriptPayout;
        mark_sml_dirty(p.proTxHash);  // keyIDVoting (SML); key-change reset+ban too
        ++r.updated;
        return {};
    }

    std::string fold_prouprev(const MutableTransaction& tx, int32_t H,
                              FoldResult& r)
    {
        vendor::CProUpRevTx p;
        if (!vendor::parse_protx_payload(tx.extra_payload, p))
            return "unparseable ProUpRevTx payload";

        auto it = m_entries.find(p.proTxHash);
        if (it == m_entries.end())
            return "ProUpRevTx names proTxHash "
                 + p.proTxHash.GetHex().substr(0, 16)
                 + " this list does not hold — state divergence";
        auto& st = it->second;
        const bool was_banned = st.IsBanned();
        st.ResetOperatorFields();
        st.BanIfNotBanned(H);
        st.nRevocationReason = p.nReason;
        if (!was_banned) ++r.banned;
        mark_sml_dirty(p.proTxHash);  // operator fields reset + isValid flip
        ++r.revoked;
        return {};
    }

    std::string fold_qfcommit(const MutableTransaction& tx, int32_t H,
                              FoldResult& r)
    {
        vendor::CFinalCommitmentTxPayload qc;
        try {
            ::PackStream s(tx.extra_payload);
            s >> qc;
            if (!s.empty())
                return "trailing bytes after qfcommit payload";
        } catch (const std::exception& ex) {
            return std::string("unparseable qfcommit payload: ") + ex.what();
        }
        if (commitment_is_null(qc.commitment)) return {};

        // dashd's punish loop (specialtxman.cpp:159-174) touches ONLY
        // invalid-marked members. When every bit of the bitset is set the
        // loop is a provable no-op, so the member list cannot affect the
        // fold — demanding a resolver there would fail the fold closed on a
        // block that mutates nothing. The test is bounded by
        // validMembers.size() rather than members.size() on purpose: that is
        // the CONSERVATIVE direction (a thin member list can only shorten
        // dashd's loop), so no punish that dashd would apply is ever skipped.
        // Measured on mainnet 2513001-2516851: 470 of the 595 non-null
        // commitments are all-valid — the difference between a replay that
        // stalls at the first commitment (h=2513003) and one that needs
        // membership only where membership actually changes state.
        if (qc.commitment.CountValidMembers()
                == qc.commitment.validMembers.size())
            return {};

        // Member resolution: index-aligned with the validMembers bitset.
        // W1 injects (captured sets); W4 derives from the replayed list.
        if (!m_members_fn)
            return "block carries a non-null qfcommit (llmqType="
                 + std::to_string(int(qc.commitment.llmqType))
                 + " quorumHash="
                 + qc.commitment.quorumHash.GetHex().substr(0, 16)
                 + ") but no quorum-member resolver is installed — PoSe "
                   "punishes cannot be folded, failing closed";
        auto members = m_members_fn(qc.commitment.llmqType,
                                    qc.commitment.quorumHash);
        if (!members)
            return "quorum-member resolver has no member set for llmqType="
                 + std::to_string(int(qc.commitment.llmqType))
                 + " quorumHash="
                 + qc.commitment.quorumHash.GetHex().substr(0, 16)
                 + " — failing closed";
        // dashd HandleQuorumCommitment (specialtxman.cpp:159-174) iterates
        // members.size() and indexes validMembers[i]. GetAllQuorumMembers may
        // return FEWER than params.size members on a thin list, so the real
        // invariant is a BOUND, not equality: members must not overrun the
        // bitset. W4's engine returns the true member-list length; the strict
        // equality check was W1's to relax at integration (W4 note,
        // replay_quorum_engine.hpp "INTERFACE RECONCILIATION POINT").
        if (members->size() > qc.commitment.validMembers.size())
            return "quorum member set size " + std::to_string(members->size())
                 + " OVERRUNS validMembers bitset size "
                 + std::to_string(qc.commitment.validMembers.size())
                 + " for quorumHash "
                 + qc.commitment.quorumHash.GetHex().substr(0, 16);

        // dashd HARDENING (h=1516043 divergence class): a MINED commitment
        // never has an empty member set — GetAllQuorumMembers always returns
        // params.size members for a quorum that produced a commitment. An
        // EMPTY member set that still carries invalid-marked members is
        // therefore a DERIVATION defect (the pre-v19 platform-quorum bug that
        // drew evo_only members and got none), not a benign thin list: the
        // punishes those invalid bits demand would be silently skipped and the
        // folded merkleRootMNList would diverge from the committed root. Fail
        // CLOSED here rather than fold a knowingly-incomplete punish pass.
        // (The all-valid commitment already returned above, so reaching here
        // with an empty member set means punishes were owed and dropped.)
        if (members->empty())
            return "quorum member set is EMPTY for a commitment carrying "
                   "invalid-marked members (llmqType="
                 + std::to_string(int(qc.commitment.llmqType))
                 + " quorumHash="
                 + qc.commitment.quorumHash.GetHex().substr(0, 16)
                 + ") — the member derivation dropped the whole set (pre-v19 "
                   "platform-quorum evo_only defect class); failing closed so "
                   "the dropped PoSe punishes cannot silently diverge the root";

        // HandleQuorumCommitment (specialtxman.cpp:159-174): punish every
        // invalid-marked member still present in the list.
        for (size_t i = 0; i < members->size(); ++i) {
            const uint256& protx = (*members)[i];
            auto it = m_entries.find(protx);
            if (it == m_entries.end()) continue;
            if (qc.commitment.validMembers[i]) continue;
            pose_punish(it->second, protx, calc_penalty(66), H, r);
        }
        return {};
    }

    /// dashd CDeterministicMNList::PoSePunish (deterministicmns.cpp:306-332):
    /// penalty += p, saturate at CalcMaxPoSePenalty; crossing max on a
    /// not-yet-banned MN ⇒ ban — the isValid flip that changes the SML root
    /// (the 2516412/2516435 case-D events).
    void pose_punish(ReplayMNState& st, const uint256& protx,
                     int32_t penalty, int32_t H, FoldResult& r)
    {
        const int32_t max_penalty = calc_max_pose_penalty();
        st.nPoSePenalty = std::min(max_penalty, st.nPoSePenalty + penalty);
        ++r.punished;
        if (!st.IsBanned() && st.nPoSePenalty >= max_penalty) {
            st.BanIfNotBanned(H);
            mark_sml_dirty(protx);  // isValid flips false; penalty alone is NOT SML
            ++r.banned;
            if (m_cfg.debug_logs) {
                LOG_INFO << "[DML-FOLD] h=" << H << " MN "
                         << protx.GetHex().substr(0, 16)
                         << " PoSe-BANNED (penalty=" << st.nPoSePenalty
                         << " max=" << max_penalty << ")";
            }
        }
    }

    /// dashd CFinalCommitment::IsNull(): no set bits and null key/vvec/sigs.
    static bool commitment_is_null(const vendor::CFinalCommitment& c)
    {
        if (c.CountSigners() != 0 || c.CountValidMembers() != 0) return false;
        for (auto b : c.quorumPublicKey) if (b != 0) return false;
        if (!c.quorumVvecHash.IsNull()) return false;
        for (auto b : c.quorumSig)  if (b != 0) return false;
        for (auto b : c.membersSig) if (b != 0) return false;
        return true;
    }
};

} // namespace replay
} // namespace coin
} // namespace dash
