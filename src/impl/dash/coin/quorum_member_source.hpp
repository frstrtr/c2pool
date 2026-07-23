// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E1 Phase-L — daemonless sourcing of the deterministic quorum MEMBER SET, the
/// input #812's verify_final_commitment needs to serve a REAL commitment.
///
/// verify_final_commitment(commitment, members) needs the ordered operator-key
/// set of the quorum's members. That set is ComputeQuorumMembers over the SML
/// AS OF the WORK block = quorumBase - WORK_DIFF_DEPTH(8) (#814 review R2:
/// dashcore v23.1.7 GetAllQuorumMembers non-rotated post-V20 feeds
/// GetListForBlock(pWorkBlockIndex), NOT the base-block list) — but the
/// embedded SML (E3) tracks the TIP, not arbitrary historical heights. This
/// module sources the historical input off the SAME coin-P2P client the E3 SML
/// sync already uses, computes the member set, and caches it for the
/// synchronous MemberKeysProvider lookup.
///
/// ONE request per quorum (R2 collapse): getmnlistd(ZERO, workHash) yields a
/// full snapshot whose SML is the work-block list AND whose embedded cbTx
/// carries the work block's bestCLSignature — both member-selection inputs in
/// one reply. Requests are DEDUPED BY BLOCK HASH (#814 review R1): on mainnet
/// the non-rotated types share quorum bases every cycle (50_60 + 100_67 every
/// 24 boundary; all four align at 576), so several (type, quorumHash) keys
/// ride ONE outstanding getmnlistd — a duplicate request would draw a second
/// reply that no longer matches an await and would leak past the demux into
/// the tip-SML maintainer (the R1 block-losing corruption; the maintainer is
/// additionally hardened against exactly that, see coin_state_maintainer.hpp).
///
/// AUTHENTICATION (#814 review R3 — the one serve-a-bad path without it): a
/// historical snapshot is the ROOT OF TRUST for the BLS member-set verify (a
/// lying peer could otherwise serve attacker keys plus a qfcommit that
/// legitimately BLS-verifies against them -> bad-qc -> lost block). So before
/// a snapshot is believed it must pass DIP-4 client verification:
///   (a) its embedded cbTx parses (type-5 CCbTx) and cbTx.nHeight == the
///       expected work height;
///   (b) cbTxMerkleTree proves the cbTx hash into the WORK block header's
///       hashMerkleRoot (header already PoW-verified by the header chain) at
///       tx index 0 (the coinbase);
///   (c) the snapshot SML's computed merkle root == cbTx.merkleRootMNList.
/// Any failure -> the pending quorums for that hash FAIL CLOSED (null-serve).
///
/// MODIFIER (#814 review R5): the coinbase ChainLock input is the work block's
/// OWN cbTx bestCLSignature — v23.1.7 GetNonNullCoinbaseChainlock does NOT
/// walk back. A null CL there means the upstream fallback modifier
/// SerializeHash((llmqType, workBlockHash)); no re-requests, no walk-back.
///
/// ASYNC by necessity: the provider is called synchronously while building a
/// template and MUST NOT block on I/O, so it only READS this cache. Population
/// is driven off relayed qfcommits (request() is kicked when a commitment for a
/// quorum is admitted) and completes when the getmnlistd reply lands. Until
/// then lookup() returns std::nullopt -> the verifier fails closed -> the slot
/// mines the consensus-valid null commitment (reward-safe), exactly the
/// pre-Phase-L posture.
///
/// DEMUX (reward-critical): historical getmnlistd replies must NOT reach the
/// E3 tip-SML maintainer — a full snapshot at an OLD base block would overwrite
/// the tip SML. on_mnlistdiff() returns TRUE when the reply matches an
/// outstanding await (whether or not it then verifies); main_dash routes such
/// replies here and skips the tip feed. Only STRICT matches consume: the diff
/// must be a full snapshot (baseBlockHash null) at an awaited block hash.
///
/// ROTATED (DIP-24): request() no-ops for a rotated type (compute is
/// unsupported there); the verifier stays fail-closed. qrinfo-based rotated
/// sourcing is the documented follow-up.
///
/// FAIL-CLOSED throughout: pre-V20 work block, base not dkgInterval-aligned,
/// header gap, rotated type, snapshot authentication failure, member
/// computation ambiguous -> the quorum simply never becomes ready and the
/// verifier serves null.
///
/// Threading: all entry points run on the single coin ioc thread (same
/// assumption as QuorumManager) — no internal locking.

#include <impl/dash/coin/dkg_commitments.hpp>          // LlmqNetwork, enabled_llmqs
#include <impl/dash/coin/utxo_adapter.hpp>             // dash_txid
#include <impl/dash/coin/vendor/quorum_members.hpp>    // compute_quorum_members
#include <impl/dash/coin/vendor/smldiff.hpp>           // CSimplifiedMNListDiff, apply_diff, ExtractMatches
#include <impl/dash/coin/vendor/cbtx.hpp>              // CCbTx, parse_cbtx
#include <impl/dash/coin/vendor/simplifiedmns.hpp>     // CSimplifiedMNList

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <vector>

namespace dash {
namespace coin {

class QuorumMemberSource {
public:
    using HashAtHeight = std::function<std::optional<uint256>(uint32_t)>;
    using HeightOfHash = std::function<std::optional<uint32_t>(const uint256&)>;
    // The PoW-verified header's hashMerkleRoot for a held block hash (the
    // DIP-4 trust anchor); std::nullopt when the header is not held.
    using MerkleRootOfHash = std::function<std::optional<uint256>(const uint256&)>;
    using SendGetMnListd = std::function<void(const uint256& base, const uint256& target)>;

    // Soft cap on cached member sets (each ~ size*49 bytes); FIFO eviction.
    static constexpr size_t kReadyCap = 1024;
    // Reap bound on outstanding requests (review nit: pendings must not
    // accumulate forever when a peer never replies); FIFO eviction.
    static constexpr size_t kPendingCap = 64;

    QuorumMemberSource(LlmqNetwork net, HashAtHeight hash_at_height,
                       HeightOfHash height_of_hash,
                       MerkleRootOfHash merkle_root_of_hash, SendGetMnListd send)
        : m_net(net), m_hash_at_height(std::move(hash_at_height))
        , m_height_of_hash(std::move(height_of_hash))
        , m_merkle_root_of_hash(std::move(merkle_root_of_hash))
        , m_send(std::move(send))
    {}

    /// The MemberKeysProvider seam: ready member set for (llmqType, quorumHash),
    /// or std::nullopt (fail closed). Never blocks / never issues I/O.
    std::optional<std::vector<vendor::MemberOperatorKey>>
    lookup(uint8_t llmq_type, const uint256& quorum_hash) const
    {
        auto it = m_ready.find(Key{llmq_type, quorum_hash});
        if (it == m_ready.end()) return std::nullopt;
        return it->second;
    }

    /// Kick sourcing for a quorum (idempotent). Called when a qfcommit for the
    /// quorum is admitted, so the member set is ready by the DKG-window height.
    void request(uint8_t llmq_type, const uint256& quorum_hash)
    {
        const Key key{llmq_type, quorum_hash};
        if (m_ready.count(key) || m_pending.count(key)) return;

        const LlmqParamsView* p = params_for(llmq_type);
        if (p == nullptr) return;                       // unknown type => fail closed
        if (p->use_rotation) {
            // ── ROTATED (DIP-24, e.g. llmq_60_75) SOURCING SEAM ─────────────
            // The non-rotated path above sources ONE full snapshot at the work
            // block (base-8) and runs ComputeQuorumMembers. A rotated quorum's
            // member set is NOT derivable from a single snapshot: dashcore
            // ComputeQuorumMembersByQuarterRotation (llmq/utils.cpp) assembles
            // it from the QUARTER-ROTATION snapshots + cycle-base mnlistdiffs
            // that only the qrinfo message carries. That wire + decode +
            // quarter-rotation port is the ITEM 2 follow-up; UNTIL it lands the
            // rotated path FAILS CLOSED here (no ready set is produced), so the
            // #816 completeness gate leaves the mixed-quorum DKG window
            // unserveable and get_work routes to the reward-safe dashd fallback.
            //
            // REMAINING WORK to make this SERVEABLE (each behind a real-vector
            // KAT against test/data/dash_rotated_quorum_members_kat.hpp — the
            // captured llmq_60_75 @1520064 ground truth: dashd's exact ordered
            // 60-member set + operator keys):
            //   1. getqrinfo P2P request: CGetQuorumRotationInfo
            //      (baseBlockHashes + blockRequestHash=quorumHash,
            //       extraShare=false) — a new p2p_messages type + a send seam
            //      analogous to send_getmnlistd (send_getqrinfo).
            //   2. CQuorumRotationInfo decode (llmq/snapshot.h /
            //      quorum_rotation_info): the 3 CQuorumSnapshot skip-lists
            //      (quorumSnapshotAtHMinusC/2C/3C) + the mnlistdiffs
            //      (mnListDiffTip/AtH/AtHMinusC/2C/3C[/4C]) — decode + DIP-4
            //      authenticate each mnlistdiff exactly like authenticate_snapshot.
            //   3. vendor::compute_quorum_members_by_quarter_rotation port of
            //      dashcore ComputeQuorumMembersByQuarterRotation +
            //      BuildNewQuorumQuarterMembers + the snapshot skip-list decode
            //      (GetQuorumQuarterMembersBySnapshot), producing the ordered
            //      MemberOperatorKey vector — MUST reproduce the captured order.
            //   4. feed that set to the SAME m_ready map so lookup() (and #812's
            //      verify_final_commitment) serves rotated commitments real.
            // Fail-closed if qrinfo can't be sourced or any snapshot mnlistdiff
            // fails DIP-4 authentication (same discipline as the non-rotated
            // authenticate_snapshot).
            LOG_DEBUG_COIND << "[QC-MEMBERS] rotated type="
                            << static_cast<int>(llmq_type) << " quorum="
                            << quorum_hash.GetHex().substr(0, 16)
                            << " => fail closed (qrinfo quarter-rotation sourcing "
                               "not yet wired; reward-safe dashd fallback)";
            return;
        }

        auto base_h = m_height_of_hash(quorum_hash);
        if (!base_h) return;                            // base header not held yet
        // Upstream refusal (utils.cpp ComputeQuorumMembers): a non-rotated
        // quorum base MUST sit on a dkgInterval boundary. Also bounds
        // peer-driven request amplification via bogus quorumHashes.
        if (*base_h % p->dkg_interval != 0) return;
        if (*base_h < kWorkDiffDepth) return;           // no work block
        const uint32_t work_h = *base_h - kWorkDiffDepth;
        if (work_h < quorum_members_v20_floor()) return; // pre-V20 => fail closed
        auto work_hash = m_hash_at_height(work_h);
        if (!work_hash || work_hash->IsNull()) return;   // work header gap

        reap_if_needed();

        Pending pend;
        pend.type        = llmq_type;
        pend.quorum_hash = quorum_hash;
        pend.work_height = work_h;
        pend.work_hash   = *work_hash;
        m_pending.emplace(key, std::move(pend));
        m_pending_fifo.push_back(key);

        // ONE full snapshot at the WORK block carries BOTH member-selection
        // inputs (SML + cbTx bestCLSignature). Dedup outstanding requests BY
        // HASH (R1): if an await for this block already exists (a sibling type
        // sharing the cycle base), ride it — do NOT draw a second reply.
        auto& waiters = m_await[*work_hash];
        waiters.push_back(key);
        if (waiters.size() == 1) {
            m_send(uint256::ZERO, *work_hash);
            LOG_INFO << "[QC-MEMBERS] sourcing work-block snapshot "
                     << work_hash->GetHex().substr(0, 16) << " (work_h=" << work_h
                     << ") for type=" << static_cast<int>(llmq_type)
                     << " quorum=" << quorum_hash.GetHex().substr(0, 16)
                     << " base_h=" << *base_h;
        } else {
            LOG_INFO << "[QC-MEMBERS] type=" << static_cast<int>(llmq_type)
                     << " quorum=" << quorum_hash.GetHex().substr(0, 16)
                     << " rides outstanding snapshot request for work block "
                     << work_hash->GetHex().substr(0, 16)
                     << " (" << waiters.size() << " waiters)";
        }
    }

    /// True iff a mnlistdiff for `block_hash` is one this source requested.
    bool awaiting(const uint256& block_hash) const
    {
        return m_await.count(block_hash) != 0;
    }

    /// Consume a historical work-block snapshot. Returns TRUE iff the diff
    /// matched an outstanding await (so the caller must NOT also feed the
    /// tip-SML maintainer) — including when it then FAILS authentication (the
    /// pendings fail closed; the reply still must not leak to the tip path).
    /// STRICT match (R1): only a FULL snapshot (baseBlockHash null) at an
    /// awaited block hash matches; anything else is not ours.
    bool on_mnlistdiff(const vendor::CSimplifiedMNListDiff& diff)
    {
        if (!diff.baseBlockHash.IsNull()) return false;   // not a full snapshot
        auto ai = m_await.find(diff.blockHash);
        if (ai == m_await.end()) return false;
        const std::vector<Key> keys = ai->second;
        m_await.erase(ai);

        // ── R3: DIP-4 client verification — authenticate BEFORE believing ──
        vendor::CCbTx cbtx;
        std::optional<vendor::CSimplifiedMNList> sml =
            authenticate_snapshot(diff, keys, cbtx);
        if (!sml) {
            for (const auto& key : keys) erase_pending(key);
            return true;   // consumed (matched an await) — but failed closed
        }

        // ── finalize every waiter off the ONE verified snapshot ────────────
        for (const auto& key : keys) {
            auto pi = m_pending.find(key);
            if (pi == m_pending.end()) continue;
            finalize(pi->second, *sml, cbtx);
            erase_pending(key);
        }
        return true;
    }

    size_t ready_count() const { return m_ready.size(); }
    size_t pending_count() const { return m_pending.size(); }

private:
    // llmq/snapshot.h @ v23.1.7: WORK_DIFF_DEPTH = 8.
    static constexpr uint32_t kWorkDiffDepth = 8;

    struct Key {
        uint8_t llmqType;
        uint256 quorumHash;
        bool operator<(const Key& r) const
        {
            if (llmqType != r.llmqType) return llmqType < r.llmqType;
            return std::memcmp(quorumHash.data(), r.quorumHash.data(), 32) < 0;
        }
        bool operator==(const Key& r) const
        {
            return llmqType == r.llmqType && quorumHash == r.quorumHash;
        }
    };
    struct Pending {
        uint8_t  type{0};
        uint256  quorum_hash;
        uint32_t work_height{0};
        uint256  work_hash;
    };

    const LlmqParamsView* params_for(uint8_t type) const
    {
        for (const auto& p : enabled_llmqs(m_net))
            if (p.type == type) return &p;
        return nullptr;
    }

    uint32_t quorum_members_v20_floor() const
    {
        return m_net == LlmqNetwork::Mainnet ? vendor::kV20FloorMainnet
                                             : vendor::kV20FloorTestnet;
    }

    uint8_t llmq_type_platform() const
    {
        return m_net == LlmqNetwork::Mainnet
            ? vendor::kLlmqTypePlatformMainnet
            : vendor::kLlmqTypePlatformTestnet;
    }

    /// R3 — DIP-4 client verification of a historical full snapshot:
    ///   (a) embedded cbTx is a type-5 CCbTx at the expected work height;
    ///   (b) cbTxMerkleTree proves that cbTx into the PoW-verified work-block
    ///       header's hashMerkleRoot at tx index 0;
    ///   (c) applied-SML merkle root == cbTx.merkleRootMNList.
    /// Returns the verified SML (and fills `cbtx_out`), or std::nullopt.
    std::optional<vendor::CSimplifiedMNList> authenticate_snapshot(
        const vendor::CSimplifiedMNListDiff& diff,
        const std::vector<Key>& keys, vendor::CCbTx& cbtx_out) const
    {
        const uint32_t expect_h =
            keys.empty() ? 0 : expected_work_height(keys.front());
        auto fail = [&](const char* why) -> std::optional<vendor::CSimplifiedMNList> {
            LOG_WARNING << "[QC-MEMBERS] snapshot AUTH FAILED (" << why
                        << ") for block " << diff.blockHash.GetHex().substr(0, 16)
                        << " — " << keys.size()
                        << " quorum(s) fail closed (null-serve)";
            return std::nullopt;
        };

        // (a) cbTx: coinbase, special-tx type 5, parseable payload, height
        // bound to the request (a peer cannot satisfy the await with a
        // different — even genuine — block's snapshot).
        if (diff.cbTx.type != 5 || diff.cbTx.extra_payload.empty())
            return fail("cbTx not a type-5 CbTx");
        if (!vendor::parse_cbtx(diff.cbTx.extra_payload, cbtx_out))
            return fail("cbTx payload unparseable");
        if (expect_h == 0 || cbtx_out.nHeight < 0
            || static_cast<uint32_t>(cbtx_out.nHeight) != expect_h)
            return fail("cbTx height != expected work height");

        // (b) merkle proof against the verified header.
        auto header_root = m_merkle_root_of_hash(diff.blockHash);
        if (!header_root || header_root->IsNull())
            return fail("work-block header not held");
        std::vector<uint256> matches;
        std::vector<unsigned int> match_idx;
        const uint256 proof_root =
            diff.cbTxMerkleTree.ExtractMatches(matches, match_idx);
        if (proof_root.IsNull() || proof_root != *header_root)
            return fail("cbTxMerkleTree root != header merkle root");
        const uint256 cbtx_hash = dash_txid(diff.cbTx);
        if (matches.size() != 1 || match_idx.size() != 1 || match_idx[0] != 0
            || matches[0] != cbtx_hash)
            return fail("cbTx not proven at coinbase position");

        // (c) SML root commitment.
        vendor::CSimplifiedMNList sml;
        vendor::apply_diff(sml, diff);   // base=ZERO: apply onto empty
        if (sml.CalcMerkleRoot() != cbtx_out.merkleRootMNList)
            return fail("SML root != cbTx.merkleRootMNList");

        return sml;
    }

    uint32_t expected_work_height(const Key& key) const
    {
        auto pi = m_pending.find(key);
        return pi == m_pending.end() ? 0 : pi->second.work_height;
    }

    void finalize(const Pending& pend, const vendor::CSimplifiedMNList& sml,
                  const vendor::CCbTx& cbtx)
    {
        const LlmqParamsView* p = params_for(pend.type);
        if (p == nullptr) return;

        // R5: the work block's OWN cbTx CL, or the upstream fallback modifier
        // when it is null — GetNonNullCoinbaseChainlock does not walk back.
        std::optional<std::array<uint8_t, vendor::CFinalCommitment::BLS_SIG_SIZE>> clsig;
        if (cbtx.nVersion >= vendor::CCbTx::VERSION_CLSIG_AND_BALANCE
            && cbtx.has_best_cl_signature()) {
            clsig = cbtx.bestCLSignature;
        }
        const uint256 modifier = vendor::compute_quorum_modifier(
            pend.type, pend.work_height, clsig, pend.work_hash);

        vendor::QuorumMemberParams qp{p->type, p->size, p->use_rotation,
                                      /*evo_only=*/p->type == llmq_type_platform()};
        auto members = vendor::compute_quorum_members(qp, modifier, sml);
        if (members) {
            insert_ready(Key{pend.type, pend.quorum_hash}, std::move(*members));
            LOG_INFO << "[QC-MEMBERS] READY type=" << static_cast<int>(pend.type)
                     << " quorum=" << pend.quorum_hash.GetHex().substr(0, 16)
                     << " members=" << p->size
                     << (clsig ? "" : " (null-CL fallback modifier)")
                     << " (real-commitment serving ENABLED for this quorum)";
        } else {
            LOG_WARNING << "[QC-MEMBERS] member computation ambiguous for quorum "
                        << pend.quorum_hash.GetHex().substr(0, 16)
                        << " -> fail closed (null-serve)";
        }
    }

    void erase_pending(const Key& key)
    {
        m_pending.erase(key);
        for (auto it = m_pending_fifo.begin(); it != m_pending_fifo.end(); ++it) {
            if (*it == key) { m_pending_fifo.erase(it); break; }
        }
    }

    // Bound outstanding requests: evict the OLDEST pending (and its await
    // membership) once the cap is hit — a dead peer must not grow state
    // forever, and an evicted quorum simply stays null-serve (fail-safe).
    void reap_if_needed()
    {
        while (m_pending.size() >= kPendingCap && !m_pending_fifo.empty()) {
            const Key victim = m_pending_fifo.front();
            auto pi = m_pending.find(victim);
            if (pi != m_pending.end()) {
                auto ai = m_await.find(pi->second.work_hash);
                if (ai != m_await.end()) {
                    auto& v = ai->second;
                    for (auto it = v.begin(); it != v.end(); ++it) {
                        if (*it == victim) { v.erase(it); break; }
                    }
                    if (v.empty()) m_await.erase(ai);
                }
                m_pending.erase(pi);
            }
            m_pending_fifo.pop_front();
        }
    }

    void insert_ready(const Key& key, std::vector<vendor::MemberOperatorKey>&& v)
    {
        if (m_ready.find(key) == m_ready.end()) {
            m_ready_fifo.push_back(key);
            if (m_ready_fifo.size() > kReadyCap) {
                m_ready.erase(m_ready_fifo.front());
                m_ready_fifo.pop_front();
            }
        }
        m_ready[key] = std::move(v);
    }

    LlmqNetwork      m_net;
    HashAtHeight     m_hash_at_height;
    HeightOfHash     m_height_of_hash;
    MerkleRootOfHash m_merkle_root_of_hash;
    SendGetMnListd   m_send;

    std::map<Key, std::vector<vendor::MemberOperatorKey>> m_ready;
    std::deque<Key> m_ready_fifo;
    std::map<Key, Pending> m_pending;
    std::deque<Key> m_pending_fifo;
    std::map<uint256, std::vector<Key>> m_await;   // work-block hash -> waiters
};

} // namespace coin
} // namespace dash
