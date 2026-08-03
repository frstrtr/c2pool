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
/// ROTATED (DIP-24): request() still no-ops for a rotated type and the
/// verifier stays fail-closed, because the quarter-rotation member COMPUTATION
/// is not ported yet. What DOES exist now is the sourcing half: request_rotated()
/// emits a getqrinfo and on_qrinfo() DIP-4 authenticates all four cycle
/// mnlistdiffs (each bound to the height the cycle geometry demands) and hands
/// back the authenticated SMLs + snapshots. Wiring those into m_ready is the
/// remaining follow-up — see the item 3/4 note on the rotated branch of
/// request().
///
/// FAIL-CLOSED throughout: pre-V20 work block, base not dkgInterval-aligned,
/// header gap, rotated type, snapshot authentication failure, member
/// computation ambiguous -> the quorum simply never becomes ready and the
/// verifier serves null.
///
/// Threading: all entry points run on the single coin ioc thread (same
/// assumption as QuorumManager) — no internal locking.

#include <impl/dash/coin/historical_sml.hpp>       // authenticate_historical_snapshot (shared R3)
#include <impl/dash/coin/dkg_commitments.hpp>          // LlmqNetwork, enabled_llmqs
#include <impl/dash/coin/utxo_adapter.hpp>             // dash_txid
#include <impl/dash/coin/vendor/quorum_members.hpp>    // compute_quorum_members
#include <impl/dash/coin/vendor/smldiff.hpp>           // CSimplifiedMNListDiff, apply_diff, ExtractMatches
#include <impl/dash/coin/vendor/cbtx.hpp>              // CCbTx, parse_cbtx
#include <impl/dash/coin/vendor/simplifiedmns.hpp>     // CSimplifiedMNList
#include <impl/dash/coin/vendor/quorum_rotation_info.hpp>  // DIP-24 CQuorumRotationInfo / CQuorumSnapshot

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <array>
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
            // STATUS — items 1 and 2 have LANDED; 3 and 4 have not:
            //   1. DONE — getqrinfo/qrinfo wire: p2p_messages.hpp
            //      message_getqrinfo / message_qrinfo, send seam
            //      CoinClient::send_getqrinfo (analogous to send_getmnlistd).
            //   2. DONE — CQuorumRotationInfo decode
            //      (vendor/quorum_rotation_info.hpp), field order PINNED against
            //      a real 602'189-byte capture, plus per-mnlistdiff DIP-4
            //      authentication with the SAME discipline as
            //      authenticate_snapshot: see request_rotated() / on_qrinfo()
            //      below. Each cycle diff is bound to its EXPECTED height, so a
            //      peer cannot substitute another block's genuine snapshot.
            //   3. TODO — vendor::compute_quorum_members_by_quarter_rotation:
            //      port of dashcore ComputeQuorumMembersByQuarterRotation +
            //      BuildNewQuorumQuarterMembers + the snapshot skip-list decode
            //      (GetQuorumQuarterMembersBySnapshot), producing the ordered
            //      MemberOperatorKey vector — MUST reproduce the captured order
            //      in test/data/dash_rotated_quorum_members_kat.hpp.
            //   4. TODO — feed that set to the SAME m_ready map so lookup() (and
            //      #812's verify_final_commitment) serves rotated commitments
            //      real.
            //
            // Until 3 lands there is NOTHING to put in m_ready, so THIS entry
            // point stays fail-closed and, deliberately, does NOT emit a
            // getqrinfo: issuing a live request whose reply cannot yet produce
            // a member set would add traffic to the reward path for no gain.
            // The sourcing half is reachable and tested via request_rotated()
            // + on_qrinfo(); item 3 flips this branch to call request_rotated()
            // and finalize_rotated() to fill m_ready. That is the whole delta.
            // Fail-closed if qrinfo can't be sourced or any cycle mnlistdiff
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

    // ═══ DIP-24 ROTATED SOURCING (items 1+2) ═══════════════════════════════
    // Wire + authenticated decode. The member-set computation itself (item 3,
    // compute_quorum_members_by_quarter_rotation) is NOT here yet, so nothing
    // reaches m_ready down this path and lookup() still fails closed for
    // rotated types. Everything below is exercised by the real-vector KAT.

    using SendGetQrInfo = std::function<void(const std::vector<uint256>& bases,
                                            const uint256& request_hash,
                                            bool extra_share)>;

    /// Optional (not a constructor arg, so no existing call site changes).
    void set_send_getqrinfo(SendGetQrInfo f) { m_send_qrinfo = std::move(f); }

    /// The four cycle SMLs a rotated member computation consumes, each already
    /// DIP-4 authenticated and bound to its expected height.
    struct RotatedInputs {
        uint8_t  llmq_type{0};
        uint256  quorum_hash;
        uint32_t cycle_base_height{0};
        // heights: H = base-8, then -C, -2C, -3C
        std::array<uint32_t, 4>                      heights{};
        std::array<vendor::CSimplifiedMNList, 4>     smls{};
        std::array<vendor::CQuorumSnapshot, 3>       snapshots{};  // H-C, H-2C, H-3C
        std::vector<vendor::CFinalCommitment>        last_commitment_per_index;
    };

    /// Ask a peer for the rotation info backing `quorum_hash`. Returns false
    /// (and sends nothing) when the request cannot be validated locally —
    /// unknown/non-rotated type, unaligned base, missing header, pre-V20.
    /// EMPTY baseBlockHashes on purpose: it makes the peer answer with FULL
    /// (from-genesis) lists, and only a full list is self-authenticating
    /// against its own cbTx.merkleRootMNList.
    bool request_rotated(uint8_t llmq_type, const uint256& quorum_hash)
    {
        const LlmqParamsView* p = params_for(llmq_type);
        if (p == nullptr || !p->use_rotation) return false;
        if (!m_send_qrinfo) return false;

        auto base_h = m_height_of_hash(quorum_hash);
        if (!base_h) return false;
        if (p->dkg_interval == 0 || *base_h % p->dkg_interval != 0) return false;
        // Need H-3C to exist: base - 8 - 3*C.
        const uint64_t span = static_cast<uint64_t>(kWorkDiffDepth)
                            + 3ull * p->dkg_interval;
        if (*base_h < span) return false;
        if (*base_h - kWorkDiffDepth < quorum_members_v20_floor()) return false;

        m_rotated_pending[Key{llmq_type, quorum_hash}] = *base_h;
        m_send_qrinfo(std::vector<uint256>{}, quorum_hash, /*extra_share=*/false);
        LOG_INFO << "[QC-MEMBERS] sourcing qrinfo for ROTATED type="
                 << static_cast<int>(llmq_type) << " quorum="
                 << quorum_hash.GetHex().substr(0, 16)
                 << " cycle_base_h=" << *base_h;
        return true;
    }

    /// Consume a qrinfo reply. DIP-4 authenticates EVERY cycle mnlistdiff with
    /// the same discipline as the non-rotated path, binding each to the height
    /// the cycle geometry says it must be — a peer cannot answer with another
    /// block's genuine snapshot. Returns the authenticated inputs, or nullopt
    /// (fail closed) if anything does not check out.
    std::optional<RotatedInputs>
    on_qrinfo(const vendor::CQuorumRotationInfo& info)
    {
        // Which outstanding rotated request is this? Bind by the H diff's
        // height: H must be (cycle_base - 8) for exactly one pending.
        vendor::CCbTx probe_cbtx;
        if (info.mnListDiffH.cbTx.type != 5
            || !vendor::parse_cbtx(info.mnListDiffH.cbTx.extra_payload, probe_cbtx)
            || probe_cbtx.nHeight < 0) {
            LOG_WARNING << "[QC-MEMBERS] qrinfo: mnListDiffH carries no usable "
                           "type-5 cbTx — fail closed";
            return std::nullopt;
        }
        const uint64_t h_height = static_cast<uint64_t>(probe_cbtx.nHeight);

        const Key* match = nullptr;
        uint32_t   base_h = 0;
        for (const auto& [key, base] : m_rotated_pending) {
            if (static_cast<uint64_t>(base) == h_height + kWorkDiffDepth) {
                match = &key;
                base_h = base;
                break;
            }
        }
        if (match == nullptr) {
            LOG_WARNING << "[QC-MEMBERS] qrinfo at H=" << h_height
                        << " matches no outstanding rotated request — dropped";
            return std::nullopt;
        }
        const Key key = *match;

        const LlmqParamsView* p = params_for(key.llmqType);
        if (p == nullptr || !p->use_rotation || p->dkg_interval == 0) {
            m_rotated_pending.erase(key);
            return std::nullopt;
        }
        const uint32_t C = p->dkg_interval;

        RotatedInputs out;
        out.llmq_type        = key.llmqType;
        out.quorum_hash      = key.quorumHash;
        out.cycle_base_height = base_h;

        const vendor::CSimplifiedMNListDiff* diffs[4] = {
            &info.mnListDiffH,
            &info.mnListDiffAtHMinusC,
            &info.mnListDiffAtHMinus2C,
            &info.mnListDiffAtHMinus3C,
        };
        for (size_t i = 0; i < 4; ++i) {
            const uint32_t expect_h =
                base_h - kWorkDiffDepth - static_cast<uint32_t>(i) * C;
            out.heights[i] = expect_h;

            // A qrinfo cycle diff MUST be a FULL list: authentication applies
            // it onto an EMPTY list, so an incremental diff would authenticate
            // a list that is not the one at that height.
            //
            // ⚠ NOT the same test as the getmnlistd path's baseBlockHash.IsNull().
            // Observed from a real dashd: when the request carries an EMPTY
            // baseBlockHashes, the qrinfo diffs come back with baseBlockHash =
            // the GENESIS hash, not ZERO. So "full" is signalled here by having
            // nothing to delete (from genesis there is nothing to delete), and
            // the actual GUARANTEE is leg (c) of the authentication below: the
            // applied-onto-empty SML root must equal cbTx.merkleRootMNList, which
            // an incremental diff cannot satisfy.
            if (!diffs[i]->deletedMNs.empty()) {
                LOG_WARNING << "[QC-MEMBERS] qrinfo cycle diff " << i
                            << " deletes " << diffs[i]->deletedMNs.size()
                            << " entries — not a FULL list, fail closed";
                m_rotated_pending.erase(key);
                return std::nullopt;
            }
            vendor::CCbTx cbtx;
            auto sml = authenticate_historical_snapshot(
                *diffs[i], expect_h, m_merkle_root_of_hash, cbtx, "QC-MEMBERS");
            if (!sml) {
                LOG_WARNING << "[QC-MEMBERS] qrinfo cycle diff " << i
                            << " failed DIP-4 authentication at expected h="
                            << expect_h << " — whole reply fails closed";
                m_rotated_pending.erase(key);
                return std::nullopt;
            }
            out.smls[i] = std::move(*sml);
        }

        out.snapshots[0] = info.quorumSnapshotAtHMinusC;
        out.snapshots[1] = info.quorumSnapshotAtHMinus2C;
        out.snapshots[2] = info.quorumSnapshotAtHMinus3C;
        out.last_commitment_per_index = info.lastCommitmentPerIndex;

        m_rotated_pending.erase(key);
        LOG_INFO << "[QC-MEMBERS] qrinfo AUTHENTICATED for rotated type="
                 << static_cast<int>(key.llmqType) << " quorum="
                 << key.quorumHash.GetHex().substr(0, 16)
                 << " cycle_base_h=" << base_h
                 << " (H=" << out.heights[0] << ") — inputs ready; member "
                    "computation (quarter rotation) NOT YET PORTED, so this "
                    "quorum remains null-serve";
        return out;
    }

    size_t rotated_pending_count() const { return m_rotated_pending.size(); }

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
        // Shared with the daemonless MN-set bridge — see historical_sml.hpp.
        // Both consumers authenticate a peer-supplied historical list on the
        // reward path and must do it identically; two copies would be two
        // places for it to rot.
        const uint32_t expect_h =
            keys.empty() ? 0 : expected_work_height(keys.front());
        auto sml = authenticate_historical_snapshot(
            diff, expect_h, m_merkle_root_of_hash, cbtx_out, "QC-MEMBERS");
        if (!sml) {
            LOG_WARNING << "[QC-MEMBERS] " << keys.size()
                        << " quorum(s) fail closed (null-serve)";
        }
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

    SendGetQrInfo             m_send_qrinfo;
    std::map<Key, uint32_t>   m_rotated_pending;   // rotated key -> cycle base h
};

} // namespace coin
} // namespace dash
