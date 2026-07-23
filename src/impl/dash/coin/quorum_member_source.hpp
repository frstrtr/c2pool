// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E1 Phase-L — daemonless sourcing of the deterministic quorum MEMBER SET, the
/// input #812's verify_final_commitment needs to serve a REAL commitment.
///
/// verify_final_commitment(commitment, members) needs the ordered operator-key
/// set of the quorum's members. That set is ComputeQuorumMembers over the SML
/// AS OF the quorum base block (quorum_members.hpp) — but the embedded SML (E3)
/// tracks the TIP, not arbitrary historical heights. This module sources the
/// two historical inputs off the SAME coin-P2P client the E3 SML sync already
/// uses (getmnlistd/mnlistdiff), computes the member set, and caches it for the
/// synchronous MemberKeysProvider lookup:
///
///   * historical SML @ quorum base block: a full cold-start diff
///     getmnlistd(ZERO, quorumHash) — the projected DMN list at that block.
///   * coinbase ChainLock @ work block (base - 8): getmnlistd(ZERO, workHash);
///     the diff's embedded cbTx carries bestCLSignature. When that block's CL
///     is null we walk back (dashcore GetNonNullCoinbaseChainlock) up to a
///     bounded number of blocks.
///
/// ASYNC by necessity: the provider is called synchronously while building a
/// template and MUST NOT block on I/O, so it only READS this cache. Population
/// is driven off relayed qfcommits (request() is kicked when a commitment for a
/// quorum is admitted) and completes when both getmnlistd replies land. Until
/// then lookup() returns std::nullopt -> the verifier fails closed -> the slot
/// mines the consensus-valid null commitment (reward-safe), exactly the
/// pre-Phase-L posture.
///
/// DEMUX (reward-critical): historical getmnlistd replies must NOT reach the
/// E3 tip-SML maintainer — a full snapshot at an OLD base block would overwrite
/// the tip SML. on_mnlistdiff() returns TRUE when it consumed a reply it was
/// awaiting; main_dash routes such replies here and skips the tip feed.
///
/// ROTATED (DIP-24): request() no-ops for a rotated type (compute is
/// unsupported there); the verifier stays fail-closed. qrinfo-based rotated
/// sourcing is the documented follow-up.
///
/// FAIL-CLOSED throughout: pre-V20 base block, header gap, rotated type, member
/// computation ambiguous, CL unresolved within the walk-back bound -> the
/// quorum simply never becomes ready and the verifier serves null.
///
/// Threading: all entry points run on the single coin ioc thread (same
/// assumption as QuorumManager) — no internal locking.

#include <impl/dash/coin/dkg_commitments.hpp>          // LlmqNetwork, enabled_llmqs
#include <impl/dash/coin/vendor/quorum_members.hpp>    // compute_quorum_members
#include <impl/dash/coin/vendor/smldiff.hpp>           // CSimplifiedMNListDiff, apply_diff
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
    using SendGetMnListd = std::function<void(const uint256& base, const uint256& target)>;

    // Bound on the GetNonNullCoinbaseChainlock walk-back (in practice the work
    // block itself carries a non-null CL on a ChainLocked chain; a small bound
    // covers a short CL gap and caps request amplification).
    static constexpr uint32_t kClWalkbackMax = 32;
    // Soft cap on cached member sets (each ~ size*49 bytes); FIFO eviction.
    static constexpr size_t kReadyCap = 1024;

    QuorumMemberSource(LlmqNetwork net, HashAtHeight hash_at_height,
                       HeightOfHash height_of_hash, SendGetMnListd send)
        : m_net(net), m_hash_at_height(std::move(hash_at_height))
        , m_height_of_hash(std::move(height_of_hash)), m_send(std::move(send))
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
        if (p == nullptr || p->use_rotation) return;   // rotated => qrinfo TODO

        auto base_h = m_height_of_hash(quorum_hash);
        if (!base_h) return;                            // base header not held yet
        if (*base_h < 8) return;                        // no work block
        const uint32_t work_h = *base_h - 8;
        if (work_h < quorum_members_v20_floor()) return; // pre-V20 => fail closed
        auto work_hash = m_hash_at_height(work_h);
        if (!work_hash || work_hash->IsNull()) return;   // work header gap

        Pending pend;
        pend.type       = llmq_type;
        pend.quorum_hash = quorum_hash;
        pend.work_height = work_h;
        pend.cl_block    = *work_hash;
        m_pending.emplace(key, std::move(pend));

        // SML @ base block, and the cbTx-bearing diff @ work block.
        m_await_sml[quorum_hash].push_back(key);
        m_await_cl[*work_hash].push_back(key);
        m_send(uint256::ZERO, quorum_hash);
        m_send(uint256::ZERO, *work_hash);
        LOG_INFO << "[QC-MEMBERS] sourcing type=" << static_cast<int>(llmq_type)
                 << " quorum=" << quorum_hash.GetHex().substr(0, 16)
                 << " base_h=" << *base_h << " work_h=" << work_h;
    }

    /// True iff a mnlistdiff for `block_hash` is one this source requested — the
    /// demux predicate main_dash consults BEFORE feeding the tip maintainer.
    bool awaiting(const uint256& block_hash) const
    {
        return m_await_sml.count(block_hash) || m_await_cl.count(block_hash);
    }

    /// Consume a historical mnlistdiff. Returns TRUE iff it matched a pending
    /// request (so the caller must NOT also feed the tip-SML maintainer). A diff
    /// can satisfy an SML await, a CL await, or (rarely) both.
    bool on_mnlistdiff(const vendor::CSimplifiedMNListDiff& diff)
    {
        bool consumed = false;
        consumed |= consume_sml(diff);
        consumed |= consume_cl(diff);
        return consumed;
    }

    size_t ready_count() const { return m_ready.size(); }
    size_t pending_count() const { return m_pending.size(); }

private:
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
        uint256  cl_block;                 // block currently awaited for the CL
        uint32_t walkback{0};
        std::optional<vendor::CSimplifiedMNList> sml;
        std::optional<std::array<uint8_t, vendor::CFinalCommitment::BLS_SIG_SIZE>> clsig;
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

    bool consume_sml(const vendor::CSimplifiedMNListDiff& diff)
    {
        auto ai = m_await_sml.find(diff.blockHash);
        if (ai == m_await_sml.end()) return false;
        // base=ZERO => full snapshot; apply onto an empty list.
        vendor::CSimplifiedMNList sml;
        vendor::apply_diff(sml, diff);
        for (const auto& key : ai->second) {
            auto pi = m_pending.find(key);
            if (pi == m_pending.end()) continue;
            pi->second.sml = sml;
            try_finalize(key);
        }
        m_await_sml.erase(ai);
        return true;
    }

    bool consume_cl(const vendor::CSimplifiedMNListDiff& diff)
    {
        auto ai = m_await_cl.find(diff.blockHash);
        if (ai == m_await_cl.end()) return false;
        // Extract the work block's coinbase ChainLock from the diff's cbTx.
        vendor::CCbTx cbtx;
        const bool have_cbtx = vendor::parse_cbtx(diff.cbTx.extra_payload, cbtx);
        const std::vector<Key> keys = ai->second;   // copy: erase below
        m_await_cl.erase(ai);
        for (const auto& key : keys) {
            auto pi = m_pending.find(key);
            if (pi == m_pending.end()) continue;
            Pending& pend = pi->second;
            if (have_cbtx && cbtx.has_best_cl_signature()) {
                pend.clsig = cbtx.bestCLSignature;
                try_finalize(key);
                continue;
            }
            // Null CL at this block — walk back one block and re-request,
            // exactly GetNonNullCoinbaseChainlock. Bounded to fail closed.
            if (pend.walkback >= kClWalkbackMax) {
                LOG_WARNING << "[QC-MEMBERS] CL walk-back exhausted for quorum "
                            << pend.quorum_hash.GetHex().substr(0, 16)
                            << " -> fail closed (null-serve)";
                m_pending.erase(pi);
                continue;
            }
            if (pend.work_height == 0) { m_pending.erase(pi); continue; }
            const uint32_t prev_h = pend.work_height - 1 - pend.walkback;
            auto prev_hash = m_hash_at_height(prev_h);
            if (!prev_hash || prev_hash->IsNull()) { m_pending.erase(pi); continue; }
            pend.walkback++;
            pend.cl_block = *prev_hash;
            m_await_cl[*prev_hash].push_back(key);
            m_send(uint256::ZERO, *prev_hash);
        }
        return true;
    }

    void try_finalize(const Key& key)
    {
        auto pi = m_pending.find(key);
        if (pi == m_pending.end()) return;
        Pending& pend = pi->second;
        if (!pend.sml || !pend.clsig) return;   // await the other leg

        const LlmqParamsView* p = params_for(pend.type);
        if (p == nullptr) { m_pending.erase(pi); return; }

        auto work_hash = m_hash_at_height(pend.work_height);
        const uint256 wh = work_hash ? *work_hash : uint256::ZERO;
        const uint256 modifier = vendor::compute_quorum_modifier(
            pend.type, pend.work_height, pend.clsig, wh);

        vendor::QuorumMemberParams qp{p->type, p->size, p->use_rotation};
        auto members = vendor::compute_quorum_members(qp, modifier, *pend.sml);
        if (members) {
            insert_ready(key, std::move(*members));
            LOG_INFO << "[QC-MEMBERS] READY type=" << static_cast<int>(pend.type)
                     << " quorum=" << pend.quorum_hash.GetHex().substr(0, 16)
                     << " members=" << p->size
                     << " (real-commitment serving ENABLED for this quorum)";
        } else {
            LOG_WARNING << "[QC-MEMBERS] member computation ambiguous for quorum "
                        << pend.quorum_hash.GetHex().substr(0, 16)
                        << " -> fail closed (null-serve)";
        }
        m_pending.erase(pi);
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

    LlmqNetwork  m_net;
    HashAtHeight m_hash_at_height;
    HeightOfHash m_height_of_hash;
    SendGetMnListd m_send;

    std::map<Key, std::vector<vendor::MemberOperatorKey>> m_ready;
    std::deque<Key> m_ready_fifo;
    std::map<Key, Pending> m_pending;
    std::map<uint256, std::vector<Key>> m_await_sml;
    std::map<uint256, std::vector<Key>> m_await_cl;
};

} // namespace coin
} // namespace dash
