#pragma once

// QuorumManager: in-memory tracker for the active LLMQ quorum set.
// Phase C-QUO step 3.
//
// Consumes the structured QuorumTail from each accepted mnlistdiff:
//   - Erase entries whose (llmqType, quorumHash) appears in deletedQuorums
//   - For each entry in newQuorums: insert/replace by (llmqType, quorumHash)
//   - Cache the latest quorumsCLSigs for Phase L's ChainLock-cycle
//     verifier to reach (it indexes into newQuorums by uint16 position
//     within the most-recent diff).
//
// Persistence is via QuorumDb (sister of SMLDb): on every accepted
// mnlistdiff we apply() in-memory, then flush state to LevelDB. On
// startup main_dash loads from QuorumDb via replace_state() before any
// diff arrives. Without persistence, ChainLock verify returns NO_POOL
// after every restart until a cold-start mnlistdiff(zero, tip) refills
// the active set — which never happens in steady state because the
// next diff is incremental.
//
// Thread-safety: all mutation goes through the on_mnlistdiff handler
// which posts to ioc; reads from other threads (Phase L's clsig
// verifier) need a shared_mutex once that lands. For now we assume
// single-threaded ioc access.

#include <impl/dash/coin/vendor/llmq_commitment.hpp>
#include <impl/dash/coin/vendor/quorum_tail.hpp>

#include <core/uint256.hpp>
#include <core/log.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

class QuorumManager
{
public:
    // Composite key for active-set lookup. We use a flat vector instead
    // of an unordered_map because we expect ~100-200 active quorums on
    // mainnet at any time and lookups are infrequent (Phase L's
    // ChainLock verifier will dominate read traffic).
    struct ActiveKey {
        uint8_t llmqType;
        uint256 quorumHash;

        bool operator==(const ActiveKey& r) const
        {
            return llmqType == r.llmqType && quorumHash == r.quorumHash;
        }
    };

    struct Entry {
        ActiveKey                  key;
        vendor::CFinalCommitment   commitment;
        // Phase C-TEMPLATE step 4 prep: the block height where this
        // quorum's qfcommit tx was mined. Populated by the
        // [QC-MINED] scanner in main_dash on_full_block when the tx
        // is observed. 0 = unknown (mnlistdiff added the quorum but
        // we haven't yet seen the corresponding qfcommit tx — happens
        // for quorums added before our header checkpoint, or while
        // bootstrap is still draining).
        //
        // dashcore's GetMinedCommitmentsUntilBlock orders quorums by
        // mining height (newest first per llmqType), which feeds
        // CalcCbTxMerkleRootQuorums. Without this field we can't
        // mirror that ordering in step 4c's compute_merkle_root_quorums.
        //
        // NOT YET PERSISTED. QuorumDb still serializes only the
        // commitment; on restart, mining_height resets to 0 and
        // repopulates as we observe blocks. Persistence lands in the
        // same commit as compute_merkle_root_quorums (when it
        // actually starts to matter).
        uint32_t                   mining_height{0};
    };

    // Look up an entry by (llmqType, quorumHash) and return a mutable
    // pointer for in-place state updates (used by the qfcommit
    // scanner to set mining_height when a type-6 tx is observed).
    // Returns nullptr if not in active set.
    Entry* find_mutable(uint8_t llmqType, const uint256& quorumHash)
    {
        for (auto& e : m_active) {
            if (e.key.llmqType == llmqType
                && e.key.quorumHash == quorumHash) {
                return &e;
            }
        }
        return nullptr;
    }

    // Apply a parsed quorum tail. Mutates the active set in place.
    // Returns the count of inserts/replaces and deletes for logging.
    struct ApplyResult {
        size_t added_or_updated{0};
        size_t deleted{0};
        size_t cl_sigs_cached{0};
        size_t active_after{0};
    };

    ApplyResult apply(const vendor::QuorumTail& tail)
    {
        ApplyResult r;

        if (!tail.deletedQuorums.empty()) {
            auto before = m_active.size();
            m_active.erase(
                std::remove_if(m_active.begin(), m_active.end(),
                    [&](const Entry& e) {
                        for (const auto& [t, h] : tail.deletedQuorums) {
                            if (e.key.llmqType == t
                                && e.key.quorumHash == h) {
                                return true;
                            }
                        }
                        return false;
                    }),
                m_active.end());
            r.deleted = before - m_active.size();
        }

        for (const auto& nq : tail.newQuorums) {
            ActiveKey k{nq.llmqType, nq.quorumHash};
            auto it = std::find_if(m_active.begin(), m_active.end(),
                [&](const Entry& e) { return e.key == k; });
            if (it != m_active.end()) {
                it->commitment = nq;
            } else {
                m_active.push_back(Entry{k, nq});
            }
            ++r.added_or_updated;
        }

        // Replace cached CL sigs each diff (the previous diff's sigs
        // are now stale — they refer to that diff's newQuorums-order
        // indices, not ours).
        m_latest_cl_sigs = tail.quorumsCLSigs;
        r.cl_sigs_cached = m_latest_cl_sigs.size();
        r.active_after = m_active.size();
        return r;
    }

    // Look up a commitment by (llmqType, quorumHash). Used by Phase L's
    // ChainLock verifier: given a clsig blob and the quorum that should
    // have signed it, fetch the quorum public key for verification.
    std::optional<vendor::CFinalCommitment>
    find(uint8_t llmqType, const uint256& quorumHash) const
    {
        for (const auto& e : m_active) {
            if (e.key.llmqType == llmqType
                && e.key.quorumHash == quorumHash) {
                return e.commitment;
            }
        }
        return std::nullopt;
    }

    size_t active_count() const { return m_active.size(); }

    // Expose active entries by const reference for iteration. Used by
    // chainlock_verify.hpp to walk the LLMQ_400_60 candidates when
    // selecting the signing quorum.
    const std::vector<Entry>& active_entries() const { return m_active; }

    // Per-type counts for logging / dashboard.
    std::unordered_map<uint8_t, size_t> active_by_type() const
    {
        std::unordered_map<uint8_t, size_t> out;
        for (const auto& e : m_active) ++out[e.key.llmqType];
        return out;
    }

    void clear()
    {
        m_active.clear();
        m_latest_cl_sigs.clear();
    }

    // Latest cached quorumsCLSigs from the most recent diff. Each entry
    // is (96-byte recovered BLS sig, vector<uint16_t> indices into the
    // most-recent diff's newQuorums). Persistence flushes this so a
    // restart between two mnlistdiffs doesn't lose the cycle map Phase L
    // reaches into.
    using CLSig = std::pair<
        std::array<uint8_t, vendor::CFinalCommitment::BLS_SIG_SIZE>,
        std::vector<uint16_t>>;

    const std::vector<CLSig>& latest_cl_sigs() const
    {
        return m_latest_cl_sigs;
    }

    // Bulk-replace state — used by QuorumDb::load_into() to warm the
    // active set + latest CL sigs from disk before the first incremental
    // diff arrives. On post-restart steady state this avoids needing a
    // full cold-start mnlistdiff(zero, tip).
    void replace_state(std::vector<Entry>&& active,
                       std::vector<CLSig>&& cl_sigs)
    {
        m_active        = std::move(active);
        m_latest_cl_sigs = std::move(cl_sigs);
    }

private:
    std::vector<Entry> m_active;

    // Most-recent diff's quorumsCLSigs — kept verbatim for Phase L's
    // cycle-shuffle verifier. Indices reference m_active positions of
    // the entries inserted from THIS diff; on the next diff they go
    // stale and we replace them.
    std::vector<CLSig> m_latest_cl_sigs;
};

} // namespace coin
} // namespace dash
