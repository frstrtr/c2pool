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
// No persistence at MVP — cold-start mnlistdiff(zeros, tip) returns the
// full active quorum set in newQuorums alongside the SML, so we
// re-bootstrap from peers in ~400 KB once. Persistence is a Phase L
// optimization if reconstruction-on-restart proves slow in practice.
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
    };

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

private:
    std::vector<Entry> m_active;

    // Most-recent diff's quorumsCLSigs — kept verbatim for Phase L's
    // cycle-shuffle verifier. Indices reference m_active positions of
    // the entries inserted from THIS diff; on the next diff they go
    // stale and we replace them.
    std::vector<std::pair<
        std::array<uint8_t, vendor::CFinalCommitment::BLS_SIG_SIZE>,
        std::vector<uint16_t>>> m_latest_cl_sigs;
};

} // namespace coin
} // namespace dash
