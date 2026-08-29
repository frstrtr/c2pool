// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Phase C-QUO step 2: structured parser for the mnlistdiff "quorum tail"
// (deletedQuorums + newQuorums + quorumsCLSigs).
//
// Design constraint: smldiff.hpp's CSimplifiedMNListDiff keeps the tail
// as an opaque std::vector<uint8_t>. That choice is preserved — SML
// sync (the Phase C-SML acceptance gate) MUST NOT fail if quorum-tail
// parsing breaks on an unknown CFinalCommitment nVersion or wire-format
// drift.
//
// This header layers a fail-safe structured parser on TOP of the opaque
// tail. The on_mnlistdiff callback applies the SML first, then calls
// parse_quorum_tail() — on success the structured fields are returned;
// on any parse failure we log a warning and skip quorum tracking for
// that diff. SML sync continues unaffected.
//
// Wire format of the tail (dashcore evo/smldiff.h:65-80, gated on
// MNLISTDIFF_CHAINLOCKS_PROTO_VERSION which is 70230 == our advertised
// proto):
//
//   vector<pair<uint8_t llmqType, uint256 quorumHash>>  deletedQuorums
//   vector<CFinalCommitment>                            newQuorums
//   map<CBLSSignature(96B), set<uint16_t>>              quorumsCLSigs

#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/log.hpp>

#include <array>
#include <cstdint>
#include <set>
#include <utility>
#include <vector>

namespace dash {
namespace coin {
namespace vendor {

struct QuorumTail
{
    std::vector<std::pair<uint8_t, uint256>>  deletedQuorums;
    std::vector<CFinalCommitment>             newQuorums;

    // Pre-Phase-L we don't index this map by signature value; the
    // entries arrive in dashcore-canonical order and we just keep them
    // for forwarding into the manager (Phase L will deserialize the
    // shuffling ChainLocks here).
    std::vector<std::pair<
        std::array<uint8_t, CFinalCommitment::BLS_SIG_SIZE>,
        std::vector<uint16_t>>>               quorumsCLSigs;
};

// Decode the opaque tail. Returns true on bit-exact success (no
// trailing garbage). Returns false on any deserialization failure or
// trailing bytes — caller should log the failure and continue without
// the quorum data for this diff. The `out` parameter is left in an
// indeterminate state on failure.
inline bool parse_quorum_tail(const std::vector<unsigned char>& bytes,
                              QuorumTail& out)
{
    if (bytes.empty()) {
        // Nothing to parse — valid pre-MNLISTDIFF_CHAINLOCKS_PROTO peer
        // would emit zero tail; we never see that against current proto
        // 70230 but the empty-input case is still a clean success.
        out = QuorumTail{};
        return true;
    }

    try {
        ::PackStream s(bytes);

        // deletedQuorums
        {
            uint64_t n = ReadCompactSize(s);
            out.deletedQuorums.clear();
            out.deletedQuorums.reserve(n);
            for (uint64_t i = 0; i < n; ++i) {
                uint8_t llmqType = 0;
                uint256 hash;
                s >> llmqType;
                s >> hash;
                out.deletedQuorums.emplace_back(llmqType, hash);
            }
        }

        // newQuorums
        {
            uint64_t n = ReadCompactSize(s);
            out.newQuorums.clear();
            out.newQuorums.reserve(n);
            for (uint64_t i = 0; i < n; ++i) {
                CFinalCommitment c;
                s >> c;
                out.newQuorums.push_back(std::move(c));
            }
        }

        // quorumsCLSigs: map<CBLSSignature(96B), set<uint16_t>>
        {
            uint64_t n = ReadCompactSize(s);
            out.quorumsCLSigs.clear();
            out.quorumsCLSigs.reserve(n);
            for (uint64_t i = 0; i < n; ++i) {
                std::array<uint8_t, CFinalCommitment::BLS_SIG_SIZE> sig{};
                s.read(std::as_writable_bytes(std::span{sig}));
                uint64_t mset = ReadCompactSize(s);
                std::vector<uint16_t> indices;
                indices.reserve(mset);
                for (uint64_t j = 0; j < mset; ++j) {
                    uint16_t idx = 0;
                    s >> idx;
                    indices.push_back(idx);
                }
                out.quorumsCLSigs.emplace_back(sig, std::move(indices));
            }
        }

        if (s.cursor_size() != 0) {
            LOG_WARNING << "[QUO] parse_quorum_tail: "
                        << s.cursor_size()
                        << " trailing bytes after structured parse "
                           "— possible wire-format drift";
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        LOG_WARNING << "[QUO] parse_quorum_tail failed: " << e.what()
                    << " bytes=" << bytes.size();
        return false;
    }
}

} // namespace vendor
} // namespace coin
} // namespace dash