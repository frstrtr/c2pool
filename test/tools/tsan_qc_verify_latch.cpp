// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ThreadSanitizer harness for MineableCommitmentCache::verified_for's memo
// latch (dkg_commitments.hpp). NOT part of the CMake build and NOT a gtest:
// it is the reproducible demonstration behind the latch being
// `mutable std::atomic<bool>` rather than `mutable bool`.
//
// The gtest twin
// (DashQcVerifyMemo.ConcurrentServeReadsAlwaysGetTheirCommitmentAndConverge,
// test_dash_dkg_commitments.cpp) pins the BEHAVIOUR under concurrency, but a
// benign-in-practice data race is still UB and an ordinary build cannot see
// it. This one can:
//
//   g++ -std=c++20 -O1 -g -fsanitize=thread \
//       -I<repo>/include -I<repo>/src -I<repo>/src/btclibs \
//       -I<repo>/src/btclibs/util -I<repo>/src/btclibs/crypto \
//       -I<repo>/src/btclibs/compat \
//       test/tools/tsan_qc_verify_latch.cpp -o /tmp/tsan_latch
//   setarch $(uname -m) -R /tmp/tsan_latch     # -R: TSan needs ASLR off
//
// Measured on this tree (gcc 13, 8 readers x 2000 reads):
//   mutable std::atomic<bool> verified -> served=16000/16000 verifies=4,
//                                         no TSan report, exit 0
//   mutable bool verified              -> WARNING: ThreadSanitizer: data race
//                                         "Write of size 1" in verified_for
//                                         at dkg_commitments.hpp:760
//
// `verifies` being >1 is not a defect: it is exactly the tolerated worst case
// — a redundant re-verify of the SAME bytes to the SAME verdict when readers
// race the latching store. The latch is positive-only, so no interleaving can
// turn a verified slot into a refusal, which is what `served` checks.

#include <impl/dash/coin/dkg_commitments.hpp>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

using namespace dash::coin;

namespace {

uint256 fill256(uint8_t b)
{
    uint256 u;
    std::vector<unsigned char> v(32, b);
    std::memcpy(u.data(), v.data(), 32);
    return u;
}

}  // namespace

int main()
{
    MineableCommitmentCache cache;
    const uint256 qh = fill256(0x91);

    // A structurally admissible real testnet LLMQ_50_60 commitment (the same
    // shape test_dash_dkg_commitments.cpp's real_commitment() builds).
    vendor::CFinalCommitment c;
    c.nVersion = vendor::CFinalCommitment::BASIC_BLS_NON_INDEXED_QUORUM_VERSION;
    c.llmqType = kLlmq50_60.type;
    c.quorumHash = qh;
    c.quorumIndex = 0;
    c.signers.assign(kLlmq50_60.size, true);
    c.validMembers.assign(kLlmq50_60.size, true);
    c.quorumPublicKey.fill(0x11);
    c.quorumVvecHash = fill256(0x22);
    c.quorumSig.fill(0x33);
    c.membersSig.fill(0x44);
    if (!cache.ingest(LlmqNetwork::Testnet, c)) {
        std::puts("FAIL: fixture commitment was not admitted");
        return 2;
    }

    std::atomic<int> calls{0};
    cache.set_bls_verify_fn([&calls](const vendor::CFinalCommitment&) {
        calls.fetch_add(1, std::memory_order_relaxed);
        return true;
    });

    constexpr int kThreads = 8;
    constexpr int kReads = 2000;
    std::atomic<bool> go{false};
    std::atomic<int> served{0};
    std::vector<std::thread> readers;
    readers.reserve(kThreads);
    for (int t = 0; t < kThreads; ++t) {
        readers.emplace_back([&] {
            while (!go.load(std::memory_order_acquire)) { }
            for (int i = 0; i < kReads; ++i)
                if (cache.verified_for(kLlmq50_60.type, qh).has_value())
                    served.fetch_add(1, std::memory_order_relaxed);
        });
    }
    go.store(true, std::memory_order_release);
    for (auto& t : readers) t.join();

    std::printf("served=%d/%d verifies=%d\n", served.load(),
                kThreads * kReads, calls.load());
    if (served.load() != kThreads * kReads) {
        std::puts("FAIL: a concurrent read withheld a verified commitment");
        return 1;
    }
    return 0;
}
