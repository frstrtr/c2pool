// Light single-TU syntax + static-budget check for the Family-B receipt headers.
// Build (light, no link needed):  g++ -std=c++20 -fsyntax-only _compile_check.cpp
// Or a tiny run:                  g++ -std=c++20 _compile_check.cpp -o /tmp/xcc && /tmp/xcc
// NOT part of the shipped tree; a self-test for this leg only.

#include <cassert>
#include <cstdio>

#include "xmr_receipt.hpp"
#include "xmr_admission.hpp"

using namespace v37::xmr;

int main() {
    // --- byte-budget sanity (also enforced by static_assert in the header) ----
    static_assert(budget::RECEIPT_TYP >= 600 && budget::RECEIPT_TYP <= 660);
    static_assert(budget::RECEIPT_MAX <= budget::PER_RECEIPT_BUDGET);
    static_assert(budget::PER_LANE_BUDGET == budget::R_MAX_XMR * budget::PER_RECEIPT_BUDGET);

    // --- a realistic receipt: derived seed, 40-tx block (depth 6), avg tail ----
    MoneroReceipt r;
    r.hashing_blob.bytes.resize(77);
    r.seed_ref.policy = SeedRefPolicy::DerivedFromBin;         // 0 B on wire
    r.coinbase_opening.prefix_tail.resize(68);                 // avg partial block
    r.coinbase_opening.tx_extra.resize(75);                    // pubkey+nonce+MM tag
    r.tree_branch.path.resize(5);
    r.tree_branch.depth = 5;
    const std::size_t ws = r.wire_size();
    std::printf("wire_size(typical) = %zu B  [scoping est 600-660]\n", ws);
    assert(ws >= 500 && ws <= budget::PER_RECEIPT_BUDGET);
    std::printf("wire_size caps: TYP=%zu MAX=%zu CAP=%zu PER_LANE=%zu\n",
                budget::RECEIPT_TYP, budget::RECEIPT_MAX,
                budget::PER_RECEIPT_BUDGET, budget::PER_LANE_BUDGET);

    // --- the admission order: verify the exact sequence with instrumented hooks -
    // Each hook records that it ran; we assert RandomX ran strictly last and only
    // when the cheap stages passed.
    static int order[8]; static int n;
    n = 0;
    AdmissionHooks h;
    h.cheap_digest       = [](const HashingBlob&){ order[n++] = 1; return bytes32{}; };
    h.seen               = [](const bytes32&){ return false; };
    h.bin_of             = [](const HashingBlob&, u64& b){ order[n++] = 2; b = 1000; return true; };
    h.open_and_bind      = [](const MoneroReceipt&, const bytes32&, u32,
                              OpenedCommitment& oc){ order[n++] = 3;
                              oc.t_origin = Difficulty{100000, 0}; return true; };
    h.consensus_difficulty = [](u64, Difficulty& d){ order[n++] = 4; d = Difficulty{100000,0}; return true; };
    h.seed_for_bin       = [](u64, const SeedRef&, bytes32&){ return true; };
    h.rx_check           = [](const bytes32&, const HashingBlob&, const Difficulty&,
                              bytes32&){ order[n++] = 5; return true; };  // HEAVY: last

    LaneKeyedHeavy lp;   // r_max=2, n_ctx=2, per_receipt_budget=700
    bytes32 carrier_id{};
    AdmitOutcome out = admit_receipt_keyed_heavy(r, carrier_id, /*carrier_bin=*/1001,
                                                 /*lane_chain_id=*/0, lp, h);
    assert(out.ok && out.stage == AdmitStage::Accepted && out.spent_randomx);
    // stages ran 1,2,3,4,5 in order; RandomX (5) strictly last.
    assert(n == 5);
    for (int i = 0; i < 5; ++i) assert(order[i] == i + 1);

    // --- a replayed receipt must be killed at stage 1, RandomX never touched ----
    n = 0;
    h.seen = [](const bytes32&){ return true; };
    AdmitOutcome dup = admit_receipt_keyed_heavy(r, carrier_id, 1001, 0, lp, h);
    assert(!dup.ok && dup.stage == AdmitStage::Dedup && !dup.spent_randomx);

    // --- an expired receipt (bin too old) dies at stage 2, no RandomX ----------
    n = 0;
    h.seen = [](const bytes32&){ return false; };
    AdmitOutcome exp = admit_receipt_keyed_heavy(r, carrier_id, /*carrier_bin=*/2000, 0, lp, h);
    assert(!exp.ok && exp.stage == AdmitStage::Expiry && !exp.spent_randomx);

    // --- verify-path dispatch --------------------------------------------------
    assert(verify_path_for(PowVerifyClass::keyed_heavy)     == VerifyPath::FamilyB_RandomXLast);
    assert(verify_path_for(PowVerifyClass::stateless_cheap) == VerifyPath::FamilyA_PoWFirst);
    assert(verify_path_for(PowVerifyClass::memory_light)    == VerifyPath::FamilyA_PoWFirst);

    std::printf("OK: order dedup->expiry->structural->R1->RandomX(last); "
                "replay killed@1, expiry killed@2, both pre-RandomX.\n");
    return 0;
}
