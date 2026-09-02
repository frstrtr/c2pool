// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_pool_sharechain_compile — COMPILE + INSTANTIATION gate for the M3
// PR-A-continuation sharechain lane. Including share_tracker.hpp transitively
// pulls the whole verify surface (share_check.hpp -> share.hpp, share_types.hpp,
// share_identity.hpp, share_messages.hpp, config_pool.hpp, donation_consensus.hpp),
// which forces every inline ShareTracker method (the v36 decayed-PPLNS walk
// get_v36_decayed_cumulative_weights, get_expected_payouts, the emergency-decay
// retarget get_target) to be fully compiled. main() then ODR-uses the verify-path
// FUNCTION TEMPLATES against the single v36 variant (MergedMiningShare), which
// transitively instantiates share_init_verify (with the BLAKE2b header-hash delta
// via compute_share_hash + check_header_fail_closed), generate_share_transaction,
// share_check, and verify_merged_coinbase_commitment. If this binary links, the
// PR-A-cont lane compiles end to end.

#include "../share_tracker.hpp"       // -> share_check.hpp -> share.hpp/share_types/share_identity/share_messages/config_pool
#include "../donation_consensus.hpp"  // tracker-coupled build_expected_payouts (File 5)

#include <cstdio>

using namespace bip110::pool;

int main()
{
    // (1) Force instantiation of the verify-path function templates against the
    //     ONLY variant on this v36-genesis wire. verify_share() internally calls
    //     share_init_verify(), generate_share_transaction(), share_check() and
    //     verify_merged_coinbase_commitment(), so taking its address instantiates
    //     the entire verify chain — including the BLAKE2b header-hash consensus
    //     delta in share_init_verify (compute_share_hash / check_header_fail_closed).
    volatile auto vp = &verify_share<MergedMiningShare, ShareTracker>;
    (void)vp;

    // (2) Construct a ShareTracker: a non-template class, so merely defining it
    //     (via the include) compiles the v36 decayed-PPLNS walk + emergency-decay
    //     retarget + get_expected_payouts (all inline members) end to end.
    ShareTracker tracker;
    (void)&tracker;  // ODR-use to defeat unused-var elision

    // (3) File 5: tracker-coupled donation build_expected_payouts (instantiate).
    volatile auto bep = &consensus::build_expected_payouts<ShareTracker>;
    (void)bep;
    volatile auto vpt = &consensus::validate_payouts_against_tracker<ShareTracker>;
    (void)vpt;

    std::printf("bip110_pool_sharechain_compile: verify-path + decayed-PPLNS + "
                "donation-consensus templates instantiated + linked OK\n");
    return 0;
}
