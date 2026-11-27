// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Source guard: main_dgb.cpp binds the live seams (rides dgb_work_source_test).
//
// The unit KATs drive the seams through the same functions main_dgb calls; a
// deleted or reordered call in main_dgb would leave them green. This pins the
// calls themselves, in main_dgb's run_node, and the order the hooks need:
//   - the payout acceptance and DGB's merged_parent_versions;
//   - the stratum best-share cell + the one best-change hook (wire_best_share);
//   - the DOGE wiring (wire_doge_merged_payouts) with the split rule and the
//     cell as the provider's best-share source, BEFORE wire_best_share (the
//     hook marks the DOGE payouts dirty);
//   - the owner's merged scripts for node-fee shares.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>

#ifndef DGB_MAIN_SRC
#error "DGB_MAIN_SRC must be defined by CMake to the path of src/c2pool/main_dgb.cpp"
#endif

namespace {
std::string main_src()
{
    std::ifstream in(DGB_MAIN_SRC);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}
} // namespace

TEST(DgbMainWiring, LiveSeamsAreBound)
{
    const std::string s = main_src();
    ASSERT_FALSE(s.empty()) << DGB_MAIN_SRC;
    const auto at = [&](const std::string& needle) { return s.find(needle); };

    EXPECT_NE(at("work_source->set_payout_acceptance("), std::string::npos);
    EXPECT_NE(at("work_source->set_merged_parent_versions(dgb::merged_parent_versions())"), std::string::npos);
    EXPECT_NE(at("work_source->set_merged_mining_manager(mm_manager.get())"), std::string::npos);
    EXPECT_NE(at("work_source->set_owner_merged_scripts("), std::string::npos);
    EXPECT_NE(at("work_source->set_pplns_inputs_fn("), std::string::npos);
    EXPECT_NE(at("work_source->set_mint_share_fn("), std::string::npos);

    const auto doge = at("dgb::coin::wire_doge_merged_payouts(mm_manager.get(), p2p_node, work_source.get(), doge_p2sh_split,");
    const auto best = at("dgb::wire_best_share(p2p_node, stratum_best_share, work_source.get(), ioc,");
    ASSERT_NE(doge, std::string::npos) << "the DOGE payout provider is not registered";
    ASSERT_NE(best, std::string::npos) << "the stratum best share is not bound";
    EXPECT_LT(doge, best) << "the best-change hook is bound before the DOGE wiring";
    EXPECT_NE(s.find("[cell = stratum_best_share]() { return cell->get(); }", doge), std::string::npos)
        << "the provider does not read the best share from the cell";
    EXPECT_NE(s.find("mm->mark_pplns_dirty()", best - 400), std::string::npos)
        << "the best-change hook does not mark the DOGE payouts dirty";
    // Nothing else binds the single-slot best-change hook.
    EXPECT_EQ(at("set_on_best_share_changed("), std::string::npos);
}
