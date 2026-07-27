// SPDX-License-Identifier: AGPL-3.0-or-later
// Dashboard merged-element topology-gating KAT (SAFE-ADDITIVE static-source
// characterization test).
//
// Charter: "The dashboard must never imply revenue that does not exist."
// A standalone coin (DASH/BTC/DGB) has NO merged child, yet the "Miners Block
// Value" card rendered a phantom "+N/A DOGE" line next to the real block value,
// inviting the reading that a second payout stream exists. Root cause: the
// merged DOM elements were not wearing the topology gate class the worker-
// username line already used, so the standalone-hide path (JS: hide every
// .merged-child-hint when currency_info.merged_child_symbol is absent) never
// touched them.
//
// This pins the ONE mechanism in place: every merged HTML element must sit
// inside a .merged-child-hint container. If anyone adds a new ungated merged
// element, this fails loudly (it fails on the pre-fix source: the bare
// <div class="stat-sub">+<span id="merged_block_value">-</span> DOGE</div>).
#include <gtest/gtest.h>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifndef DASHBOARD_HTML_PATH
#error "DASHBOARD_HTML_PATH must be defined by CMake"
#endif

namespace {
std::string read_dashboard() {
    std::ifstream f(DASHBOARD_HTML_PATH);
    EXPECT_TRUE(f.good()) << "cannot open " << DASHBOARD_HTML_PATH;
    std::stringstream ss; ss << f.rdbuf();
    return ss.str();
}
std::vector<std::string> lines_of(const std::string& s) {
    std::vector<std::string> out; std::string line; std::stringstream ss(s);
    while (std::getline(ss, line)) out.push_back(line);
    return out;
}
} // namespace

// Every HTML element that renders merged-child data must carry the topology
// gate class, so the standalone-hide path covers it. A merged element is an
// HTML declaration `id="<merged-id>"` (JS refs use '#id' and are excluded).
TEST(DashboardMergedGating, EveryMergedElementIsTopologyGated) {
    const auto html = read_dashboard();
    const std::vector<std::string> merged_ids = {
        "merged_block_value", "node_merged_payout", "time_to_merged_block"};
    for (const auto& line : lines_of(html)) {
        for (const auto& id : merged_ids) {
            if (line.find("id=\"" + id + "\"") != std::string::npos) {
                EXPECT_NE(line.find("merged-child-hint"), std::string::npos)
                    << "merged element '" << id << "' is not inside a "
                       ".merged-child-hint gate -- it will render on a "
                       "standalone coin that has no merged child. Line:\n"
                    << line;
            }
        }
    }
}

// The standalone-hide path (the ONE mechanism) must still exist: JS hides every
// .merged-child-hint when currency_info has no merged_child_symbol.
TEST(DashboardMergedGating, StandaloneHidePathPresent) {
    const auto html = read_dashboard();
    EXPECT_NE(html.find(".merged-child-hint').style('display', 'none')"),
              std::string::npos)
        << "the topology gate that hides merged elements on a standalone coin "
           "is missing -- merged elements would render for every coin.";
}

// A merged block-value symbol must come from topology (merged-child-symbol-hint),
// never a hardcoded 'DOGE' fused to the merged_block_value element.
TEST(DashboardMergedGating, NoHardcodedMergedSymbolOnBlockValue) {
    const auto html = read_dashboard();
    EXPECT_EQ(html.find("id=\"merged_block_value\">-</span> DOGE"),
              std::string::npos)
        << "merged_block_value has a hardcoded 'DOGE' symbol; a merged coin "
           "with a different child (or a standalone coin) would render a "
           "phantom currency.";
}
