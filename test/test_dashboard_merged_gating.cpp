// SPDX-License-Identifier: AGPL-3.0-or-later
// Dashboard merged-element topology-gating KAT (SAFE-ADDITIVE static-source
// characterization test).
//
// Charter: "The dashboard must never imply revenue that does not exist."
// A standalone coin (DASH/BTC/DGB) has NO merged child, yet several DOM sites
// rendered a phantom "+N/A DOGE" line, a "DOGE block" legend entry, and a
// hardcoded DOGE address-explorer link next to the real block value -- inviting
// the reading that a second payout stream exists. Root cause: the merged DOM
// elements were not wearing the ONE topology gate class the worker-username
// line already used, so the standalone-hide path (JS: hide every
// .merged-child-hint when currency_info.merged_child_symbol is absent) never
// touched them.
//
// This pins the ONE mechanism in place across every merged site. If anyone
// adds a new ungated merged element, this fails loudly.
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

// (a) One mechanism, applied everywhere: every HTML element that renders
// merged-child data must carry the topology gate class so the standalone-hide
// path covers it. Covers the "Miners Block Value" card ids at ~1852/1854 and
// the node-payout id at ~1860. A merged element is an HTML declaration
// `id="<merged-id>"` (JS refs use '#id' and are excluded).
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

// (b) The block-graph LEGEND (~2301) must not carry a bare hardcoded
// "DOGE block" entry: on a standalone coin the legend would advertise a merged
// chain that does not exist. The gated form wraps the whole legend-item in the
// topology class and drives the symbol text from currency_info via
// .merged-child-symbol-hint. FAILS on the pre-fix source (bare "DOGE block").
TEST(DashboardMergedGating, MergedBlockLegendIsGated) {
    const auto html = read_dashboard();
    EXPECT_EQ(html.find(">DOGE block<"), std::string::npos)
        << "the block-graph legend has a bare hardcoded 'DOGE block' entry; on "
           "a standalone coin it advertises a merged chain that does not exist. "
           "Wrap the legend-item in .merged-child-hint and render the symbol via "
           ".merged-child-symbol-hint.";
    EXPECT_NE(html.find("legend-item merged-child-hint"), std::string::npos)
        << "the merged-block legend entry is not topology-gated.";
}

// (b) The JS write sites (~3042/3049) that stamp 'N/A' into the merged card
// must target ONLY ids whose HTML declaration is topology-gated -- otherwise a
// standalone coin flashes a phantom "+N/A" before/without the hide path. This
// couples the JS writes to the gate: every id written with 'N/A' here must be
// in the gated set above.
TEST(DashboardMergedGating, MergedNaWritesTargetGatedElements) {
    const auto html = read_dashboard();
    const auto lines = lines_of(html);
    const std::vector<std::string> na_write_ids = {
        "merged_block_value", "time_to_merged_block"};
    for (const auto& id : na_write_ids) {
        // the 'N/A' write must exist (documents the site we are gating)...
        EXPECT_NE(html.find("d3.select('#" + id + "').text('N/A')"),
                  std::string::npos)
            << "expected merged 'N/A' write for '" << id << "' not found; if it "
               "moved, re-point this KAT at the new site.";
        // ...and the element it writes to must be gated.
        bool gated = false;
        for (const auto& line : lines)
            if (line.find("id=\"" + id + "\"") != std::string::npos &&
                line.find("merged-child-hint") != std::string::npos)
                gated = true;
        EXPECT_TRUE(gated)
            << "JS writes 'N/A' into '" << id << "' but its HTML declaration is "
               "not inside a .merged-child-hint gate -- phantom on standalone.";
    }
}

// (c) Failure direction 1 -- standalone / failed currency_info fetch renders as
// standalone: the hide path keys off the absence of merged_child_symbol.
TEST(DashboardMergedGating, StandaloneHidePathPresent) {
    const auto html = read_dashboard();
    EXPECT_NE(html.find("info.merged_child_symbol"), std::string::npos)
        << "the gate must key off currency_info.merged_child_symbol; a missing "
           "or failed fetch (no merged_child_symbol) must read as standalone.";
    EXPECT_NE(html.find(".merged-child-hint').style('display', 'none')"),
              std::string::npos)
        << "the topology gate that HIDES merged elements on a standalone coin "
           "is missing -- merged elements would render for every coin.";
}

// (c) Failure direction 2 -- a merged parent (LTC, merged_child_symbol present)
// still SHOWS its merged elements: the show path must exist too, so the fix
// does not over-correct into hiding merged data on the coin that has it.
TEST(DashboardMergedGating, MergedParentShowPathPresent) {
    const auto html = read_dashboard();
    EXPECT_NE(html.find(".merged-child-hint').style('display', null)"),
              std::string::npos)
        << "the show path (reveal merged elements when merged_child_symbol is "
           "present) is missing -- LTC would stop showing its DOGE merged data.";
}

// (b) A merged block-value symbol must come from topology
// (.merged-child-symbol-hint), never a hardcoded 'DOGE' fused to the
// merged_block_value element.
TEST(DashboardMergedGating, NoHardcodedMergedSymbolOnBlockValue) {
    const auto html = read_dashboard();
    EXPECT_EQ(html.find("id=\"merged_block_value\">-</span> DOGE"),
              std::string::npos)
        << "merged_block_value has a hardcoded 'DOGE' symbol; a merged coin "
           "with a different child (or a standalone coin) would render a "
           "phantom currency.";
}

// (d) Merged (DOGE) address-explorer links must route through the currency_info
// prefix (per-node truthful), not a hardcoded blockchair URL fused into the
// href. FAILS on the pre-fix source (hardcoded href + no currency_info field).
TEST(DashboardMergedGating, MergedExplorerRoutedThroughCurrencyInfo) {
    const auto html = read_dashboard();
    EXPECT_NE(html.find("merged_child_address_explorer_url_prefix"),
              std::string::npos)
        << "the dashboard does not read currency_info."
           "merged_child_address_explorer_url_prefix; merged address links are "
           "hardcoded and cannot follow this node's real topology.";
    EXPECT_EQ(html.find("'https://blockchair.com/dogecoin/address/' + "
                        "encodeURIComponent(miner.mergedAddress)"),
              std::string::npos)
        << "the merged payout-address link is a hardcoded blockchair URL; route "
           "it through currency_info.merged_child_address_explorer_url_prefix.";
}
