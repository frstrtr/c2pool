// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_node_smoke.cpp — CI driver for the live XmrNode daemon smoke.
//
// Runs the shared, network-free smoke (src/c2pool/v37/xmr/xmr_node_smoke.hpp)
// against a monerod STUB (MockMonerodTransport). Its own harness: nonzero exit
// on any failed check (the same convention as the sibling v37_*_test suites),
// so it runs on BOTH build.yml legs with no gtest/boost/RandomX/monerod. This
// is the NON-HOLLOW gate for Milestone A: it is listed as a --target in both
// build.yml legs and audited by the src/c2pool/**/test drift-guard.
// ===========================================================================

#include <cstdio>
#include <filesystem>
#include <string>

#include "c2pool/v37/xmr/xmr_node_smoke.hpp"

int main() {
    namespace smoke = c2pool::v37n::xmr::smoke;

    std::filesystem::path tmp =
        std::filesystem::temp_directory_path() /
        ("v37-xmr-node-smoke-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);

    smoke::Report rep = smoke::run(tmp);

    int fails = 0;
    for (const auto& c : rep.checks) {
        std::printf("[%s] %s%s%s\n", c.pass ? "PASS" : "FAIL", c.name.c_str(),
                    c.detail.empty() ? "" : "  — ", c.detail.c_str());
        if (!c.pass) ++fails;
    }
    std::printf("v37_xmr_node_smoke: %s (%d/%zu)\n", fails ? "FAIL" : "OK",
                static_cast<int>(rep.checks.size()) - fails, rep.checks.size());

    std::filesystem::remove_all(tmp);
    return fails ? 1 : 0;
}
