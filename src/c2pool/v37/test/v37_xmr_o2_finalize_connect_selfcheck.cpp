// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_o2_finalize_connect_selfcheck.cpp  (X9 O-2, wire 4)
//
// Driver for o2::finalize_connect_selfcheck (xmr/xmr_o2_finalize_connect.hpp):
// network-free, RandomX-free, against the monerod STUB with the injected test
// point-check backend — the same shape as v37_xmr_node_smoke. Proves a queued
// win -> XmrNode::on_network_block_won (amount-honest FOUND) -> restart inside
// the D_conf window -> pending-FOUND sidecar re-drive -> FINALIZE at
// bin_height = H_b + D_conf -> finalW nets to 0 -> sidecar retired; plus the
// late-FOUND / malformed / all-zero-bid refusals, the valueless record,
// idempotence per bid and the orphan disposition. Nonzero exit on any failure.
// ===========================================================================
#include <unistd.h>

#include <cstdio>
#include <filesystem>
#include <string>

#include "c2pool/v37/xmr/xmr_o2_finalize_connect.hpp"

int main() {
    std::filesystem::path tmp =
        std::filesystem::temp_directory_path() /
        ("v37-xmr-o2-fc-" + std::to_string(::getpid()));
    std::filesystem::remove_all(tmp);
    std::filesystem::create_directories(tmp);

    const auto rep = c2pool::v37n::xmr::o2::finalize_connect_selfcheck(tmp);
    std::printf("== v37_xmr_o2_finalize_connect_selfcheck ==\n");
    int fails = 0;
    for (const auto& c : rep.checks) {
        std::printf("  [%s] %s%s%s\n", c.pass ? "PASS" : "FAIL", c.name.c_str(),
                    c.detail.empty() ? "" : "  -- ", c.detail.c_str());
        if (!c.pass) ++fails;
    }
    std::printf("== %s (%d/%zu passed) ==\n", fails ? "FAIL" : "OK",
                static_cast<int>(rep.checks.size()) - fails, rep.checks.size());
    std::filesystem::remove_all(tmp);
    return fails ? 1 : 0;
}
