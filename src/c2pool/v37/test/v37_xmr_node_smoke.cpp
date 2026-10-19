// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_xmr_node_smoke.cpp -- XmrNode's descriptor backends (c2pool/v37/xmr/xmr_node.hpp), network-free:
//   S2b  a node with no ed25519 point-check backend refuses to start (fail-closed)
//   S2a  with a backend injected it starts, the backend is live and a well-formed XMR_STD descriptor validates;
//        the construction log names the backends before "bring_up: complete"
// ===========================================================================

#include <cstdint>
#include <cstdio>
#include <exception>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_node.hpp"

namespace {

// A trivial point-check backend: any non-zero 32-byte point is accepted, all-zero refused. Enough to show the node
// installs a backend and xmr_ref_valid() goes live; the ref10 torsion check is xmr_torsion_kat's.
bool test_point_check(const std::uint8_t* pt) {
    for (int i = 0; i < 32; ++i) if (pt[i] != 0) return true;
    return false;
}

int g_fails = 0, g_checks = 0;
void check(bool ok, const std::string& what) {
    ++g_checks;
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) ++g_fails;
}

}  // namespace

int main() {
    using namespace c2pool::v37n::xmr;
    XmrNodeConfig c;
    c.network = MoneroNetwork::Stagenet;

    ::v37::xmr::set_point_check_backend(nullptr);
    {
        XmrNode node(c, /*point_check=*/nullptr);
        bool threw = false;
        try { node.bring_up(); } catch (const std::exception&) { threw = true; }
        check(threw && !node.up(), "S2b fail-closed without a point-check backend");
    }
    XmrNode node(c, &test_point_check);
    bool up = false;
    try {
        node.bring_up();
        up = node.up();
    } catch (const std::exception& e) {
        check(false, std::string("bring_up with a backend: ") + e.what());
    }
    check(up, "bring_up succeeds with a backend");
    {
        const bool live = ::v37::xmr::point_check_backend() != nullptr;
        ::v37::ScriptRef ref;
        ref.kind = ::v37::xmr::XMR_STD;
        ref.payload.assign(64, 0);
        for (int i = 0; i < 64; ++i) ref.payload[i] = static_cast<std::uint8_t>(i + 1);
        const bool valid = ::v37::xmr::xmr_ref_valid(ref);
        check(live && valid, "S2a point-check backend live + XMR descriptor validates");
        const std::vector<std::string>& L = node.construction_log();
        int i_back = -1, i_done = -1;
        for (int i = 0; i < static_cast<int>(L.size()); ++i) {
            if (L[i].rfind("backends:", 0) == 0) i_back = i;
            if (L[i].rfind("bring_up: complete", 0) == 0) i_done = i;
        }
        check(i_back >= 0 && i_done > i_back, "S2a the backends are installed before bring_up completes");
    }
    std::printf("v37_xmr_node_smoke: %s (%d/%d)\n", g_fails ? "FAIL" : "OK", g_checks - g_fails, g_checks);
    return g_fails ? 1 : 0;
}
