// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/main_v37_btc.cpp   (Track A2 / Milestone A-BTC — entrypoint)
//
// The c2pool-v37-btc daemon entrypoint: the live v37 node lifecycle for the
// BITCOIN FAMILY (XbtcNode), wired to the mature v36 coin plumbing. Sibling of
// main_v37.cpp (the W0 scaffold) and main_v37_xmr.cpp (Milestone A-XMR).
//
// EXPERIMENTAL / DEVNET-DEFAULT — do not run in production. The shipped default
// is DASH regtest (reorg-injectable for the controlled falsifier). Mainnet is a
// loud opt-in (--i-understand-mainnet).
//
// Two modes:
//   --selftest / --mock-smoke   network-free, in-process lifecycle invariants
//                over a MockCoinBackend (the CI-runnable core; no coin daemon,
//                no Boost, no PoW). Exercises the full mine→bury→settle path,
//                the reorg drill, W6 recovery, and F2 fail-closed. Exit 0 iff
//                green. This is the SAME body the CI target v37_btc_node_smoke
//                runs.
//   (default)    a single live node: open() the store + recover, start() the
//                engine + lane, bind the v36 core::StratumServer to
//                --stratum-bind, and run the height-watch against the coin
//                backend (DASH embedded-SPV / LTC daemon). The live coin backend
//                + StratumServer binding is the CI/heavy leg; the local build
//                ships the smoke.
// ===========================================================================
#include <cstdio>
#include <string>

#include <c2pool/v37/btc/btc_node_smoke.hpp>

int main(int argc, char** argv) {
    bool selftest = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--selftest" || a == "--mock-smoke") selftest = true;
    }
    if (selftest) return c2pool::v37n::btc::run_btc_node_smoke() ? 1 : 0;

    std::printf(
        "c2pool-v37-btc (EXPERIMENTAL, DASH-regtest default; do not run in production)\n"
        "  --selftest   run the network-free lifecycle invariants and exit\n"
        "  (live mode binds the v36 core::StratumServer + coin backend; CI leg)\n");
    return 2;
}
