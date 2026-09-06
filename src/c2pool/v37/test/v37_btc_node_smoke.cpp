// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_btc_node_smoke.cpp — CI driver for the live XbtcNode daemon smoke.
//
// Runs run_btc_node_smoke() (btc/btc_node_smoke.hpp) — the SAME asserted body as
// `c2pool-v37-btc --selftest` — over a MockCoinBackend, and returns nonzero on
// any failed check. Listed in BOTH build.yml legs (Linux x86_64 + ASan/UBSan)
// and covered by the src/c2pool/**/test drift-guard, so it is a real gate, not
// hollow-green. Links only Threads (the lifecycle is header-only + the mock
// backend; no coin lib, no Boost).
// ===========================================================================
#include <c2pool/v37/btc/btc_node_smoke.hpp>

int main() {
    return c2pool::v37n::btc::run_btc_node_smoke() ? 1 : 0;
}
