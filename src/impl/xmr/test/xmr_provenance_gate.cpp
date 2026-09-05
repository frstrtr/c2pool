// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// CI provenance gate for the Family-B (XMR / RandomX) lane. Compiling this TU
// fires the three compile-time predicates in impl/xmr/xmr_provenance.hpp:
//   (1) every ported/vendored row is pinned to a 40-char commit and names a source;
//   (2) p2pool-derived rows stay GPL-3.0-only (copyleft never silently upgraded);
//   (3) the lane's licence set is closed to {BSD-3, GPL-3.0-only, AGPL-3.0}.
// The runtime check pins the row count. Header resolves via the global src/
// include dir. Authored fresh for c2pool; attribution-clean.
#include "impl/xmr/xmr_provenance.hpp"

#include <cstdio>

int main() {
    using namespace c2pool::xmr::provenance;
    if (kManifest.size() != 14) {
        std::printf("FAIL: XMR provenance manifest has %zu rows, expected 14\n",
                    kManifest.size());
        return 1;
    }
    std::printf("xmr provenance gate OK: %zu rows; static_asserts held "
                "(pinned rows, copyleft preserved, licence set closed)\n",
                kManifest.size());
    return 0;
}
