// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_difficulty_kat.cpp  --  X1 KAT: check_hash equivalence
//
// The XMR settlement lane re-checks a solved Monero block against the difficulty
// monerod reported, using the Monero rule  hash * difficulty < 2^256  (the hash
// read little-endian as a 256-bit integer). The lane's hot path runs the
// boost-FREE reimplementation `xmr::coin::check_hash` (../coin/xmr_check_hash.hpp);
// this KAT pins it BYTE-FOR-BYTE against the vendored monero-project reference
// oracle `cryptonote::check_hash` (../coin/vendor/difficulty.cpp, the boost
// multiprecision path) across boundary vectors, AND against hand-verified
// expected results. Any divergence between the two implementations, or from the
// expected accept/reject, fails the build.
//
// This is the ONLY XMR-lane target that compiles the vendored difficulty.cpp,
// so it also proves that TU builds intact behind the authored compat shims
// (../coin/compat/crypto/hash.h, ../coin/compat/cryptonote_config.h) with
// Boost::headers. No libsodium / RandomX is linked.
//
// VECTOR PROVENANCE: arithmetic boundary vectors around the 256-bit overflow
// edge (2^255, 2^192, all-ones), the canonical way Monero's own
// difficulty.cpp is unit-tested. Reproduced as literals.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "xmr_check_hash.hpp"      // xmr::coin::check_hash (boost-free, hot path)

#include "crypto/hash.h"           // compat shim: crypto::hash
#include "vendor/difficulty.h"     // cryptonote::check_hash (boost oracle)

namespace {

int g_fail = 0;

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> o; o.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}

// hash_hex is little-endian (byte 0 first), exactly as Monero stores a block id.
struct DV { const char* hash_hex; std::uint64_t dlo; std::uint64_t dhi; bool expect; const char* note; };

const DV kVectors[] = {
    // 64-bit-difficulty edge (dhi = 0).
    { "0000000000000000000000000000000000000000000000000000000000000000", 1, 0, true,  "0, d=1" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 1, 0, true,  "2^256-1, d=1" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 2, 0, false, "2^256-1, d=2 overflow" },
    { "0000000000000000000000000000000000000000000000000000000000000080", 1, 0, true,  "2^255, d=1" },
    { "0000000000000000000000000000000000000000000000000000000000000080", 2, 0, false, "2^255, d=2 boundary" },
    { "0100000000000000000000000000000000000000000000000000000000000000", 0x100000000ULL, 0, true, "1, d=2^32" },
    // 128-bit difficulty (dhi != 0) -> exercises the multi-limb path.
    { "0100000000000000000000000000000000000000000000000000000000000000", 0, 1, true,  "1, d=2^64" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0, 1, false, "2^256-1, d=2^64 overflow" },
    { "ffffffffffffffff000000000000000000000000000000000000000000000000", 0, 1, true,  "2^64-1, d=2^64" },
    { "ffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000", 0, 1, true,  "2^192-1, d=2^64" },
    { "0000000000000000000000000000000000000000000000000100000000000000", 0, 1, false, "2^192, d=2^64 boundary" },
};

void run() {
    for (const DV& v : kVectors) {
        auto hb = unhex(v.hash_hex);
        bool ok_len = (hb.size() == 32);

        // boost-free reimplementation (lane hot path)
        unsigned char h[32];
        std::memcpy(h, hb.data(), 32);
        bool got_light = xmr::coin::check_hash(h, v.dlo, v.dhi);

        // vendored monero-project boost oracle
        crypto::hash ch{};
        std::memcpy(ch.data, hb.data(), 32);
        cryptonote::difficulty_type d =
            (cryptonote::difficulty_type(v.dhi) << 64) | cryptonote::difficulty_type(v.dlo);
        bool got_oracle = cryptonote::check_hash(ch, d);

        bool agree   = (got_light == got_oracle);
        bool correct = (got_light == v.expect);
        bool ok = ok_len && agree && correct;
        std::printf("  [%s] %-28s light=%d oracle=%d expect=%d\n",
                    ok ? "PASS" : "FAIL", v.note, got_light, got_oracle, v.expect);
        if (!ok) ++g_fail;
    }
}

} // namespace

int main() {
    std::printf("=== xmr_difficulty_kat (check_hash: boost-free == vendored boost oracle) ===\n");
    run();
    std::printf("%s (%d failure%s)\n", g_fail ? "KAT FAILED" : "KAT OK",
                g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
