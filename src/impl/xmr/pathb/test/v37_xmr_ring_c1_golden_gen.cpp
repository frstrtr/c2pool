// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_ring_c1_golden_gen: the K = 1 window golden (a SCAFFOLD golden: hf
// 16, v1's window function, a test tag) over the vectors of
// v37_xmr_ring_c1_vectors.hpp.
//   --out=FILE    write the golden text
//   --raw=FILE    write every record in full
//   --check=FILE  compare the golden text with FILE byte for byte
// Prints PASS / FAIL, the record count and the regime case counts; on a
// mismatch the first differing record's name.
// ---------------------------------------------------------------------------
#include <cstdio>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include "v37_xmr_ring_c1_vectors.hpp"

#ifndef RING_C1_GEN_SHA256
#define RING_C1_GEN_SHA256 "unset"
#endif
#ifndef RING_C1_VEC_SHA256
#define RING_C1_VEC_SHA256 "unset"
#endif

namespace {

std::string arg_of(int argc, char** argv, const std::string& key) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a.rfind(key, 0) == 0) return a.substr(key.size());
    }
    return {};
}

std::string first_diff(const std::string& got, const std::string& want) {
    std::istringstream g(got), w(want);
    std::string lg, lw;
    for (;;) {
        const bool eg = !std::getline(g, lg), ew = !std::getline(w, lw);
        if (eg && ew) return {};
        if (eg || ew || lg != lw) return (eg ? std::string("<end>") : lg.substr(0, lg.find('\t'))) + " / expected " +
                                         (ew ? std::string("<end>") : lw.substr(0, lw.find('\t')));
    }
}

}  // namespace

int main(int argc, char** argv) {
    ring_c1::Recorder rec;
    ring_c1::all_vectors(rec);

    char seed[32];
    std::snprintf(seed, sizeof seed, "0x%016llx", static_cast<unsigned long long>(ring_c1::kSeed));
    std::vector<std::string> header{
            "v37_xmr_ring_c1_golden: SCAFFOLD golden (hf 16, v1's window function, test tag)",
            "entry points: window, window_from over ListedBins, select_window_bins, tip_window, evaluate_window_at, "
            "split, window_root, canonical_miner_tx",
            std::string("source-sha256 v37_xmr_ring_c1_golden_gen.cpp ") + RING_C1_GEN_SHA256,
            std::string("source-sha256 v37_xmr_ring_c1_vectors.hpp ") + RING_C1_VEC_SHA256,
            std::string("seed ") + seed + " list-cases " + std::to_string(ring_c1::kListCases) + " store-cases " +
                    std::to_string(ring_c1::kStoreCases),
    };
    bool zero = false;
    for (std::size_t r = 0; r < ring_c1::RgCount; ++r) {
        header.push_back(std::string("regime ") + ring_c1::kRegimeName[r] + " target " +
                         std::to_string(ring_c1::kRegimeTarget[r]) + " reached " + std::to_string(rec.regime[r]));
        if (rec.regime[r] == 0) zero = true;
    }
    const std::string text = ring_c1::golden_text(header, rec);

    const std::string out = arg_of(argc, argv, "--out="), raw = arg_of(argc, argv, "--raw="),
                      chk = arg_of(argc, argv, "--check=");
    if (!out.empty()) {
        std::ofstream f(out, std::ios::binary);
        f << text;
    }
    if (!raw.empty()) {
        const std::vector<std::uint8_t> r = ring_c1::golden_raw(rec);
        std::ofstream f(raw, std::ios::binary);
        f.write(reinterpret_cast<const char*>(r.data()), static_cast<std::streamsize>(r.size()));
    }
    for (std::size_t r = 0; r < ring_c1::RgCount; ++r)
        std::printf("  regime %s: %llu cases (target %llu)\n", ring_c1::kRegimeName[r],
                    static_cast<unsigned long long>(rec.regime[r]),
                    static_cast<unsigned long long>(ring_c1::kRegimeTarget[r]));
    bool ok = !zero;
    if (zero) std::printf("  FAIL: a regime has zero cases\n");
    if (!chk.empty()) {
        std::ifstream f(chk, std::ios::binary);
        const std::string want((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (want.empty()) {
            std::printf("  FAIL: golden %s not read\n", chk.c_str());
            ok = false;
        } else if (text != want) {
            std::printf("  FAIL: differs from the golden at %s\n", first_diff(text, want).c_str());
            ok = false;
        }
    }
    std::printf("v37_xmr_ring_c1_golden_gen: %s: %zu records\n", ok ? "PASS" : "FAIL", rec.recs.size());
    return ok ? 0 : 1;
}
