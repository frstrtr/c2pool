// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/test/pathb_kat_shard.hpp
// The sections of a Path B KAT, its shards and the gather of their results
// (run_sections):
//   (no argument)            every section, in run order;
//   <section>                that section;
//   --shard=i/n [--out=<p>]  the sections of shard i of n (shard_plan); with
//                            --out the result is written to <p>.i;
//   --gather=n --out=<p>     reads <p>.0 .. <p>.(n - 1); passes when every
//                            section ran in exactly one shard and no check
//                            failed; the result files are removed once read;
//   --plan=n                 prints the sections and cost of each of n shards.
// The sections of one group run in one shard.
// ---------------------------------------------------------------------------
#pragma once

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <numeric>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "pathb_kat_check.hpp"
#include "pathb_kat_lane.hpp"  // run_part

namespace pathb_kat {

// A section in run order, with its cost (seconds under ASan+UBSan) and its group (none: nullptr).
struct KatSection {
    const char* name;
    void (*run)();
    std::uint64_t cost;
    const char* group = nullptr;
};

// The shard of each section for n shards. A unit is a section without a group, or the sections of one group (at its
// first section, with their summed cost). The units by cost, highest first (run order on equal cost), each to the
// least loaded shard (the lowest index on equal load); a section runs in the shard of its unit.
inline std::vector<std::size_t> shard_plan(const std::vector<KatSection>& sections, std::size_t n) {
    std::vector<std::size_t> unit(sections.size()), order, shard(sections.size());
    std::vector<std::uint64_t> cost(sections.size(), 0);
    std::iota(unit.begin(), unit.end(), std::size_t{0});
    for (std::size_t k = 0; k < sections.size(); ++k) {
        for (std::size_t j = 0; j < k && sections[k].group != nullptr; ++j)
            if (sections[j].group != nullptr && std::string_view(sections[j].group) == sections[k].group) {
                unit[k] = unit[j];
                break;
            }
        if (unit[k] == k) order.push_back(k);
        cost[unit[k]] += sections[k].cost;
    }
    std::stable_sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) { return cost[a] > cost[b]; });
    std::vector<std::uint64_t> load(n, 0);
    for (const std::size_t u : order) {
        const auto s = static_cast<std::size_t>(std::min_element(load.begin(), load.end()) - load.begin());
        shard[u] = s;
        load[s] += cost[u];
    }
    for (std::size_t k = 0; k < sections.size(); ++k) shard[k] = shard[unit[k]];
    return shard;
}

inline bool parse_size(const char* b, const char* e, std::size_t& v) {
    const auto r = std::from_chars(b, e, v);
    return b != e && r.ec == std::errc{} && r.ptr == e;
}

// "i/n", n >= 1, i < n.
inline bool parse_shard(const std::string& s, std::size_t& i, std::size_t& n) {
    const auto slash = s.find('/');
    return slash != std::string::npos && parse_size(s.data(), s.data() + slash, i) &&
           parse_size(s.data() + slash + 1, s.data() + s.size(), n) && n >= 1 && i < n;
}

inline std::string shard_file(const std::string& out, std::size_t i) { return out + "." + std::to_string(i); }

inline int gather_shards(const char* kat, const std::vector<KatSection>& sections, const std::string& out,
                         std::size_t n) {
    long long checks = 0, fails = 0;
    bool ok = true;
    std::vector<int> seen(sections.size(), 0);
    for (std::size_t i = 0; i < n; ++i) {
        const std::string path = shard_file(out, i);
        std::ifstream f(path);
        std::size_t fi = 0, fn = 0;
        long long c = 0, fl = 0;
        if (!(f >> fi >> fn >> c >> fl) || fi != i || fn != n) {
            std::printf("  FAIL: no result of shard %zu/%zu in %s\n", i, n, path.c_str());
            ok = false;
            continue;
        }
        std::string ran, name;
        while (f >> name) {
            std::size_t k = 0;
            while (k < sections.size() && name != sections[k].name) ++k;
            if (k == sections.size()) {
                std::printf("  FAIL: shard %zu/%zu ran an unknown section %s\n", i, n, name.c_str());
                ok = false;
            } else {
                ++seen[k];
            }
            ran += " " + name;
        }
        f.close();
        std::remove(path.c_str());
        std::printf("[shard %zu/%zu] %lld checks, %lld failures:%s\n", i, n, c, fl, ran.c_str());
        checks += c;
        fails += fl;
    }
    for (std::size_t k = 0; k < sections.size(); ++k)
        if (seen[k] != 1) {
            std::printf("  FAIL: section %s ran in %d shards\n", sections[k].name, seen[k]);
            ok = false;
        }
    ok = ok && fails == 0;
    std::printf("%s: %s: %lld checks, %lld failures (%zu shards)\n", kat, ok ? "PASS" : "FAIL", checks, fails, n);
    return ok ? 0 : 1;
}

inline int print_plan(const std::vector<KatSection>& sections, std::size_t n) {
    const std::vector<std::size_t> plan = shard_plan(sections, n);
    for (std::size_t i = 0; i < n; ++i) {
        std::uint64_t cost = 0;
        std::string names;
        for (std::size_t k = 0; k < sections.size(); ++k)
            if (plan[k] == i) {
                cost += sections[k].cost;
                names += std::string(" ") + sections[k].name;
            }
        std::printf("[shard %zu/%zu] cost %llu:%s\n", i, n, static_cast<unsigned long long>(cost), names.c_str());
    }
    return 0;
}

inline int run_sections(const char* kat, const std::vector<KatSection>& sections, int argc, char** argv) {
    const auto usage = [&] {
        std::fprintf(stderr, "usage: %s [<section> | --shard=i/n [--out=<p>] | --gather=n --out=<p> | --plan=n]\n",
                     kat);
        return 2;
    };
    std::string only, out;
    std::size_t shard = 0, shards = 0, gather_n = 0, plan_n = 0;
    for (int a = 1; a < argc; ++a) {
        const std::string arg = argv[a];
        if (arg.rfind("--shard=", 0) == 0) {
            if (!parse_shard(arg.substr(8), shard, shards)) return usage();
        } else if (arg.rfind("--gather=", 0) == 0) {
            const std::string v = arg.substr(9);
            if (!parse_size(v.data(), v.data() + v.size(), gather_n) || gather_n == 0) return usage();
        } else if (arg.rfind("--plan=", 0) == 0) {
            const std::string v = arg.substr(7);
            if (!parse_size(v.data(), v.data() + v.size(), plan_n) || plan_n == 0) return usage();
        } else if (arg.rfind("--out=", 0) == 0 && arg.size() > 6) {
            out = arg.substr(6);
        } else if (arg.rfind("--", 0) != 0 && only.empty()) {
            only = arg;
        } else {
            return usage();
        }
    }
    if (plan_n) return shards || gather_n || !only.empty() || !out.empty() ? usage() : print_plan(sections, plan_n);
    if (gather_n) return shards || !only.empty() || out.empty() ? usage() : gather_shards(kat, sections, out, gather_n);
    if ((shards && !only.empty()) || (!out.empty() && !shards)) return usage();
    const std::vector<std::size_t> plan = shard_plan(sections, shards ? shards : 1);
    if (!out.empty()) std::remove(shard_file(out, shard).c_str());
    std::string ran;
    for (std::size_t k = 0; k < sections.size(); ++k) {
        const KatSection& s = sections[k];
        if ((!only.empty() && only != s.name) || (shards && plan[k] != shard)) continue;
        const auto t0 = std::chrono::steady_clock::now();
        const int f0 = g_fail;
        run_part(s.name, s.run);
        std::printf("[%s] %.1f s%s\n", s.name,
                    std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(),
                    g_fail != f0 ? " FAIL" : "");
        std::fflush(stdout);
        ran += std::string(" ") + s.name;
    }
    if (!shards) return finish(kat);
    const std::string label = std::string(kat) + " shard " + std::to_string(shard) + "/" + std::to_string(shards);
    int rc = finish(label.c_str());
    if (!out.empty()) {
        std::ofstream f(shard_file(out, shard));
        f << shard << ' ' << shards << ' ' << g_checks << ' ' << g_fail << '\n' << ran << '\n';
        if (!f) {
            std::printf("  FAIL: cannot write %s\n", shard_file(out, shard).c_str());
            rc = 1;
        }
    }
    return rc;
}

}  // namespace pathb_kat
