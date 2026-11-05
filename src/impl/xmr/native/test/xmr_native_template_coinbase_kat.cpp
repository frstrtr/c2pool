// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_template_coinbase_kat.cpp   --  C4 KAT
//
// THE CLAIM UNDER TEST: the Path B miner tx (build_miner_tx_hf16) built from
// the native chain's miner data (C4 capture) is the one built from monerod's
// identical values, and each value the native source supplies moves it.
//
//   1. the native derivation: R = emission_base_reward(the native
//      already_generated_coins, major) + the backlog's fees; amounts =
//      split(R, window) over three payees; one output per payee, distinct
//      one-time keys, Sum(vout) == R; the PBX1 extra carries mm_root under 0x03
//   2. the monerod arm's identical miner data: a byte-identical miner tx
//   3. each rebound field moves it: height, prev_id (r), already_generated_coins
//      (R, exact-sum held), a backlog fee (R, exact-sum held)
//   4. hf 17: the amount fork fuse (no Path B miner tx at hf >= 17)
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/contracts/miner_data.hpp"
#include "impl/xmr/pathb/pathb_emission.hpp"
#include "impl/xmr/pathb/pathb_miner_tx.hpp"
#include "impl/xmr/pathb/pathb_window.hpp"
#include "impl/xmr/pathb/test/pathb_kat_bodies.hpp"
#include "impl/xmr/pathb/test/pathb_kat_check.hpp"
#include "impl/xmr/pathb/test/pathb_kat_miner.hpp"

namespace nat = c2pool::xmr::native;
namespace pb = ::c2pool::xmr::pathb;

#include "xmr_c4_parity_golden.hpp"
namespace G4 = c2pool::xmr::native::golden_c4;

namespace {

int g_fail = 0;
int g_checks = 0;

void CHECK(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) ++g_fail;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
}

nat::Hash node_hash_from_hex(const char* h) {
    nat::Hash out{};
    auto nib = [](char c) -> int { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (std::size_t i = 0; i < 32 && h[2 * i] && h[2 * i + 1]; ++i)
        out[i] = static_cast<std::uint8_t>(nib(h[2 * i]) * 16 + nib(h[2 * i + 1]));
    return out;
}

::c2pool::xmr::node::MinerData native_miner_data() {
    ::c2pool::xmr::node::MinerData md;
    md.major_version           = G4::MD_MAJOR_VERSION;
    md.height                  = G4::MD_HEIGHT;
    md.prev_id                 = node_hash_from_hex(G4::MD_PREV_ID);
    md.seed_hash               = node_hash_from_hex(G4::MD_SEED_HASH);
    md.difficulty.lo           = G4::MD_DIFFICULTY_LO;
    md.difficulty.hi           = G4::MD_DIFFICULTY_HI;
    md.median_weight           = G4::MD_MEDIAN_WEIGHT;
    md.already_generated_coins = G4::MD_ALREADY_GENERATED_COINS;
    md.median_timestamp        = G4::ROWS[G4::ROWS_COUNT - 1].timestamp;
    return md;
}

pathb_kat::RefBook g_book;
pb::Window g_window;

void setup_window() {
    std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
    for (std::uint8_t i = 0; i < 3; ++i)
        wts.push_back({g_book.add(pathb_kat::key_ref(static_cast<std::uint8_t>(0xB0 + i))), 1000003u + 7919u * i});
    g_window = pathb_kat::window_of(wts);
}

struct Built {
    std::uint64_t R = 0;
    std::optional<pb::MinerTx> tx;
};

// The Path B miner tx of one miner data: R from the native emission and the backlog's fees, split over the window.
Built build(const ::c2pool::xmr::node::MinerData& md) {
    Built b;
    std::uint64_t fees = 0;
    for (const auto& t : md.tx_backlog) fees += t.fee;
    b.R = nat::emission_base_reward(md.already_generated_coins, md.major_version) + fees;
    std::vector<pb::MinerPayee> payees;
    for (const pb::SplitOutput& o : pb::split(b.R, g_window)) payees.push_back({g_book.refs.at(o.payee), o.amount});
    pb::Hash32 p_r{};
    std::memcpy(p_r.data(), md.prev_id.data(), 32);
    const std::array<std::uint8_t, pb::kExtraNonceBytes> en{0, 0, 0, 0};
    b.tx = pb::build_miner_tx_hf16(pathb_kat::seq32(0x31), pathb_kat::seq32(0x51), p_r, md.height, payees, en,
                                   pathb_kat::seq32(0x71));
    return b;
}

std::uint64_t sum_of(const Built& b) {
    std::uint64_t s = 0;
    if (b.tx)
        for (const pb::MinerOut& o : b.tx->outs) s += o.amount;
    return s;
}

}  // namespace

int main() {
    std::printf("=== xmr_native_template_coinbase_kat (the Path B miner tx from the native miner data) ===\n");
    setup_window();
    const ::c2pool::xmr::node::MinerData md = native_miner_data();

    std::printf("== 1. the native derivation ==\n");
    const Built cb = build(md);
    CHECK(cb.tx.has_value(), "build_miner_tx_hf16 on the native miner data");
    CHECK(cb.R == 600000000000ull, "native emission at the captured height: the 0.6 XMR tail, no backlog (" +
                                           std::to_string(cb.R) + ")");
    CHECK(cb.tx && cb.tx->outs.size() == 3, "one output per window payee (3)");
    bool distinct = cb.tx.has_value();
    if (cb.tx)
        for (std::size_t i = 0; i < cb.tx->outs.size(); ++i)
            for (std::size_t j = i + 1; j < cb.tx->outs.size(); ++j)
                distinct = distinct && !(cb.tx->outs[i].key == cb.tx->outs[j].key);
    CHECK(distinct, "every output carries a distinct one-time key");
    CHECK(sum_of(cb) == cb.R, "Sum(vout) == R to the piconero");
    CHECK(cb.tx && cb.tx->extra.size() == 74 && cb.tx->extra[39] == 0x03 && cb.tx->extra[40] == 0x21 &&
                  cb.tx->extra[41] == 0x00 && std::memcmp(cb.tx->extra.data() + 42, pathb_kat::seq32(0x71).data(), 32) == 0,
          "the PBX1 extra (74 B) carries mm_root under 0x03 at depth 0");

    std::printf("== 2. the monerod arm's identical values give a byte-identical miner tx ==\n");
    {
        const ::c2pool::xmr::node::MinerData daemon = md;
        const Built d = build(daemon);
        CHECK(d.tx && cb.tx && d.tx->prefix == cb.tx->prefix && d.tx->r == cb.tx->r, "byte-identical miner tx, same r");
    }

    std::printf("== 3. every rebound field is load-bearing ==\n");
    {
        ::c2pool::xmr::node::MinerData h = md;
        h.height += 1;
        const Built b = build(h);
        CHECK(b.tx && cb.tx && b.tx->prefix != cb.tx->prefix, "a different height moves the miner tx");
    }
    {
        ::c2pool::xmr::node::MinerData p = md;
        p.prev_id[0] ^= 0xff;
        const Built b = build(p);
        CHECK(b.tx && cb.tx && !(b.tx->r == cb.tx->r), "a different prev_id moves the tx secret r");
    }
    {
        ::c2pool::xmr::node::MinerData e = md;
        e.already_generated_coins = 1000000000000000ull;
        const Built b = build(e);
        CHECK(b.R > cb.R, "a smaller coin total gives a larger base reward (" + std::to_string(b.R) + ")");
        CHECK(b.tx && sum_of(b) == b.R, "  ...and Sum(vout) == the new R");
    }
    {
        ::c2pool::xmr::node::MinerData f = md;
        ::c2pool::xmr::node::TxBacklogEntry t{};
        t.weight = 1500;
        t.blob_size = 1400;
        t.fee = 42000000ull;
        f.tx_backlog.push_back(t);
        const Built b = build(f);
        CHECK(b.R == cb.R + 42000000ull && b.tx && sum_of(b) == b.R, "a native backlog fee enters R; Sum(vout) == R");
    }

    std::printf("== 4. the amount fork fuse ==\n");
    CHECK(pb::amount_fork_fused(17) && !pb::amount_fork_fused(16), "hf 17 fused, hf 16 not");

    std::printf("=== %d checks, %d failed ===\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
