// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// v37_t1_reward_verify_kat.cpp — Dash T1-prep step 3: THE REWARD A FOLD
// CONSUMES IS THE REWARD THE BLOCK MINED.
//
// Before step 3, a peer folded E_b with whatever reward the winner's v0x02 cut
// descriptor carried, for whatever block id it named — no check that the block
// existed, sat on the best chain at H_b, or paid that much. One forged
// descriptor inflated every peer's owed ledger. And the winner itself folded
// the CACHED getblocktemplate miner_value, not the coinbase it actually mined.
//
// WHAT IS ASSERTED (a FIXED event stream: no clocks, no sockets, no RNG)
//   1  the coinbase parser on a REAL DASH testnet block (h=1558817, mined by
//      the v37 soak): 5 outputs summing to 238104286 duffs; minus dashd's
//      `masternode payments` 178578214 = the miner slice 59526072, which is
//      exactly the reward the winner's descriptor carried for it
//   2  the parser refuses what is not a coinbase (truncations, a non-null
//      prevout, odd / non-hex input, an above-MAX_MONEY output)
//   3  the verdict table: honest, forged reward, unknown block, not active,
//      wrong height, daemon unavailable, superblock non-zero, VALUELESS claim
//   4  own_mined_reward: the slice from the MINED bytes; refused on a template
//      at another (height, parent); VALUELESS at a superblock-cycle height
//   5  ★ accept-honest: A mines (MINED reward), B verifies + folds, both bury,
//      owed_digest(A) == owed_digest(B), non-empty
//   6  ★ reject-forged-reward: a descriptor claiming more than the mined slice
//      is REFUSED, counted, and B stays at the empty anchor
//   7  ★ reject-unknown-block: dashd never had it -> REFUSED, counted
//   8  the other refusals: not active, height mismatch, no facts attached
//   9  own mined-reward mode: an offered MINED value wins over the cached
//      template (counted when they differ); no offer / an offer for another
//      bid -> VALUELESS, never the cached value
//  10  verification OFF (the default for every other caller) keeps the pre-
//      step-3 behaviour byte-for-byte: same registration, same owed_digest
//
// Stdlib-only self-harness: MockCoinBackend + MemSettleStore, Threads for the
// engine executor. Registered with add_test AND in BOTH build.yml --target
// lists (the #1539 / #769 hollow-green rule).
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/btc/btc_node.hpp>
#include <c2pool/v37/btc/mined_block_verify.hpp>

using namespace c2pool::v37n::btc;
namespace settle = ::c2pool::v37n::settle;

static int g_fails = 0;
static int g_checks = 0;
static void check(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) { ++g_fails; std::printf("T1-RV-KAT FAIL: %s\n", what.c_str()); }
    else       std::printf("  ok: %s\n", what.c_str());
}

static std::string hex32(const ::v37::bytes32& d) {
    static const char* H = "0123456789abcdef";
    std::string s;
    for (auto b : d) { s += H[b >> 4]; s += H[b & 15]; }
    return s;
}
static std::vector<std::uint8_t> unhex(const std::string& h) {
    std::vector<std::uint8_t> b(h.size() / 2);
    for (std::size_t i = 0; i < b.size(); ++i)
        b[i] = static_cast<std::uint8_t>(std::stoi(h.substr(2 * i, 2), nullptr, 16));
    return b;
}

// ── GOLDEN: DASH testnet block 00000035df02647c…62d8, h=1558817 ─────────────
// 80-byte header + compactsize(1) + tx[0] (the CbTx, version 3 type 5), exactly
// as `getblock <bid> 0` serves it (the block carried only the coinbase). Its
// outputs: 59526071 -> the soak's miner A, 66966830 -> OP_RETURN (platform
// credit-pool burn), 111611384 -> the masternode payee, 1 -> the v36 donation
// script, 0 -> OP_RETURN. `masternode payments <bid> 1`.amount = 178578214.
static const char* kBlock1558817 =
    "0000002066cb12053bb9781c9ecdacfb7dc8fc8b937b5e4e811046b54ef1fe372d000000957e8fe37ff658fb302bd780d4"
    "1b3be47c1df7f371c8990d0cad3d2adad54a8854f2b26a16947b1d0008d0020103000500010000000000000000000000000000"
    "000000000000000000000000000000000000ffffffff190321c9172f5032506f6f6c2d74444153482f6332706f6f6c2fffffff"
    "ff05b74b8c03000000001976a9140a7bf49abc7d07ade1826202b39a2b05a6d413ea88ac2ed5fd0300000000016af80da706"
    "000000001976a914a50fda9b0221aee1c59ba905f5427a59977f81a888ac01000000000000001976a91420cb5c22b1e4d594"
    "7e5c112c7696b51ad9af3c6188ac00000000000000002a6a28000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000af030021c91700d3fc90c659ab1c8c75b98da4eccb963cbb6598a30ccd0b4335"
    "dcfa7dae6620943ba4f907628d37989e31ab3104aa88af1fe57bccc94aba9a330a8b4277a97f7201b385c4673741610367a86"
    "301b3944818a835eec72d90667964a2fc3361132e4be2f37bb8b5bc09e70cd438e93298d69317d4cc4b01d56c02378ed0e794"
    "51bf30fa1bc201670bcc5e9a644263531da9a9182b009acba1785b978b6550921acf2b8020dc805b210000";
static const char* kParent1558817 = "0000002d37fef14eb54610814e5e7b938bfcc87dfbaccd9e1c78b93b0512cb66";
static const std::uint64_t kTotal1558817 = 238104286ULL;
static const std::uint64_t kMnPay1558817 = 178578214ULL;
static const std::uint64_t kSlice1558817 = 59526072ULL;

static const char* kEmptyAnchor =
    "66078202d7c70e6dbf230d10b716d3f96fbd4d21dac4ba5eb3ac89ca854d54b3";

// ── the two-node stack (same shape as v37_s1c_convergence_kat.cpp) ──────────
static ::v37::PayoutDescriptor p2pkh_desc(std::uint8_t tag) {
    std::vector<std::uint8_t> s = {0x76, 0xa9, 0x14};
    for (int i = 0; i < 20; ++i) s.push_back(tag);
    s.push_back(0x88); s.push_back(0xac);
    ::v37::PayoutDescriptor d;
    d.pay = ::v37::canonicalize_script(s);
    return d;
}
static const ::v37::ChainId CH     = 7;
static const std::uint64_t  D_CONF = 3;
static const int            N_PUSH = 24;
static const std::uint64_t  CACHED = 5000000000ULL;   // MockCoinBackend's block_reward (the "cached template")
static const std::uint64_t  MINED  = 4000000000ULL;   // the miner slice of the coinbase A actually mined
static const char* kWonBid =
    "00000000000000000a1b2c3d4e5f60718293a4b5c6d7e8f900112233445566aa";

struct Node {
    std::shared_ptr<MockCoinBackend> coin;
    std::unique_ptr<XbtcNode>        node;
    Node(std::shared_ptr<MockCoinBackend> c, bool verify) : coin(std::move(c)) {
        BtcNodeConfig cfg;
        cfg.lane_chain = CH;
        cfg.d_conf     = D_CONF;
        node = std::make_unique<XbtcNode>(cfg, std::make_unique<MemSettleStore>(), coin, p2pkh_pay_of());
        node->open();
        node->start();
        node->set_mined_reward_mode(verify);
        node->set_require_verified_peer_wins(verify);
    }
    ~Node() { if (node) node->stop(); }
    void push_fixed_stream() {
        for (int i = 0; i < N_PUSH; ++i)
            node->engine()
                .submit_tracked(::v37::LaneRecord::push(
                    CH, p2pkh_desc(static_cast<std::uint8_t>(0xa0 + (i % 4))), 1 + (i % 3), 0))
                .get();
    }
    ::v37::bytes32 owed() const { return node->ledger().owed_digest(); }
};

static MinedBlockFacts honest_facts(std::uint64_t h, std::uint64_t slice) {
    MinedBlockFacts f;
    f.state = MinedBlockFacts::State::Have;
    f.on_active_chain = true;
    f.height = h;
    f.miner_slice = slice;
    return f;
}

struct Run {
    WonBlockOutcome won;
    PeerWinOutcome  peer;
    ::v37::bytes32  owed_a{}, owed_b{};
    bool            b_pending = false;
    S1PeerStats     b_stats;
    OwnRewardStats  a_own;
};

// A wins at a known height (with the MINED reward offered when `offer`), B
// receives a descriptor carrying `claimed` (default: A's own folded reward)
// with `facts` attached (or none). Both then bury D_conf deep and finalize.
static Run run(bool verify, std::optional<std::uint64_t> claimed,
               std::optional<MinedBlockFacts> facts, bool offer = true,
               const std::string& offer_bid = kWonBid) {
    Run r;
    auto coin = std::make_shared<MockCoinBackend>(CACHED);
    Node A(coin, verify), B(coin, verify);
    A.push_fixed_stream();
    B.push_fixed_stream();
    coin->append_block("g0");
    const std::uint64_t h = coin->append_block(kWonBid);
    const ::v37::bytes32 owed_at_win = A.owed();
    if (offer) A.node->offer_mined_reward(offer_bid, MINED, /*superblock=*/false);
    r.won = A.node->on_block_won(kWonBid, h, 0);

    PeerWin w;
    w.bid                = kWonBid;
    w.h_b                = h;
    w.cut_next_pos       = r.won.cut.next_pos;
    w.cut_spine_digest   = r.won.cut.lane_digest;
    w.reward             = claimed ? *claimed : r.won.cut.reward;
    w.payout_emitted     = r.won.emitted;
    w.owed_digest_at_win = owed_at_win;
    w.facts              = facts;
    r.peer      = B.node->on_peer_block_won(w);
    r.b_pending = B.node->ledger().is_pending(kWonBid);

    for (int i = 0; i <= static_cast<int>(D_CONF); ++i) coin->append_block("f" + std::to_string(i));
    A.node->poll_tip();
    B.node->poll_tip();
    r.owed_a  = A.owed();
    r.owed_b  = B.owed();
    r.b_stats = B.node->s1c_stats();
    r.a_own   = A.node->own_reward_stats();
    return r;
}

int main() {
    std::printf("== v37 T1-prep step 3: reward verification KAT ==\n");

    // ── 1. the parser on a REAL testnet block ────────────────────────────────
    const std::vector<std::uint8_t> blk = unhex(kBlock1558817);
    {
        const CoinbaseOutputs cb = parse_coinbase_outputs(blk);
        check(cb.ok, "1a the real testnet coinbase (h=1558817) parses" + (cb.ok ? std::string() : ": " + cb.error));
        check(cb.n_out == 5, "1b it has 5 outputs (miner, burn, masternode, 1-duff donation, OP_RETURN)");
        check(cb.total == kTotal1558817, "1c sum(vout) == 238104286 duffs (getblock v2 agrees)");
        const auto slice = miner_slice_of(cb.total, kMnPay1558817);
        check(slice && *slice == kSlice1558817,
              "1d sum(vout) - masternode payments(178578214) == 59526072 == the descriptor reward the soak carried");
        const CoinbaseOutputs hx = parse_coinbase_outputs_hex(kBlock1558817);
        check(hx.ok && hx.total == cb.total && hx.n_out == cb.n_out, "1e the hex entry point agrees byte-for-byte");
    }

    // ── 2. the parser refuses what is not a coinbase ─────────────────────────
    {
        bool all_short_refused = true;
        // every truncation that ends before the last output's script
        const std::size_t end_of_outputs = 80 + 1 + 4 + 1 + 36 + 1 + 25 + 4 + 1 +
                                           (8 + 1 + 25) + (8 + 1 + 1) + (8 + 1 + 25) + (8 + 1 + 25) + (8 + 1 + 42);
        for (std::size_t n = 0; n < end_of_outputs; ++n)
            if (parse_coinbase_outputs(blk.data(), n).ok) { all_short_refused = false; break; }
        check(all_short_refused, "2a every truncation before the end of the outputs is refused");
        check(parse_coinbase_outputs(blk.data(), end_of_outputs).ok,
              "2b ...and the prefix that ends exactly after the outputs parses (locktime/payload not needed)");
        std::vector<std::uint8_t> nc = blk;
        nc[80 + 1 + 4 + 1 + 32] = 0x00;       // prevout index 0xffffffff -> 0xffffff00
        check(!parse_coinbase_outputs(nc).ok, "2c a non-null prevout index is not a coinbase");
        std::vector<std::uint8_t> big = blk;
        const std::size_t v0 = 80 + 1 + 4 + 1 + 36 + 1 + 25 + 4 + 1;
        for (int k = 0; k < 8; ++k) big[v0 + k] = 0xff;   // first output value = 2^64-1
        check(!parse_coinbase_outputs(big).ok, "2d an above-MAX_MONEY output is refused");
        check(!parse_coinbase_outputs_hex("0").ok && !parse_coinbase_outputs_hex("zz").ok,
              "2e odd-length / non-hex block text is refused");
    }

    // ── 3. the verdict table ────────────────────────────────────────────────
    {
        const MinedBlockFacts ok = honest_facts(100, 777);
        check(verify_peer_win(ok, 100, 777) == WinVerdict::Ok, "3a honest: active, right height, reward == mined slice");
        check(verify_peer_win(ok, 100, 778) == WinVerdict::RewardMismatch, "3b forged: reward != mined slice");
        check(verify_peer_win(ok, 101, 777) == WinVerdict::HeightMismatch, "3c wrong H_b");
        MinedBlockFacts na = ok; na.on_active_chain = false;
        check(verify_peer_win(na, 100, 777) == WinVerdict::NotActive, "3d not on the best chain");
        MinedBlockFacts ms; ms.state = MinedBlockFacts::State::Missing;
        check(verify_peer_win(ms, 100, 777) == WinVerdict::UnknownBlock, "3e dashd never had the block");
        MinedBlockFacts un; un.state = MinedBlockFacts::State::Unknown;
        check(verify_peer_win(un, 100, 777) == WinVerdict::Unavailable, "3f dashd could not be asked");
        MinedBlockFacts ns = ok; ns.miner_slice.reset();
        check(verify_peer_win(ns, 100, 777) == WinVerdict::Unavailable, "3g no mined slice computed -> refused, never a pass");
        MinedBlockFacts sb = ok; sb.superblock_height = true;
        check(verify_peer_win(sb, 100, 777) == WinVerdict::SuperblockNonzero, "3h non-zero claim at a superblock height");
        check(verify_peer_win(sb, 100, 0) == WinVerdict::Ok, "3i a VALUELESS (0) claim at a superblock height verifies");
        check(verify_peer_win(ns, 100, 0) == WinVerdict::Ok, "3j a VALUELESS claim needs no reward proof...");
        check(verify_peer_win(ms, 100, 0) == WinVerdict::UnknownBlock, "3k ...but still needs the block to exist");
        check(is_superblock_height(1558800, 24, 4200) && !is_superblock_height(1558817, 24, 4200) &&
              !is_superblock_height(24, 24, 4200) && !is_superblock_height(48, 0, 0),
              "3l superblock-cycle heights (testnet cycle 24 from 4200; cycle 0 = none)");
    }

    // ── 4. own_mined_reward ─────────────────────────────────────────────────
    {
        const auto m = own_mined_reward(blk, 1558817, kParent1558817, 1558817, kParent1558817, kMnPay1558817, false);
        check(m.reward && *m.reward == kSlice1558817 && m.coinbase_total == kTotal1558817,
              "4a own slice from the MINED bytes == 59526072");
        const auto h2 = own_mined_reward(blk, 1558817, kParent1558817, 1558818, kParent1558817, kMnPay1558817, false);
        check(!h2.reward, "4b a template at another height is refused (nullopt -> VALUELESS)");
        const auto p2 = own_mined_reward(blk, 1558817, kParent1558817, 1558817, std::string(64, '0'), kMnPay1558817, false);
        check(!p2.reward, "4c a template on another parent is refused");
        const auto s2 = own_mined_reward(blk, 1558800, kParent1558817, 1558817, kParent1558817, kMnPay1558817, true);
        check(s2.reward && *s2.reward == 0, "4d a superblock-cycle height is VALUELESS by rule");
        const auto ov = own_mined_reward(blk, 1558817, kParent1558817, 1558817, kParent1558817, kTotal1558817 + 1, false);
        check(!ov.reward, "4e payments above the coinbase total are refused");
    }

    // ── 5. ★ accept-honest ──────────────────────────────────────────────────
    {
        Run r = run(true, std::nullopt, honest_facts(1, MINED));
        std::printf("   owed A = %s\n   owed B = %s\n", hex32(r.owed_a).c_str(), hex32(r.owed_b).c_str());
        check(r.won.cut.reward == MINED, "5a the winner folded the MINED reward (not the cached 50.00)");
        check(r.peer.registered && r.b_pending, "5b the peer VERIFIED the claim and registered the FOUND");
        check(r.b_stats.verified == 1 && r.peer.verify_verdict == WinVerdict::Ok, "5c counted verified=1");
        check(hex32(r.owed_a) != kEmptyAnchor && r.owed_a == r.owed_b,
              "5d ★ owed_digest(A) == owed_digest(B), non-empty");
        check(r.a_own.mined == 1 && r.a_own.cached_disagreed == 1 && r.a_own.unverified == 0,
              "5e own: mined=1, cached_disagreed=1 (cached 50.00 != mined 40.00)");
    }

    // ── 6. ★ reject-forged-reward ────────────────────────────────────────────
    {
        Run r = run(true, MINED * 2, honest_facts(1, MINED));
        check(!r.peer.registered && r.peer.refused_unverified &&
              r.peer.verify_verdict == WinVerdict::RewardMismatch,
              "6a a descriptor claiming 2x the MINED slice is REFUSED (reward_mismatch)");
        check(r.peer.verify_expected && *r.peer.verify_expected == MINED, "6b the refusal names the mined slice");
        check(r.b_stats.reward_mismatch == 1 && r.b_stats.verified == 0, "6c counted reward_mismatch=1");
        check(hex32(r.owed_b) == kEmptyAnchor, "6d the peer credited NOTHING (stays at the empty anchor)");
        check(r.owed_a != r.owed_b, "6e ...so the fork is VISIBLE (A != B), never hidden behind a plausible number");
    }

    // ── 7. ★ reject-unknown-block ────────────────────────────────────────────
    {
        MinedBlockFacts ms; ms.state = MinedBlockFacts::State::Missing;
        Run r = run(true, std::nullopt, ms);
        check(!r.peer.registered && r.peer.verify_verdict == WinVerdict::UnknownBlock,
              "7a a block dashd never had is REFUSED (unknown_block)");
        check(r.b_stats.unknown_block == 1 && hex32(r.owed_b) == kEmptyAnchor, "7b counted, nothing credited");
    }

    // ── 8. the other refusals ───────────────────────────────────────────────
    {
        MinedBlockFacts na = honest_facts(1, MINED); na.on_active_chain = false;
        Run a = run(true, std::nullopt, na);
        check(!a.peer.registered && a.b_stats.not_active == 1, "8a not on the best chain -> REFUSED (not_active)");
        Run b = run(true, std::nullopt, honest_facts(2, MINED));
        check(!b.peer.registered && b.b_stats.height_mismatch == 1, "8b wrong height -> REFUSED (height_mismatch)");
        Run c = run(true, std::nullopt, std::nullopt);
        check(!c.peer.registered && c.peer.verify_verdict == WinVerdict::Unverified &&
              c.b_stats.verify_unavailable == 1, "8c no facts attached while verification is required -> REFUSED");
        MinedBlockFacts sb = honest_facts(1, MINED); sb.superblock_height = true;
        Run d = run(true, std::nullopt, sb);
        check(!d.peer.registered && d.b_stats.superblock_nonzero == 1, "8d non-zero claim at a superblock height -> REFUSED");
    }

    // ── 9. own mined-reward mode ────────────────────────────────────────────
    {
        Run a = run(true, std::nullopt, honest_facts(1, 0), /*offer=*/false);
        check(a.won.cut.reward == 0 && a.won.cut.valueless && a.a_own.unverified == 1,
              "9a no MINED offer -> the own win registers VALUELESS (never the cached value)");
        check(a.peer.registered && a.owed_a == a.owed_b,
              "9b ...its reward-0 descriptor verifies on the peer and both still converge");
        Run b = run(true, std::nullopt, honest_facts(1, 0), /*offer=*/true, /*offer_bid=*/std::string(64, 'f'));
        check(b.won.cut.reward == 0 && b.a_own.unverified == 1, "9c an offer for ANOTHER bid is never consumed");
    }

    // ── 10. verification OFF = the pre-step-3 behaviour ─────────────────────
    {
        Run off = run(false, std::nullopt, std::nullopt, /*offer=*/false);
        check(off.won.cut.reward == CACHED, "10a mode off: the fold reads block_reward() exactly as before");
        check(off.peer.registered && off.owed_a == off.owed_b,
              "10b mode off: a descriptor without facts registers exactly as before");
        check(off.b_stats.verified == 0 && off.b_stats.verify_unavailable == 0, "10c ...and no verify counter moves");
    }

    std::printf("== %d/%d checks passed ==\n", g_checks - g_fails, g_checks);
    return g_fails == 0 ? 0 : 1;
}
