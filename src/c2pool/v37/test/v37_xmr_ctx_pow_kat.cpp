// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_ctx_pow_kat -- the WORK behind a receipt's Monero context.
//
// A Monero block a lane peer serves as a receipt's context (FB_CTX) is used
// only if the node's own verified Monero chain index holds it, or if its proof
// of work meets the difficulty its parent implies in that index -- the parent
// held there, or itself verified this way -- at most 2 unknown blocks above the
// index (the tip-freshness bound: a template is never more than 2 heights past
// its tip). A hash below that difficulty is forged (ban); everything that
// cannot be judged yet waits and never bans.
//
// The index is the REAL native ChainIndex (Regtest, seed_direct): a tip G at
// height 5000 whose 100-row difficulty window gives a next difficulty of
// exactly 1000. It is bound to the relay exactly as main_v37_xmr.cpp binds the
// native node's index. RandomX is a model -- keccak256(seed | hashing blob) --
// so work is real (blocks are mined by grinding the nonce) and deterministic.
//
//   C1  index reads: holds_verified; context_target at depth 1 equals the
//       index's own template difficulty (1000) and at depth 2 the hand-computed
//       window value (1011); the rules floor; an unknown anchor cannot be judged
//   C2  verdicts (relay::judge_block_ctx):
//         a block the index holds              -> used, no hash spent
//         depth 1 and depth 2 with valid PoW   -> used
//         zero work                            -> forged (ban), re-hashed first
//         work for the parent's difficulty but not the one the parent implies
//                                              -> forged (ban)
//         a height its parent does not imply   -> forged (ban), no hash spent
//         an unknown parent                    -> deferred, never banned
//         depth 3                              -> deferred, never banned, no hash
//         a verifier that cannot hash          -> deferred, never banned
//         no index wired                       -> deferred
//   C3  serving: the index does not serve a parked (unverified) alternative
//       block, so an honest server never hands out a block a peer would ban for
#include <atomic>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/relay/xmr_relay_node.hpp>
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"

using namespace gap2test;
namespace nat = c2pool::xmr::native;

static constexpr u64 kH    = 5000;   // G's height
static constexpr u64 kWin  = 100;    // difficulty rows ending at G
static constexpr u64 kStep = 1000;   // cumulative difficulty per row -> next difficulty 1000
static constexpr u64 kCum0 = 5'000'000;

static bytes32 block_id(const SynthBlock& sb) {   // keccak256(varint(len) | hashing_blob)
    std::vector<u8> pre;
    put_varint(pre, sb.hashing_blob.size());
    pre.insert(pre.end(), sb.hashing_blob.begin(), sb.hashing_blob.end());
    const auto h = ::xmr::coin::keccak256(pre.data(), pre.size());
    bytes32 b; std::memcpy(b.data(), h.data(), 32); return b;
}
static nat::Hash nh(const bytes32& b) { nat::Hash h{}; std::memcpy(h.data(), b.data(), 32); return h; }
static bytes32 bb(const nat::Hash& h) { bytes32 b{}; std::memcpy(b.data(), h.data(), 32); return b; }

static SynthBlock with_block_nonce(SynthBlock sb, std::uint32_t nonce) {
    for (int i = 0; i < 4; ++i) {
        sb.full_blob[sb.nonce_offset + i] = static_cast<u8>(nonce >> (8 * i));
        sb.hashing_blob[sb.nonce_offset + i] = static_cast<u8>(nonce >> (8 * i));
    }
    return sb;
}

// The RandomX model: deterministic, seed-dependent, and real work to meet.
static bytes32 model_pow(const std::vector<u8>& blob, const bytes32& seed) {
    std::vector<u8> pre(seed.begin(), seed.end());
    pre.insert(pre.end(), blob.begin(), blob.end());
    const auto h = ::xmr::coin::keccak256(pre.data(), pre.size());
    bytes32 b; std::memcpy(b.data(), h.data(), 32); return b;
}
static bool meets(const bytes32& pow, u64 d) {
    ::xmr::coin::Hash256 h; std::memcpy(h.data(), pow.data(), 32);
    return ::xmr::coin::check_hash(h, d, 0);
}
// The first nonce whose model hash meets `pass_d` and (if set) misses `miss_d`.
static SynthBlock grind(const SynthBlock& sb, const bytes32& seed, u64 pass_d, u64 miss_d = 0) {
    for (std::uint32_t n = 0; n < 50'000'000u; ++n) {
        SynthBlock m = with_block_nonce(sb, n);
        const bytes32 p = model_pow(m.hashing_blob, seed);
        if (pass_d && !meets(p, pass_d)) continue;
        if (miss_d && meets(p, miss_d)) continue;
        return m;
    }
    std::printf("    grind gave up\n");
    return sb;
}

struct ModelRx {
    std::atomic<u64> calls{0};
    bool down = false;
    CtxHashFn fn() {
        return [this](const std::vector<u8>& blob, const bytes32& seed, bytes32& pow) {
            ++calls;
            if (down) return false;
            pow = model_pow(blob, seed);
            return true;
        };
    }
};

// The index's own PoW gate is out of scope here (its blocks are "ours"): accept.
class AcceptPow final : public nat::IPowSource {
public:
    bool prefetch(const nat::Hash&, const std::optional<nat::Hash>&) override { return true; }
    bool seed_resident(const nat::Hash&) const override { return true; }
    nat::PowVerdict verify(const std::uint8_t*, std::size_t, const nat::Hash&, const nat::U128&, nat::Hash&) override {
        return nat::PowVerdict::Accept;
    }
};

// main_v37_xmr.cpp's binding of the native index, verbatim in behaviour.
static CtxChainSource bind_index(nat::ChainIndex& idx) {
    CtxChainSource cs;
    cs.verified = [&idx](const bytes32& id) { return idx.holds_verified(nh(id)); };
    cs.target = [&idx](const bytes32& anchor, const std::vector<CtxStep>& above, std::uint64_t major,
                       CtxTarget& out, std::string& why) {
        std::vector<std::pair<std::uint64_t, nat::U128>> rows;
        for (const auto& st : above) { nat::U128 d{}; d.lo = st.diff_lo; d.hi = st.diff_hi; rows.emplace_back(st.timestamp, d); }
        nat::U128 d{}; nat::Hash seed{}; std::uint64_t h = 0;
        const std::uint8_t mv = static_cast<std::uint8_t>(major > 255 ? 255 : major);
        if (!idx.context_target(nh(anchor), rows, mv, d, seed, h, why)) return false;
        out.diff_lo = d.lo; out.diff_hi = d.hi; out.height = h; out.seed = bb(seed);
        return true;
    };
    return cs;
}

// A structurally real Monero block in the native KATs' shape (one tagged-key
// coinbase output, a bare pubkey extra, no transactions) for the index itself.
static nat::BlockEntry native_block(const bytes32& prev, u64 height, u64 ts, u8 salt) {
    std::vector<u8> b;
    put_varint(b, 16); put_varint(b, 16); put_varint(b, ts);
    b.insert(b.end(), prev.begin(), prev.end());
    for (int i = 0; i < 4; ++i) b.push_back(0);
    put_varint(b, 2); put_varint(b, height + 60); put_varint(b, 1); b.push_back(0xFF); put_varint(b, height);
    put_varint(b, 1); put_varint(b, 600000000000ull); b.push_back(0x03);
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<u8>(0x10 + i));
    b.push_back(salt);
    put_varint(b, 33); b.push_back(0x01);
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<u8>(0x40 + i));
    b.push_back(0x00);
    put_varint(b, 0);
    nat::BlockEntry e; e.block_blob = std::move(b);
    return e;
}

static BlockCtx ctx_of(const SynthBlock& sb) {
    BlockCtx bc; std::string why;
    if (!verify_block_ctx(block_id(sb), sb.full_blob, bc, &why)) std::printf("    verify_block_ctx failed: %s\n", why.c_str());
    return bc;
}

int main() {
    Checker C;
    std::printf("== v37_xmr_ctx_pow_kat ==\n");

    // ── the index: tip G at 5000, next difficulty exactly 1000 ──────────────
    const SynthBlock G = make_block(kH, b32_of(1), 7, nullptr, 0, 10);
    const bytes32 idG = block_id(G);
    const u64 tsG = 1700000000ull + kH;   // make_block's header timestamp
    std::vector<nat::DifficultyRow> win;
    for (u64 i = 0; i < kWin; ++i) {
        nat::DifficultyRow r;
        r.timestamp = tsG - (kWin - 1 - i) * 120;
        r.cumulative_difficulty.lo = kCum0 + i * kStep;
        win.push_back(r);
    }
    nat::ChainRow tip;
    tip.height = kH; tip.id = nh(idG); tip.prev_id = nh(b32_of(1));
    tip.timestamp = tsG; tip.major_version = 16; tip.minor_version = 16;
    tip.block_weight = 300; tip.long_term_weight = 300;
    tip.difficulty.lo = kStep; tip.cumulative_difficulty = win.back().cumulative_difficulty;
    tip.pow_verified = true;
    bytes32 S{}; for (int i = 0; i < 32; ++i) S[i] = static_cast<u8>(0xc0 + i);   // the RandomX seed block id of this epoch
    const u64 epoch = ::xmr::coin::rx_seedheight(kH + 1);
    std::vector<std::uint64_t> ts60;
    for (u64 i = kWin - 60; i < kWin; ++i) ts60.push_back(win[i].timestamp);

    AcceptPow pow;
    nat::ChainIndexOptions o;
    o.net = nat::XmrNet::Regtest;
    nat::ChainIndex idx(o, pow);
    idx.seed_direct(tip, win, {300}, {300}, ts60, {{epoch, nh(S)}});
    idx.force_synced(true);
    const CtxChainSource src = bind_index(idx);

    // ── C1 index reads ──────────────────────────────────────────────────────
    C(idx.holds_verified(nh(idG)) && !idx.holds_verified(nh(b32_of(2))), "C1 holds_verified: G (a best-chain row) yes, a stranger no");
    nat::U128 d{}; nat::Hash sd{}; u64 h = 0; std::string why;
    const bool t1 = idx.context_target(nh(idG), {}, 16, d, sd, h, why);
    C(t1 && d.lo == 1000 && d.hi == 0 && h == kH + 1 && bb(sd) == S,
      "C1 depth 1: difficulty " + std::to_string(d.lo) + ", height " + std::to_string(h) + ", seed = the epoch's seed block");
    const auto ti = idx.template_inputs();
    C(ti && ti->difficulty.lo == d.lo && ti->difficulty.hi == d.hi,
      "C1 depth 1 equals the index's OWN template difficulty for the next block (" + std::to_string(ti ? ti->difficulty.lo : 0) + ")");
    {
        nat::U128 one{}; one.lo = 1000;
        // window 100 rows + (tsG+1, +1000): work 100000 over 11881 s -> ceil(100000*120/11881) = 1011
        const bool t2 = idx.context_target(nh(idG), {{tsG + 1, one}}, 16, d, sd, h, why);
        C(t2 && d.lo == 1011 && h == kH + 2,
          "C1 depth 2: the window extended by the depth-1 block gives " + std::to_string(d.lo) + " (hand-computed 1011), height " + std::to_string(h));
    }
    C(idx.context_target(nh(idG), {}, 1, d, sd, h, why) && d.lo == 1000,
      "C1 a block claiming major version 1 is judged at the tip's rules (120 s target), not a 60 s one");
    why.clear();
    const bool t3 = idx.context_target(nh(b32_of(3)), {}, 16, d, sd, h, why);
    C(!t3 && !why.empty(), "C1 an anchor the index does not hold cannot be judged: " + why);

    // ── C2 verdicts ─────────────────────────────────────────────────────────
    ModelRx rx;
    std::map<bytes32, CtxPowRec> recs;
    const CtxRecFn rec_of = [&](const bytes32& id) -> std::optional<CtxPowRec> {
        const auto it = recs.find(id);
        if (it == recs.end()) return std::nullopt;
        return it->second;
    };
    auto judge = [&](const SynthBlock& sb) { return judge_block_ctx(ctx_of(sb), src, rec_of, 2, rx.fn()); };

    {   // the index holds it
        const u64 c0 = rx.calls;
        const auto v = judge(G);
        C(v.kind == CtxPow::Indexed && v.usable() && !v.ban() && rx.calls == c0,
          "C2 a block our index holds is used with no hash spent (" + std::string(to_string(v.kind)) + ")");
    }
    const SynthBlock B1 = grind(make_block(kH + 1, idG, 11, nullptr, 0, 11), S, 1000);
    const bytes32 idB1 = block_id(B1);
    {
        const auto v = judge(B1);
        C(v.kind == CtxPow::Accept && v.depth == 1 && v.step.diff_lo == 1000 && v.step.timestamp == tsG + 1,
          "C2 depth 1 with valid PoW is used: " + v.why);
        if (v.kind == CtxPow::Accept) recs[idB1] = CtxPowRec{idG, v.step};
    }
    const SynthBlock B2 = grind(make_block(kH + 2, idB1, 12, nullptr, 0, 12), S, 1011);
    const bytes32 idB2 = block_id(B2);
    {
        const auto v = judge(B2);
        C(v.kind == CtxPow::Accept && v.depth == 2 && v.step.diff_lo == 1011,
          "C2 depth 2 with valid PoW is used at the difficulty its parent implies (1011): " + v.why);
        if (v.kind == CtxPow::Accept) recs[idB2] = CtxPowRec{idB1, v.step};
    }
    {   // zero work
        const SynthBlock Z = grind(make_block(kH + 1, idG, 13, nullptr, 0, 13), S, 0, 1000);
        const u64 c0 = rx.calls;
        const auto v = judge(Z);
        C(v.kind == CtxPow::Forged && v.ban() && !v.usable() && rx.calls == c0 + 2,
          "C2 a zero-work block is FORGED (a ban), after a confirming re-hash: " + v.why);
    }
    {   // work for 1000 (the parent's own difficulty) but not 1011 (what the parent implies at depth 2)
        const SynthBlock W2 = grind(make_block(kH + 2, idB1, 14, nullptr, 0, 14), S, 1000, 1011);
        const auto v = judge(W2);
        C(v.kind == CtxPow::Forged && v.ban(), "C2 work below the difficulty the parent implies is FORGED: " + v.why);
    }
    {   // a height its parent does not imply
        const SynthBlock Hx = grind(make_block(kH + 5, idG, 15, nullptr, 0, 15), S, 1000);
        const u64 c0 = rx.calls;
        const auto v = judge(Hx);
        C(v.kind == CtxPow::Forged && v.ban() && rx.calls == c0, "C2 a wrong height for its parent is FORGED with no hash spent: " + v.why);
    }
    {   // an unknown parent
        const SynthBlock U = grind(make_block(kH + 1, b32_of(77), 16, nullptr, 0, 16), S, 1000);
        const u64 c0 = rx.calls;
        const auto v = judge(U);
        C(v.kind == CtxPow::Defer && !v.ban() && !v.usable() && rx.calls == c0,
          "C2 a block whose parent is neither indexed nor verified here is refused WITHOUT a ban: " + v.why);
    }
    {   // depth 3
        const SynthBlock B3 = grind(make_block(kH + 3, idB2, 17, nullptr, 0, 17), S, 1);
        const u64 c0 = rx.calls;
        const auto v = judge(B3);
        C(v.kind == CtxPow::Defer && !v.ban() && rx.calls == c0,
          "C2 depth 3 is DEFERRED (waits for our own Monero sync), never banned, no hash spent: " + v.why);
    }
    {   // the verifier cannot hash
        const SynthBlock B1b = grind(make_block(kH + 1, idG, 18, nullptr, 0, 18), S, 1000);
        rx.down = true;
        const auto v = judge(B1b);
        rx.down = false;
        C(v.kind == CtxPow::Defer && !v.ban(), "C2 a verifier that cannot hash defers, never bans: " + v.why);
        const auto v2 = judge(B1b);
        C(v2.kind == CtxPow::Accept, "C2 ...and the same block is used once it can");
    }
    {   // no index wired
        const auto v = judge_block_ctx(ctx_of(B1), CtxChainSource{}, rec_of, 2, rx.fn());
        C(v.kind == CtxPow::Defer && !v.ban(), "C2 with no chain index wired nothing is used and nobody is banned");
    }
    {   // the bound is the relay's default
        RelayOptions ro;
        C(ro.ctx_max_depth == 2, "C2 RelayOptions::ctx_max_depth defaults to 2 (the tip-freshness bound)");
    }

    // ── C3 serving: a parked (unverified) alternative block is not served ──
    {
        const nat::BlockEntry e = native_block(b32_of(88), kH + 2, tsG + 2, 19);   // parent unknown -> parked
        const nat::OfferResult r = idx.offer_block(nullptr, e, false);
        std::vector<std::uint8_t> out;
        C(r.outcome == nat::OfferOutcome::ParkedOrphan && idx.alt_size() >= 1 && !idx.block_blob_of(r.id, out),
          std::string("C3 a parked orphan is held but NOT served as a context (") + nat::to_string(r.outcome) + ": " + r.why + ")");
        C(!idx.holds_verified(r.id), "C3 ...and it is not 'held verified' either");
    }

    return C.done("v37_xmr_ctx_pow_kat");
}
