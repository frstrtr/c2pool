// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_s1b_arming_kat.cpp
//
// ★★ THE FIRST_ELIGIBLE ARMING RULE — a FROM-SPEC shadow of the W4 owed fold,
//    carrying BOTH arming rules side by side, over the SAME fixtures the
//    shipped owed goldens use.
//
// THE DEFECT (observed live, 2-node XMR regtest rig, 2026-09-13).
//   owed_digest's preimage is
//       "V37O" || for each finalW row, key ASC : key(32) || i64 finalW || u64 first_eligible
//   and OwedLedger::rearm_first_eligible(bin_height) arms a key at the bin where
//       EffectiveOwed(k) = finalW(k) - SUM over PENDING blocks of payout(k)
//   first goes strictly positive. The PENDING set is deliberately NOT
//   synchronised across nodes — tolerating that relay-hop skew is exactly why
//   the v0x03 wire-carry exists — so two honest nodes handed the SAME finalize
//   stream arm the same key at DIFFERENT bins. Arming is sticky, so from that
//   moment their owed_digests differ FOREVER while their balances stay
//   byte-identical. On the rig both nodes replayed events=269 from their own W6
//   store, both reported one owed key at the same balance at hw=47 cursor=44,
//   and the digests still read 6bd47268... (A) and ec91e352... (B).
//
// THE RULING (operator, 2026-09-13): arm on the FINALIZED HALF — finalW(k) > 0
//   — instead of on EffectiveOwed. The finalize stream is byte-identical
//   cross-node (the F1 driver agrees on bids, heights, bins and order), so
//   first_eligible(k) becomes a function of the finalized balance ALONE and is
//   identical on every honest node. Rejected: dropping the column from the
//   preimage (loses the payout-order commitment) and carrying it on the wire
//   (extra wire + winner-trust).
//
// ★ WHY THIS FILE IS A SHADOW AND NOT THE FIX.
//   rearm_first_eligible lives in the consensus fold body
//   (src/c2pool/v37/w4_settlement.hpp). Changing it is a consensus activation
//   and the operator's hand. This suite therefore implements the ledger
//   FROM SPEC — its own sha256d, its own FOUND/FINALIZE/ORPHAN state machine,
//   its own preimage — and carries BOTH rules as a compile-time-free runtime
//   switch. It touches no canon file. The exact minimal canon diff is in the
//   turnkey note at the bottom of this comment and in the PR body.
//
// WHAT IT PINS
//   1  the from-spec hash IS the canon hash: sha256d("V37O") == the b4db1ded...
//      empty-ledger anchor, which is therefore UNCHANGED under both rules (an
//      empty finalized partition has no rows, so it has no fe column at all).
//   2  ORACLE — driven over oes_v1::schedule_v1() (the shared schedule the
//      shipped owed-event-MMR goldens were minted on), the OLD rule reproduces
//      every published value byte-for-byte at every cut: owed_digest,
//      ledger_seq, the w5 StateCommitment root gate-OFF and gate-ON. That is
//      what makes this model an oracle rather than an opinion.
//   3  RE-MINT — the same schedule under the NEW rule. Cuts 0/6/15 do not move;
//      cuts 21/24 do, and the new values are pinned here.
//   4  SHAPE INVARIANCE — for any stream whose FOUND events carry an EMPTY
//      payout and are immediately followed by their FINALIZE, EffectiveOwed is
//      identically finalW at every rearm, so the two rules agree pointwise.
//      That is the shape of the V37.1 ridge schedule and of both DROPS
//      activation mints, so 9cfaf97d.../87c5249a.../984c7753.../ae44add2...
//      and the two DROPS folds do NOT move. Proved on 20000 randomised
//      streams including NEGATIVE credits (the DROPS REPLACE delta).
//   5  THE LIVE FORK, REPRODUCED AND CLOSED — the real captured event stream
//      from the rig's node A store, replayed against a second node that
//      received the same stream with two peer FOUNDs arriving one relay hop
//      earlier. Identical finalW, identical ledger_seq, one row, one key.
//      OLD rule: fe 4 vs 5, two different digests. NEW rule: one digest.
//   6  GENERAL DETERMINISM — randomised skew over random streams: the OLD rule
//      forks a large fraction of honest node pairs; the NEW rule forks none.
//
// Stdlib only. No engine, no coin backend, no sockets, no clocks, no threads.
// SAME HOLLOW-GREEN GUARD as the sibling suites: ALSO listed on BOTH build.yml
// --target lists (the Linux x86_64 leg and the ASan+UBSan leg) so CI compiles
// and RUNS it instead of registering a NOT_BUILT CTest sentinel (the DGB #137 /
// #769 / c2pool#1539 unregistered-KAT class).
// ===========================================================================

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "owed_event_mmr_golden_v1.hpp"   // the SHARED schedule + published goldens

namespace {

using Bytes32 = std::array<std::uint8_t, 32>;
using Amounts = std::map<Bytes32, long long>;

// ── from-spec SHA-256 / sha256d ───────────────────────────────────────────
// Written out here on purpose: the point of a from-spec shadow is that it does
// not borrow the canon's hash, so case A1 (sha256d("V37O") == the shipped
// anchor) is a real cross-check of the construction and not a tautology.
struct Sha256 {
    std::uint32_t h[8]; std::uint64_t len = 0; std::uint8_t buf[64]; std::size_t n = 0;
    Sha256() { h[0]=0x6a09e667;h[1]=0xbb67ae85;h[2]=0x3c6ef372;h[3]=0xa54ff53a;
               h[4]=0x510e527f;h[5]=0x9b05688c;h[6]=0x1f83d9ab;h[7]=0x5be0cd19; }
    static std::uint32_t rr(std::uint32_t x, int c) { return (x >> c) | (x << (32 - c)); }
    void block(const std::uint8_t* p) {
        static const std::uint32_t K[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (std::uint32_t(p[4*i]) << 24) | (std::uint32_t(p[4*i+1]) << 16) |
                   (std::uint32_t(p[4*i+2]) << 8) | std::uint32_t(p[4*i+3]);
        for (int i = 16; i < 64; ++i) {
            std::uint32_t s0 = rr(w[i-15],7) ^ rr(w[i-15],18) ^ (w[i-15] >> 3);
            std::uint32_t s1 = rr(w[i-2],17) ^ rr(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        std::uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],hh=h[7];
        for (int i = 0; i < 64; ++i) {
            std::uint32_t S1 = rr(e,6) ^ rr(e,11) ^ rr(e,25);
            std::uint32_t ch = (e & f) ^ ((~e) & g);
            std::uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            std::uint32_t S0 = rr(a,2) ^ rr(a,13) ^ rr(a,22);
            std::uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            std::uint32_t t2 = S0 + mj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;
    }
    void update(const std::uint8_t* p, std::size_t l) {
        len += l;
        while (l) {
            std::size_t t = std::min(l, std::size_t(64) - n);
            std::memcpy(buf + n, p, t); n += t; p += t; l -= t;
            if (n == 64) { block(buf); n = 0; }
        }
    }
    Bytes32 final_() {
        std::uint64_t bits = len * 8;
        std::uint8_t pad = 0x80; update(&pad, 1);
        std::uint8_t z = 0; while (n != 56) update(&z, 1);
        std::uint8_t b8[8];
        for (int i = 0; i < 8; ++i) b8[i] = std::uint8_t((bits >> (56 - 8*i)) & 0xff);
        update(b8, 8);
        Bytes32 o{};
        for (int i = 0; i < 8; ++i) {
            o[4*i]   = std::uint8_t((h[i] >> 24) & 0xff); o[4*i+1] = std::uint8_t((h[i] >> 16) & 0xff);
            o[4*i+2] = std::uint8_t((h[i] >> 8) & 0xff);  o[4*i+3] = std::uint8_t(h[i] & 0xff);
        }
        return o;
    }
};
Bytes32 sha256(const std::uint8_t* p, std::size_t n) { Sha256 s; s.update(p, n); return s.final_(); }
Bytes32 sha256d(const std::vector<std::uint8_t>& v) {
    Bytes32 a = sha256(v.data(), v.size());
    return sha256(a.data(), a.size());
}
std::string hex(const Bytes32& d) {
    static const char* H = "0123456789abcdef";
    std::string s; for (auto b : d) { s += H[b >> 4]; s += H[b & 15]; } return s;
}
void put_u64(std::vector<std::uint8_t>& v, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back(std::uint8_t((x >> (8*i)) & 0xff));
}

// ── the two arming rules ──────────────────────────────────────────────────
enum class Arm { EffectiveOwed,   // SHIPPED today — forks under relay-hop skew
                 FinalizedHalf }; // the RULING — a function of finalW alone

// ── the from-spec OWED ledger ─────────────────────────────────────────────
// Mirrors OwedLedger's public contract exactly: FOUND normalises zero rows and
// is idempotent per bid; FINALIZE applies credit - payout, rearms, then prunes
// zero-and-unarmed rows; ORPHAN removes a pending bid or prices a post-SETTLED
// residual; owed_digest commits the FINALIZED partition only, key ASC, skipping
// w == 0. ledger_seq bumps once per non-no-op mutation.
struct Model {
    Arm arm = Arm::EffectiveOwed;
    std::uint64_t seq = 0;
    Amounts finalW;
    std::map<std::string, std::pair<Amounts, Amounts>> pending;  // bid -> (credit, payout)
    std::set<std::string> settled;
    std::map<Bytes32, std::uint64_t> fe;
    long long residual = 0;

    explicit Model(Arm a) : arm(a) {}

    void on_found(const std::string& bid, const Amounts& credit, const Amounts& payout) {
        if (pending.count(bid) || settled.count(bid)) return;
        Amounts c, p;
        for (const auto& [k, v] : credit) if (v != 0) c[k] = v;
        for (const auto& [k, v] : payout) if (v != 0) p[k] = v;
        pending.emplace(bid, std::make_pair(std::move(c), std::move(p)));
        ++seq;
    }
    void on_finalized(const std::string& bid, std::uint64_t bin_height) {
        auto it = pending.find(bid);
        if (it == pending.end()) return;
        for (const auto& [k, v] : it->second.first)  finalW[k] += v;
        for (const auto& [k, v] : it->second.second) finalW[k] -= v;
        pending.erase(it);
        settled.insert(bid);
        rearm(bin_height);
        prune();
        ++seq;
    }
    void on_orphaned(const std::string& bid, const Amounts& settled_payout) {
        auto it = pending.find(bid);
        if (it != pending.end()) { pending.erase(it); ++seq; return; }
        if (settled.count(bid)) {
            long long r = 0; for (const auto& [k, v] : settled_payout) { (void)k; r += v; }
            if (r > 0) residual += r;
            ++seq;
        }
    }
    long long effective_owed(const Bytes32& k) const {
        long long v = 0;
        auto f = finalW.find(k); if (f != finalW.end()) v = f->second;
        for (const auto& [bid, cp] : pending) {
            (void)bid; auto p = cp.second.find(k);
            if (p != cp.second.end()) v -= p->second;
        }
        return v;
    }
    void rearm(std::uint64_t bin_height) {
        std::set<Bytes32> keys;
        for (const auto& [k, w] : finalW) { (void)w; keys.insert(k); }
        for (const auto& [k, b] : fe)     { (void)b; keys.insert(k); }
        for (const auto& [bid, cp] : pending) {
            (void)bid; for (const auto& [k, v] : cp.second) { (void)v; keys.insert(k); }
        }
        for (const auto& k : keys) {
            bool live;
            if (arm == Arm::EffectiveOwed) {
                live = effective_owed(k) > 0;
            } else {
                auto f = finalW.find(k);
                live = (f != finalW.end() && f->second > 0);
            }
            if (live) { if (!fe.count(k)) fe[k] = bin_height; }
            else        fe.erase(k);
        }
    }
    void prune() {
        for (auto it = finalW.begin(); it != finalW.end();) {
            if (it->second == 0 && !fe.count(it->first)) it = finalW.erase(it);
            else ++it;
        }
    }
    std::uint64_t fe_at(const Bytes32& k) const {
        auto it = fe.find(k); return it == fe.end() ? 0ull : it->second;
    }
    Bytes32 owed_digest() const {
        std::vector<std::uint8_t> pre = {'V','3','7','O'};
        for (const auto& [k, w] : finalW) {
            if (w == 0) continue;
            pre.insert(pre.end(), k.begin(), k.end());
            put_u64(pre, static_cast<std::uint64_t>(w));
            put_u64(pre, fe_at(k));
        }
        return sha256d(pre);
    }
};

void apply_step(Model& m, const oes_v1::Step& st) {
    switch (st.op) {
        case 0: m.on_found(st.bid, st.credit, st.payout); break;
        case 1: m.on_finalized(st.bid, st.bin_height); break;
        case 2: m.on_orphaned(st.bid, st.settled); break;
        default: break;
    }
}

// ── from-spec w5 StateCommitment (leaf rule mirrored from v37_lane.hpp) ────
Bytes32 leaf_hash(const std::vector<std::uint8_t>& p) {
    std::vector<std::uint8_t> b; b.reserve(p.size() + 1);
    b.push_back(0x00); b.insert(b.end(), p.begin(), p.end());
    return sha256d(b);
}
Bytes32 interior(const Bytes32& l, const Bytes32& r) {
    std::vector<std::uint8_t> b; b.reserve(65);
    b.push_back(0x01); b.insert(b.end(), l.begin(), l.end()); b.insert(b.end(), r.begin(), r.end());
    return sha256d(b);
}
Bytes32 merkle_root(std::vector<Bytes32> level) {
    while (level.size() > 1) {
        std::vector<Bytes32> next;
        std::size_t i = 0;
        for (; i + 1 < level.size(); i += 2) next.push_back(interior(level[i], level[i+1]));
        if (i < level.size()) next.push_back(level[i]);          // promote odd
        level = std::move(next);
    }
    return level[0];
}
Bytes32 unhex32(const char* s) {
    Bytes32 o{};
    auto nib = [](char c) -> int { return c >= 'a' ? c - 'a' + 10 : c - '0'; };
    for (int i = 0; i < 32; ++i) o[i] = std::uint8_t((nib(s[2*i]) << 4) | nib(s[2*i+1]));
    return o;
}
// mmr == nullptr -> gate OFF (no "V37M" leaf). The MMR root itself is NOT a
// function of first_eligible (it commits the event payloads), so the gate-ON
// root is re-derived with the PUBLISHED mmr leaf_count/root as inputs.
Bytes32 sc_root(const Model& m, std::uint64_t chain,
                const std::pair<std::uint64_t, const char*>* mmr) {
    std::vector<std::pair<Bytes32, std::uint64_t>> rows;
    for (const auto& [k, w] : m.finalW)
        if (w > 0) rows.emplace_back(k, static_cast<std::uint64_t>(w));
    std::sort(rows.begin(), rows.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    std::vector<Bytes32> leaves;
    {   std::vector<std::uint8_t> p = {'V','3','7','S'};
        put_u64(p, chain); put_u64(p, m.seq); put_u64(p, rows.size());
        Bytes32 od = m.owed_digest(); p.insert(p.end(), od.begin(), od.end());
        leaves.push_back(leaf_hash(p)); }
    for (const auto& [k, w] : rows) {
        std::vector<std::uint8_t> p = {'V','3','7','E'};
        p.insert(p.end(), k.begin(), k.end()); put_u64(p, w);
        leaves.push_back(leaf_hash(p));
    }
    if (mmr) {
        std::vector<std::uint8_t> p = {'V','3','7','M'};
        put_u64(p, mmr->first);
        Bytes32 r = unhex32(mmr->second); p.insert(p.end(), r.begin(), r.end());
        leaves.push_back(leaf_hash(p));
    }
    return merkle_root(leaves);
}

// ── tiny deterministic RNG (splitmix64) ───────────────────────────────────
struct Rng {
    std::uint64_t s;
    explicit Rng(std::uint64_t seed) : s(seed) {}
    std::uint64_t next() {
        std::uint64_t z = (s += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    std::uint64_t below(std::uint64_t n) { return next() % n; }
};

// ── goldens ───────────────────────────────────────────────────────────────
// The empty-ledger anchor, sha256d("V37O"). NO ROWS -> no fe column -> the
// arming rule cannot reach it. Asserted under BOTH rules.
const char* ANCHOR_OWED_EMPTY =
    "b4db1ded95a73f939975a259f9b48a1d182109f44397ed77e35d624f1a5cf339";

// ★ THE RE-MINT. The oes_v1 schedule is the only shipped owed fixture that
// carries a PENDING payout across a FINALIZE, so it is the only one the ruling
// moves. Cuts 0/6/15 are unchanged; cuts 21 and 24 land on these values.
const char* REMINT_OWED_21_24 =
    "dff20133e4824072c224469a1aed460620ddf7d55275aff40e944ff8f0b6bdf7";
const char* SUPERSEDED_OWED_21_24 =
    "5e3c0cd2ff4db05b1111ef2cb8174838f238f61dae0dea258ba818528908b2e4";
const char* REMINT_SC_OFF_21 = "a436d0590f962719165869bc4ea09ed30312755dc9fbb042696b9609159cefec";
const char* REMINT_SC_ON_21  = "0379deb8676d1da6b2022d158277bb06363591c8a34bddf7150924b2b1ce8444";
const char* REMINT_SC_OFF_24 = "3f030a249bd4b36fbca505aba6add56a1cdd92072b2197182b6ec948aac4e487";
const char* REMINT_SC_ON_24  = "cd57f501ae85c7c6fb636c2e49835162fa6dd3c1c91585e1b854fcec1298cbdf";

// ★ THE LIVE FORK, reproduced from the rig's own captured W6 event stream.
// Identity key, credits, payouts and bins are the literal bytes node A wrote to
// /rig/settleA/settle.img. The only thing varied is WHEN two peer FOUNDs
// arrived — one relay hop earlier on the second node.
const char* LIVE_KEY_HEX =
    "b9d5bd32d700531cee590afe283b328f03c7712c82b4aca20392dd0f3e41643f";
const char* FORK_OLD_A   = "d004509fe8bc58afe6aebe5f861a31ea1ea30785b69996369914e922d3d463d9";
const char* FORK_OLD_B   = "689d08268d5dd8b6683bc8ff8a2293b66af692f8bbcfebdf2eebccd5c0350b9c";
const char* CONVERGED    = "d004509fe8bc58afe6aebe5f861a31ea1ea30785b69996369914e922d3d463d9";

long g_checks = 0, g_fail = 0;
void check(bool ok, const std::string& what) {
    ++g_checks;
    if (!ok) { ++g_fail; std::printf("  FAIL: %s\n", what.c_str()); }
    else       std::printf("  ok:   %s\n", what.c_str());
}

// ── live stream fixtures ──────────────────────────────────────────────────
Bytes32 live_key() { return unhex32(LIVE_KEY_HEX); }
oes_v1::Step LF(const char* bid, long long c, long long p) {
    oes_v1::Step s; s.op = 0; s.bid = bid; s.credit[live_key()] = c;
    if (p) s.payout[live_key()] = p; return s;
}
oes_v1::Step LFIN(const char* bid, std::uint64_t bin) {
    oes_v1::Step s; s.op = 1; s.bid = bid; s.bin_height = bin; return s;
}
oes_v1::Step LORP(const char* bid) { oes_v1::Step s; s.op = 2; s.bid = bid; return s; }

std::vector<oes_v1::Step> live_node_a() {
    return { LF("f4ebc89e", 35184338534400LL, 0), LF("fce7431b", 35184338534400LL, 0),
             LF("8c300bf5", 35184271425600LL, 0), LF("c4365009", 35184271425600LL, 0),
             LF("7098a41e", 35184271425600LL, 0), LF("cd6d4a23", 35184271425600LL, 0),
             LF("f49a6f06", 35184204316927LL, 0), LF("653c35e4", 35184204316927LL, 0),
             LF("68644a0c", 35184137208383LL, 0),
             LFIN("f4ebc89e", 4), LORP("fce7431b"),
             LF("2e4af6a8", 35184070099967LL, 35184070099966LL),
             LF("f66767f5", 35184070099967LL, 35184070099966LL),
             LFIN("8c300bf5", 5), LORP("c4365009"), LORP("7098a41e"), LORP("cd6d4a23") };
}
// The SAME events, the SAME finalize substream in the SAME order at the SAME
// bins — only the two payout-bearing peer FOUNDs arrive before the first
// finalize instead of after it.
std::vector<oes_v1::Step> live_node_b_skewed() {
    auto a = live_node_a();
    std::vector<oes_v1::Step> b;
    for (int i = 0; i < 9; ++i) b.push_back(a[i]);
    b.push_back(a[11]); b.push_back(a[12]);
    b.push_back(a[9]);  b.push_back(a[10]);
    for (int i = 13; i < 17; ++i) b.push_back(a[i]);
    return b;
}

} // namespace

int main() {
    std::printf("=== v37 S-1b FIRST_ELIGIBLE ARMING — from-spec shadow (canon untouched) ===\n\n");

    // ── A. the from-spec hash IS the canon hash, and the empty anchor ──────
    std::printf("[A] from-spec construction + the EMPTY-LEDGER anchor\n");
    {
        // FIPS 180-4 vector, so a broken sha256 cannot silently agree with itself.
        const char* abc = "abc";
        Bytes32 d1 = sha256(reinterpret_cast<const std::uint8_t*>(abc), 3);
        check(hex(d1) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
              "A0 sha256(\"abc\") == the FIPS 180-4 vector");
        for (Arm a : {Arm::EffectiveOwed, Arm::FinalizedHalf}) {
            Model m(a);
            check(hex(m.owed_digest()) == ANCHOR_OWED_EMPTY,
                  std::string("A1 empty ledger owed_digest == b4db1ded... under the ") +
                  (a == Arm::EffectiveOwed ? "OLD" : "NEW") + " rule");
        }
        Model m0(Arm::FinalizedHalf);
        check(m0.finalW.empty() && m0.fe.empty(),
              "A2 ...and it is UNCHANGED for a structural reason: no rows, so no fe column");
    }

    // ── B. ORACLE: the OLD rule reproduces every published value ──────────
    std::printf("\n[B] ORACLE — the OLD (EffectiveOwed) rule over oes_v1::schedule_v1()\n");
    const auto sch = oes_v1::schedule_v1();
    const auto goldens = oes_v1::goldens_v1();
    const std::uint64_t CHAIN = 7;
    for (const auto& g : goldens) {
        Model m(Arm::EffectiveOwed);
        for (std::size_t i = 0; i < g.steps && i < sch.size(); ++i) apply_step(m, sch[i]);
        std::pair<std::uint64_t, const char*> mmr{g.mmr_leaves, g.mmr_root};
        const bool ok_owed = hex(m.owed_digest()) == g.owed_digest;
        const bool ok_seq  = m.seq == g.ledger_seq;
        const bool ok_off  = hex(sc_root(m, CHAIN, nullptr)) == g.sc_root_gate_off;
        const bool ok_on   = hex(sc_root(m, CHAIN, &mmr))    == g.sc_root_gate_on;
        char b[192];
        std::snprintf(b, sizeof b,
                      "B@%zu owed_digest + ledger_seq + StateCommitment root (gate OFF and ON) "
                      "all reproduce the shipped goldens", g.steps);
        check(ok_owed && ok_seq && ok_off && ok_on, b);
    }

    // ── C. RE-MINT under the ruling ───────────────────────────────────────
    std::printf("\n[C] RE-MINT — the NEW (finalized-half) rule over the SAME schedule\n");
    for (const auto& g : goldens) {
        Model m(Arm::FinalizedHalf);
        for (std::size_t i = 0; i < g.steps && i < sch.size(); ++i) apply_step(m, sch[i]);
        std::pair<std::uint64_t, const char*> mmr{g.mmr_leaves, g.mmr_root};
        const std::string od = hex(m.owed_digest());
        const std::string so = hex(sc_root(m, CHAIN, nullptr));
        const std::string sn = hex(sc_root(m, CHAIN, &mmr));
        std::printf("   cut=%2zu seq=%llu owed=%s\n", g.steps,
                    static_cast<unsigned long long>(m.seq), od.c_str());
        char b[160];
        if (g.steps < 21) {
            std::snprintf(b, sizeof b, "C@%zu the ruling does NOT move this cut", g.steps);
            check(od == g.owed_digest && so == g.sc_root_gate_off && sn == g.sc_root_gate_on, b);
        } else {
            std::snprintf(b, sizeof b, "C@%zu owed_digest re-mints to dff20133... "
                          "(supersedes 5e3c0cd2...)", g.steps);
            check(od == REMINT_OWED_21_24 && g.owed_digest == std::string(SUPERSEDED_OWED_21_24) &&
                  od != g.owed_digest, b);
            const char* wo = g.steps == 21 ? REMINT_SC_OFF_21 : REMINT_SC_OFF_24;
            const char* wn = g.steps == 21 ? REMINT_SC_ON_21  : REMINT_SC_ON_24;
            std::snprintf(b, sizeof b, "C@%zu StateCommitment root re-mints too "
                          "(the V37S summary leaf carries owed_digest)", g.steps);
            check(so == wo && sn == wn && so != g.sc_root_gate_off && sn != g.sc_root_gate_on, b);
        }
    }
    {   // non-vacuity: the schedule really does hold a pending payout across a
        // finalize, which is the ONLY way the two rules can disagree.
        Model m(Arm::EffectiveOwed);
        bool saw_pending_payout_at_finalize = false;
        for (const auto& st : sch) {
            if (st.op == 1 && m.pending.count(st.bid)) {
                for (const auto& [bid, cp] : m.pending)
                    if (bid != st.bid && !cp.second.empty()) saw_pending_payout_at_finalize = true;
            }
            apply_step(m, st);
        }
        check(saw_pending_payout_at_finalize,
              "C-NV the fixture is non-vacuous: a FINALIZE runs with another block's "
              "payout still PENDING");
    }

    // ── D. SHAPE INVARIANCE — the DROPS / V37.1 fixtures do NOT move ───────
    std::printf("\n[D] SHAPE INVARIANCE — payout == {} and FINALIZE adjacent to FOUND\n");
    {
        Rng r(0x5EED4096ull);
        const int TRIALS = 20000;
        int diverged = 0, moved_fe = 0;
        for (int t = 0; t < TRIALS; ++t) {
            const int nk = 1 + int(r.below(5));
            std::vector<Bytes32> keys(nk);
            for (auto& k : keys) for (auto& b : k) b = std::uint8_t(r.below(256));
            std::vector<oes_v1::Step> steps;
            const int nb = 1 + int(r.below(6));
            for (int i = 0; i < nb; ++i) {
                oes_v1::Step f; f.op = 0; f.bid = "b" + std::to_string(i);
                for (const auto& k : keys)
                    if (r.below(10) < 8)
                        f.credit[k] = static_cast<long long>(r.below(10000001ull)) - 5000000LL;
                steps.push_back(f);                                   // payout deliberately EMPTY
                oes_v1::Step fin; fin.op = 1; fin.bid = f.bid; fin.bin_height = 100 + 13ull*i;
                steps.push_back(fin);
            }
            Model o(Arm::EffectiveOwed), n(Arm::FinalizedHalf);
            for (const auto& s : steps) { apply_step(o, s); apply_step(n, s); }
            if (!(o.owed_digest() == n.owed_digest())) ++diverged;
            if (o.fe != n.fe) ++moved_fe;
        }
        std::printf("   randomised trials=%d (credits INCLUDE negative REPLACE deltas): "
                    "digest divergences=%d fe divergences=%d\n", TRIALS, diverged, moved_fe);
        check(diverged == 0 && moved_fe == 0,
              "D1 on this shape the two rules are POINTWISE IDENTICAL, for any credits");
        std::printf("   => the V37.1 ridge anchors 9cfaf97d.../87c5249a..., the DROPS mints\n"
                    "      984c7753...(arity 2) / ae44add2...(arity 1) and their folds\n"
                    "      b03abb1f... / 50b5d7d1..., and the S-1 live-wiring golden\n"
                    "      4e13dd3f... are all minted on this shape and do NOT move.\n");
    }

    // ── E. THE LIVE FORK, reproduced and closed ───────────────────────────
    std::printf("\n[E] THE LIVE 2-NODE FORK — real captured stream, relay-hop skew\n");
    {
        const auto A = live_node_a();
        const auto B = live_node_b_skewed();
        check(A.size() == B.size(), "E0 both nodes see the SAME 17 events");

        Model oa(Arm::EffectiveOwed), ob(Arm::EffectiveOwed);
        for (const auto& s : A) apply_step(oa, s);
        for (const auto& s : B) apply_step(ob, s);
        check(oa.finalW == ob.finalW && oa.seq == ob.seq && oa.finalW.size() == 1,
              "E1 identical finalW, identical ledger_seq, ONE row, ONE key");
        std::printf("   finalW = %lld piconero on key %s...\n",
                    oa.finalW.begin()->second, hex(oa.finalW.begin()->first).substr(0, 16).c_str());
        std::printf("   OLD  A first_eligible=%llu owed=%s\n",
                    static_cast<unsigned long long>(oa.fe_at(live_key())), hex(oa.owed_digest()).c_str());
        std::printf("   OLD  B first_eligible=%llu owed=%s\n",
                    static_cast<unsigned long long>(ob.fe_at(live_key())), hex(ob.owed_digest()).c_str());
        check(oa.fe_at(live_key()) == 4 && ob.fe_at(live_key()) == 5,
              "E2 the OLD rule arms the SAME key at DIFFERENT bins (4 vs 5)");
        check(hex(oa.owed_digest()) == FORK_OLD_A && hex(ob.owed_digest()) == FORK_OLD_B &&
              !(oa.owed_digest() == ob.owed_digest()),
              "E3 ...so two honest nodes commit DIFFERENT owed_digests — the live defect");

        Model na(Arm::FinalizedHalf), nb(Arm::FinalizedHalf);
        for (const auto& s : A) apply_step(na, s);
        for (const auto& s : B) apply_step(nb, s);
        std::printf("   NEW  A first_eligible=%llu owed=%s\n",
                    static_cast<unsigned long long>(na.fe_at(live_key())), hex(na.owed_digest()).c_str());
        std::printf("   NEW  B first_eligible=%llu owed=%s\n",
                    static_cast<unsigned long long>(nb.fe_at(live_key())), hex(nb.owed_digest()).c_str());
        check(na.fe_at(live_key()) == nb.fe_at(live_key()) && na.fe_at(live_key()) == 4,
              "E4 the NEW rule arms both at the bin the FINALIZED balance first went positive");
        check(na.owed_digest() == nb.owed_digest() && hex(na.owed_digest()) == CONVERGED,
              "E5 ★ the forking case CONVERGES — byte-equal owed_digest on both nodes");
        check(na.finalW == oa.finalW,
              "E6 ...and the balances are untouched: the ruling moves the AGE key, never the money");
    }

    // ── F. GENERAL cross-node determinism under arbitrary skew ────────────
    std::printf("\n[F] GENERAL DETERMINISM — random streams, random relay-hop skew\n");
    {
        Rng r(0x1625A11Bull);
        const int TRIALS = 3000;
        int old_forks = 0, new_forks = 0;
        for (int t = 0; t < TRIALS; ++t) {
            const int nk = 1 + int(r.below(4));
            std::vector<Bytes32> keys(nk);
            for (auto& k : keys) for (auto& b : k) b = std::uint8_t(r.below(256));
            const int nb = 3 + int(r.below(7));
            std::vector<oes_v1::Step> founds, fins;
            for (int i = 0; i < nb; ++i) {
                oes_v1::Step f; f.op = 0; f.bid = "b" + std::to_string(i);
                for (const auto& k : keys) {
                    if (r.below(10) < 9) f.credit[k]  = 1 + static_cast<long long>(r.below(1000000000000ull));
                    if (r.below(10) < 5) f.payout[k]  = 1 + static_cast<long long>(r.below(1000000000000ull));
                }
                founds.push_back(f);
            }
            std::uint64_t bh = 1 + r.below(50);
            for (int i = 0; i < nb; ++i) {
                if (r.below(10) < 6) continue;
                bh += 1 + r.below(5);
                oes_v1::Step fin; fin.op = 1; fin.bid = "b" + std::to_string(i); fin.bin_height = bh;
                fins.push_back(fin);
            }
            if (fins.empty()) { oes_v1::Step fin; fin.op = 1; fin.bid = "b0"; fin.bin_height = bh + 1; fins.push_back(fin); }
            // Two arrival orders of the SAME events: the finalize substream is held
            // byte-identical (order AND bins); only the FOUND positions move, and a
            // FOUND always stays strictly before its own FINALIZE.
            auto weave = [&](Rng& rr) {
                std::vector<oes_v1::Step> out = fins;
                for (const auto& f : founds) {
                    std::size_t lim = out.size();
                    for (std::size_t i = 0; i < out.size(); ++i)
                        if (out[i].op == 1 && out[i].bid == f.bid) { lim = i; break; }
                    out.insert(out.begin() + static_cast<long>(rr.below(lim + 1)), f);
                }
                return out;
            };
            const auto oa_ord = weave(r), ob_ord = weave(r);
            for (Arm a : {Arm::EffectiveOwed, Arm::FinalizedHalf}) {
                Model A(a), B(a);
                for (const auto& s : oa_ord) apply_step(A, s);
                for (const auto& s : ob_ord) apply_step(B, s);
                if (!(A.finalW == B.finalW)) { std::printf("  FAIL: F-pre finalW must agree\n"); ++g_fail; }
                if (!(A.owed_digest() == B.owed_digest())) {
                    if (a == Arm::EffectiveOwed) ++old_forks; else ++new_forks;
                }
            }
        }
        std::printf("   trials=%d   OLD(EffectiveOwed) forks=%d   NEW(finalized-half) forks=%d\n",
                    TRIALS, old_forks, new_forks);
        check(new_forks == 0, "F1 ★ the NEW rule NEVER forks two honest nodes under relay-hop skew");
        check(old_forks > 0,  "F2 ...and the test is not vacuous: the OLD rule forks a large fraction");
    }

    std::printf("\n=== %ld checks, %ld failures ===\n", g_checks, g_fail);
    if (g_fail == 0) {
        std::printf("\nMACHINE-READABLE MINT\n");
        std::printf("remint_owed_cut21=%s\n", REMINT_OWED_21_24);
        std::printf("remint_owed_cut24=%s\n", REMINT_OWED_21_24);
        std::printf("remint_sc_off_cut21=%s\n", REMINT_SC_OFF_21);
        std::printf("remint_sc_on_cut21=%s\n",  REMINT_SC_ON_21);
        std::printf("remint_sc_off_cut24=%s\n", REMINT_SC_OFF_24);
        std::printf("remint_sc_on_cut24=%s\n",  REMINT_SC_ON_24);
        std::printf("empty_anchor_unchanged=%s\n", ANCHOR_OWED_EMPTY);
        std::printf("fork_old_A=%s\n", FORK_OLD_A);
        std::printf("fork_old_B=%s\n", FORK_OLD_B);
        std::printf("converged=%s\n",  CONVERGED);
    }
    return g_fail == 0 ? 0 : 1;
}
