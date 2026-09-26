// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_next_seed_kat.cpp   (NEXT-SEED ANNOUNCE)
//
// Operator ruling 09-26: announce the next RandomX seed ahead of the switch.
// The settlement provider used to serve next_seed_hash = nullopt (monerod's
// get_miner_data has no such field), so at a seed switch the ~256 MiB Argon2d
// cache init ran on the stratum thread inside the new-template hook (a live
// node stalled a job push ~6 s) and no miner could prepare early.
//
// Runs the path that serves miners: the REAL native chain index
// (ChainStateView, the C4 golden windows re-seeded at heights around an epoch
// boundary E), NativeMinerDataSource, XmrSettlementTemplateProvider,
// SettlementStratumTemplateSource and the merged XmrStratumServer, then the
// daemon's O2RandomXVerifier fed the served jobs exactly as the listener hook
// feeds it (on_template).
//   (A) next_seed_hash is present in the served job for EXACTLY the 64
//       heights before the switch (monerod get_block_template rule:
//       rx_seedheights(h) -> seed != next), equal to the block id at the next
//       seed height; absent everywhere else; the stratum job JSON carries
//       "next_seed_hash" exactly then.
//   (C) the daemon arm (get_miner_data has none): the id comes from one
//       get_block_header_by_height per tip inside the window, none outside.
//   (B) across the announced switch: no cache initialisation at the switch
//       job, the previous epoch stays resident, every hash equals a FRESH
//       cache + FRESH VM reference.
// RED on the pre-fix tree (nothing announced; the switch keys the cache on
// the listener), GREEN on the fix. HEAVY (real RandomX, up to 4 x 256 MiB).
// ===========================================================================
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/native/contracts/fakes/fakes.hpp"
#include "impl/xmr/native/template/xmr_native_miner_data.hpp"

#include "c2pool/v37/xmr/xmr_o2_randomx_verify.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"

#include "xmr_c4_state_builder.hpp"

using namespace c2pool::xmr::native;
using namespace c2pool::xmr::native::testkit;

namespace o2    = c2pool::v37n::xmr::o2;
namespace strat = ::v37::xmr::stratum;
namespace tmpl  = c2pool::xmr::native::tmpl;

namespace {

int g_fail = 0;
void check(bool ok, const std::string& what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

// Monero rx_seedheight / rx_seedheights, RESTATED (not borrowed) so the rule
// under test is judged against Monero and not against the code that serves it.
std::uint64_t ref_seedheight(std::uint64_t h) {
    return h <= 2048 + 64 ? 0 : (h - 64 - 1) & ~std::uint64_t(2048 - 1);
}

// ---- the lane fixture (as v37_xmr_m2_native_settlement_kat) ----------------
std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}
struct LaneFixture {
    o2::XmrOwedFixture      ledger{static_cast<::v37::ChainId>(0x0000ABCDu)};
    o2::XmrSettlementConfig scfg;
    LaneFixture() {
        const auto P1 = point_of(1), P2 = point_of(2), P3 = point_of(3), P4 = point_of(4);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P1, P2), 3'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P3, P2), 2'000'000'000ull);
        scfg.h_min = 0; scfg.output_cap = 0;
        scfg.set_residual_sink_std(P4, P2);
    }
};

// ---- the C4 golden windows, rolled once (build_state's roll, verbatim) -----
struct Windows {
    std::vector<DifficultyRow> diff;
    std::vector<std::uint64_t> shortw, longw, times;
    ChainRow tip;
};
Windows golden_windows() {
    Windows w;
    w.diff = c2a_difficulty_seed(); w.shortw = c2a_short_term_seed();
    w.longw = c2a_long_term_seed(); w.times = c2a_timestamp_seed();
    std::uint64_t agc = G2::AGC_BEFORE_FIRST;
    WeightState ws; ws.seed(w.shortw, w.longw);
    const G4::GoldenRow* last = nullptr;
    for (std::size_t i = 0; i < G4::ROWS_COUNT; ++i) {
        const G4::GoldenRow& r = G4::ROWS[i];
        if (r.height > G4::MD_HEIGHT - 1) break;
        const std::uint8_t v = r.major_version;
        const std::uint64_t eff = ws.effective_median(v);
        const std::uint64_t pen = penalty_median(eff, ws.short_term_median(), v);
        std::uint64_t base = 0;
        get_block_reward(pen, r.block_weight, agc, v, base);
        agc = accumulate_generated_coins(agc, base);
        ws.push(r.block_weight, r.long_term_weight);
        w.diff.push_back(DifficultyRow{r.timestamp, u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi)});
        w.shortw.push_back(r.block_weight); w.longw.push_back(r.long_term_weight); w.times.push_back(r.timestamp);
        last = &r;
    }
    auto tail_of = [](auto& v, std::size_t keep) {
        if (v.size() > keep) v.erase(v.begin(), v.begin() + static_cast<long>(v.size() - keep));
    };
    tail_of(w.diff, static_cast<std::size_t>(DIFFICULTY_BLOCKS_COUNT));
    tail_of(w.shortw, static_cast<std::size_t>(CRYPTONOTE_REWARD_BLOCKS_WINDOW));
    tail_of(w.longw, static_cast<std::size_t>(G2::LT_WINDOW_SIZE));
    tail_of(w.times, static_cast<std::size_t>(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW));
    ChainRow& t = w.tip;
    t.height = last->height; t.timestamp = last->timestamp;
    t.major_version = last->major_version; t.minor_version = last->minor_version;
    t.block_weight = last->block_weight; t.long_term_weight = last->long_term_weight;
    t.difficulty = u128_of(last->difficulty_lo, last->difficulty_hi);
    t.cumulative_difficulty = u128_of(last->cumulative_difficulty_lo, last->cumulative_difficulty_hi);
    t.pow_verified = true; t.already_generated_coins = agc;
    return w;
}

// Re-seed `view` so the block being mined is `h` (tip = h-1, id synthetic),
// with every epoch seed block at or below the tip resolvable (synthetic ids).
void seed_at(ChainStateView& view, const Windows& w, std::uint64_t h) {
    ChainRow tip = w.tip;
    tip.height = h - 1;
    tip.id = synthetic_id(h - 1);
    std::vector<std::pair<std::uint64_t, Hash>> seeds;
    for (std::uint64_t s = (tip.height & ~std::uint64_t(2047)), n = 0; n < 3 && s >= 2048; s -= 2048, ++n)
        seeds.emplace_back(s, synthetic_id(s));
    view.seed_direct(tip, w.diff, w.shortw, w.longw, w.times, seeds);
    view.set_synced(true);
}

struct NullSink final : strat::IShareSink {
    void on_accepted_share(const strat::AcceptedShare&) override {}
    void submit_network_block(std::uint32_t, std::uint32_t, std::uint32_t) override {}
};
struct Lines final : strat::ITransport {
    std::vector<std::string> lines;
    bool send_line(std::uint64_t, std::string_view l) override { lines.emplace_back(l); return true; }
    void close(std::uint64_t) override {}
};

// Fresh-cache + fresh-VM ground truth for one seed.
struct Reference {
    randomx_cache* cache = nullptr;
    randomx_vm*    vm    = nullptr;
    explicit Reference(const o2::Seed32& seed) {
        ::c2pool::xmr::VerifierOptions o;
        cache = randomx_alloc_cache(::c2pool::xmr::cache_flags(o));
        if (!cache) return;
        randomx_init_cache(cache, seed.data(), seed.size());
        vm = randomx_create_vm(::c2pool::xmr::vm_flags(o), cache, nullptr);
    }
    ~Reference() { if (vm) randomx_destroy_vm(vm); if (cache) randomx_release_cache(cache); }
    o2::Hash32 hash(const std::vector<std::uint8_t>& b) {
        o2::Hash32 h{}; randomx_calculate_hash(vm, b.data(), b.size(), h.data()); return h;
    }
};

struct Rig {
    Windows                          w = golden_windows();
    ChainStateView                   view{XmrNet::Stagenet};
    fakes::FakeTxpool                pool;
    tmpl::NativeMinerDataSource      src{view, pool, {}, &pool};
    LaneFixture                      lane;
    o2::XmrSettlementTemplateProvider provider{src, lane.ledger, lane.scfg, /*share_diff=*/16};
    o2::SettlementStratumTemplateSource ts{provider};

    // Serve the template for height h; false when the provider refused.
    bool job_at(std::uint64_t h, strat::TemplateJob& tj) {
        seed_at(view, w, h);
        if (!provider.refresh() || provider.current().height != h) return false;
        return ts.get_job(0, tj);
    }
};

std::string hex(const o2::Seed32& s) { return strat::StratumDialect::to_hex(s.data(), s.size()); }

// E = the epoch boundary after the golden's seed block; switch at E+65.
constexpr std::uint64_t E = G4::SEED_HEIGHT + 2048;

void suite_announce(Rig& r) {
    std::printf("== (A) next_seed_hash in the served job around the switch at %llu (E=%llu) ==\n",
                static_cast<unsigned long long>(E + 65), static_cast<unsigned long long>(E));
    int built = 0, present = 0, right = 0, wrong_place = 0, json_ok = 0, json_n = 0;
    std::vector<std::uint64_t> hs;
    for (std::uint64_t h = E - 3; h <= E + 68; ++h) hs.push_back(h);
    hs.push_back(E - 1000); hs.push_back(E + 1000);
    o2::O2RandomXVerifier vjson;   // not initialised: login never hashes
    NullSink sink;
    for (std::uint64_t h : hs) {
        strat::TemplateJob tj;
        if (!r.job_at(h, tj)) { std::printf("  refresh at %llu: %s\n", (unsigned long long)h, r.provider.last_error().c_str()); continue; }
        ++built;
        const std::uint64_t sh = ref_seedheight(h), nh = ref_seedheight(h + 64);
        const bool want = nh != sh;
        if (tj.next_seed_hash) ++present;
        if (want != tj.next_seed_hash.has_value()) ++wrong_place;
        if (want && tj.next_seed_hash && *tj.next_seed_hash == synthetic_id(nh)
            && tj.seed_hash == synthetic_id(sh)) ++right;
        if (h == E || h == E + 1 || h == E + 64 || h == E + 65) {   // the stratum job JSON
            Lines tr;
            strat::XmrStratumServer srv(r.ts, vjson, sink, tr);
            strat::XmrStratumSession s(1);
            srv.handle_login(s, 1, "4xxx.rig");
            const std::string& l = tr.lines.empty() ? std::string() : tr.lines.back();
            const bool has = l.find("\"next_seed_hash\":\"" + hex(synthetic_id(nh)) + "\"") != std::string::npos;
            const bool any = l.find("next_seed_hash") != std::string::npos;
            ++json_n;
            if (want ? has : !any) ++json_ok;
            std::printf("  h=%llu job JSON next_seed_hash %s\n", (unsigned long long)h, any ? "present" : "absent");
        }
    }
    std::printf("  templates=%d present=%d right_id=%d misplaced=%d\n", built, present, right, wrong_place);
    check(built == static_cast<int>(hs.size()), "every height served a template (" + std::to_string(built) + ")");
    check(present == 64, "next_seed_hash present at exactly 64 heights (E+1..E+64), got " + std::to_string(present));
    check(right == 64, "each equals the block id at the next seed height E (and seed_hash the current seed)");
    check(wrong_place == 0, "absent everywhere else (E-3..E, E+65..E+68, mid-epoch)");
    check(json_n == 4 && json_ok == 4, "stratum job JSON carries next_seed_hash exactly in the lag window (4/4)");
}

void suite_switch(Rig& r) {
    std::printf("== (B) O2RandomXVerifier across the ANNOUNCED switch (jobs from the provider) ==\n");
    using clk = std::chrono::steady_clock;
    const o2::Seed32 A = synthetic_id(E - 2048), B = synthetic_id(E);
    o2::O2RandomXVerifier v; o2::RandomXPolicy p; p.enabled = true;
    const bool init_ok = v.init(p);
    check(init_ok, "verifier init (" + std::string(o2::O2RandomXVerifier::to_string(v.mode())) + ")");
    double max_lag_ms = 0;
    strat::TemplateJob tj, pre_switch;
    bool announced = false;
    for (std::uint64_t h = E + 1; h <= E + 64; ++h) {           // the lag window, as the hook sees it
        if (!r.job_at(h, tj)) { check(false, "template at " + std::to_string(h)); return; }
        const auto t0 = clk::now();
        v.on_template(tj);
        const double ms = std::chrono::duration<double, std::milli>(clk::now() - t0).count();
        if (h > E + 1 && ms > max_lag_ms) max_lag_ms = ms;
        announced = announced || tj.next_seed_hash.has_value();
    }
    pre_switch = tj;
    // Give an announced helper build time to finish, feeding the same template
    // the way the listener would on its next wake (no-op when nothing announced).
    for (int i = 0; announced && i < 1200 && !v.seed_resident(B); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        v.on_template(tj);
    }
    std::printf("  lag window: announced=%d, max hook %.1f ms (E+2..E+64), B resident before switch=%d | %s\n",
                announced ? 1 : 0, max_lag_ms, v.seed_resident(B) ? 1 : 0, v.describe().c_str());
    const std::uint64_t pf0 = v.stats().prefetches;
    if (!r.job_at(E + 65, tj)) { check(false, "template at the switch"); return; }
    const auto t0 = clk::now();
    v.on_template(tj);                                             // THE SWITCH JOB
    const double sw_ms = std::chrono::duration<double, std::milli>(clk::now() - t0).count();
    const std::uint64_t pf1 = v.stats().prefetches;
    std::printf("  switch job (h=%llu, seed B): hook %.1f ms, prefetches %llu -> %llu | %s\n",
                (unsigned long long)(E + 65), sw_ms, (unsigned long long)pf0, (unsigned long long)pf1,
                v.describe().c_str());
    check(tj.seed_hash == B && !tj.next_seed_hash, "switch job: seed_hash = B, no next_seed_hash");
    check(pf1 == pf0, "announced switch: NO cache initialisation at the switch job");
    check(v.seed_resident(A) && v.seed_resident(B), "previous epoch A still resident for in-flight jobs, B resident");
    // Hashes vs fresh references: post-switch job on B, pre-switch job on A.
    int eqB = 0, eqA = 0;
    {
        Reference ref(B);
        for (std::uint32_t n = 0; n < 4; ++n) {
            std::vector<std::uint8_t> b = tj.blob;
            std::memcpy(b.data() + tj.nonce_offset, &n, 4);
            o2::Hash32 h{};
            if (v.randomx_hash(b.data(), b.size(), tj.height, B, h) && h == ref.hash(b)) ++eqB;
        }
    }
    {
        Reference ref(A);
        for (std::uint32_t n = 0; n < 4; ++n) {
            std::vector<std::uint8_t> b = pre_switch.blob;
            std::memcpy(b.data() + pre_switch.nonce_offset, &n, 4);
            o2::Hash32 h{};
            if (v.randomx_hash(b.data(), b.size(), pre_switch.height, A, h) && h == ref.hash(b)) ++eqA;
        }
    }
    check(eqB == 4, "post-switch job (seed B): 4/4 hashes == fresh reference B");
    check(eqA == 4, "pre-switch job (seed A) after the switch: 4/4 hashes == fresh reference A");
}

// ---------------------------------------------------------------------------
// (C) the DAEMON arm (--xmr-template-source monerod): get_miner_data has no
// next_seed_hash, so the id of the next seed block comes from
// get_block_header_by_height, asked only inside the lag window, once per tip.
// A fake monerod: get_miner_data = the C4 golden capture with its height and
// prev_id moved; get_block_header_by_height(n) answers id synthetic_id(n).
// ---------------------------------------------------------------------------
namespace node = ::c2pool::xmr::node;
class FakeMonerod final : public node::IMonerodTransport {
public:
    std::uint64_t height = G4::MD_HEIGHT;
    int header_calls = 0;
    void rpc_post(const std::string& body, std::function<void(const node::RpcResponse&)> cb) override {
        std::string out;
        const auto hp = body.find("get_block_header_by_height");
        if (hp != std::string::npos) {
            ++header_calls;
            const auto p = body.find("\"height\":");
            const std::uint64_t n = std::strtoull(body.c_str() + p + 9, nullptr, 10);
            out = "{\"id\":\"0\",\"jsonrpc\":\"2.0\",\"result\":{\"block_header\":{\"height\":" + std::to_string(n) +
                  ",\"timestamp\":1,\"reward\":1,\"difficulty\":1000,\"hash\":\"" + hex(synthetic_id(n)) +
                  "\",\"prev_hash\":\"" + hex(synthetic_id(n - 1)) + "\"},\"status\":\"OK\"}}";
        } else {
            out = G4::MD_RAW_JSON;
            const std::string h0 = "\"height\":" + std::to_string(G4::MD_HEIGHT);
            out.replace(out.find(h0), h0.size(), "\"height\":" + std::to_string(height));
            const auto pp = out.find("\"prev_id\":\"") + 11;
            out.replace(pp, 64, hex(synthetic_id(height - 1)));
        }
        node::RpcResponse r;
        r.body.assign(out.begin(), out.end());
        cb(r);
    }
    void zmq_subscribe(const std::string&, std::function<void(const node::ZmqFrame&)>) override {}
};

void suite_daemon_arm() {
    std::printf("== (C) DAEMON arm: next_seed_hash from get_block_header_by_height ==\n");
    FakeMonerod m;
    LaneFixture lane;
    o2::XmrSettlementTemplateProvider provider(m, lane.ledger, lane.scfg, 16);
    o2::SettlementStratumTemplateSource ts(provider);
    struct Want { std::uint64_t h; bool present; };
    const Want ws[] = {{E + 5, true}, {E + 6, true}, {E + 65, false}, {E + 1000, false}};
    int ok = 0;
    for (const Want& w : ws) {
        m.height = w.h;
        strat::TemplateJob tj;
        const bool built = provider.refresh() && ts.get_job(0, tj) && tj.height == w.h;
        const bool good = built && (w.present ? (tj.next_seed_hash && *tj.next_seed_hash == synthetic_id(E))
                                              : !tj.next_seed_hash);
        std::printf("  h=%llu built=%d next_seed_hash %s\n", (unsigned long long)w.h, built ? 1 : 0,
                    tj.next_seed_hash ? hex(*tj.next_seed_hash).substr(0, 16).c_str() : "absent");
        if (good) ++ok;
    }
    check(ok == 4, "daemon arm: present (= id at E) at E+5, E+6; absent at E+65 and mid-epoch (" + std::to_string(ok) + "/4)");
    check(m.header_calls == 2, "daemon arm: one get_block_header_by_height per tip inside the window, none outside (" +
                               std::to_string(m.header_calls) + ")");
}

} // namespace

int main() {
    std::printf("== v37_xmr_next_seed_kat ==\n");
    Rig r;
    suite_announce(r);
    suite_switch(r);
    suite_daemon_arm();
    std::printf("== %s (%d failures) ==\n", g_fail ? "FAIL" : "OK", g_fail);
    return g_fail ? 1 : 0;
}
