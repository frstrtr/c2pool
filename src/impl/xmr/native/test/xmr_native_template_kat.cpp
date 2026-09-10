// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_template_kat.cpp   --  C4 KATs
//
// The C4 seam: two IMinerDataSource implementations, the readiness gate, the
// epoch/rebuild rule, the body pins and the arm resolver -- plus the one thing
// this component exists to prove:
//
//   A TEMPLATE BUILT FROM THE NATIVE CHAIN INDEX AND THE NATIVE TXPOOL CARRIES
//   THE SAME SEVEN get_miner_data FIELDS THE DAEMON REPORTS AT THAT HEIGHT.
//
// PARITY, and why it is honest. Suite A replays a REAL get_miner_data captured
// from a synced stagenet monerod (0.18.5.1, height 2 204 960) and compares it,
// field by field, against a NativeMinerDataSource driven by a chain state that
// was rolled forward -- from the C2a golden's captured windows -- using
// monerod's own per-height rows. Not one of the seven compared values was
// computed by this repository:
//
//   height                   the daemon's, from the captured response
//   prev_id                  the daemon's block id for the tip
//   seed_hash                the daemon's, cross-checked by the golden
//                            generator against the id it reported for the block
//                            at rx_seedheight(H)
//   difficulty               the daemon's next difficulty, hex string and all
//   median_weight            the daemon's effective median
//   already_generated_coins  the daemon's emission total
//   major_version            the daemon's hard-fork version
//
// so a formula error on our side cannot pass by agreeing with itself. The
// eighth field, median_timestamp, is NOT exposed by get_miner_data (p2pool
// derives it too); it is checked as a CONSTRAINT -- the 60-block median of
// monerod's own captured timestamps -- which is exactly what monerod enforces.
//
// Suite B is the other half of the parity claim and the reason the seam is
// safe to land: the SAME captured response, replayed through the production
// MoneroDaemonRpc::parse_miner_data over a fake transport, gives a MinerData
// that is field-identical to the native arm's. The monerod arm IS the old path.
//
// The remaining suites are the C4 plan's K-C4-3..5 plus the pieces the plan
// leaves to the implementer: body pins, backlog policy plumbing, and the arm
// resolver's fallback matrix.
//
// Suites H, I and J are REGRESSION pins, one per defect the C4 review found.
// Each fails on the code as it stood before the fix, and each carries its own
// non-vacuity check so it cannot pass for an empty reason:
//
//   H  R-C4-1  tx_body(id) is the body OF THAT ID. A body source COMPACTS its
//              reply, so an id that went missing between selectable_backlog()
//              and get_blobs() used to shift every later body onto the wrong
//              id -- an invalid block, built and relayed. The suite punches a
//              hole ahead of other bodies and asserts identity per id, plus
//              the fail-closed path for a source that breaks the contract.
//   I  R-C4-2  a re-snapshot under an UNCHANGED tip keeps its pin. The pin key
//              is the tip id, so pinning and then de-duplicating under the same
//              key used to leave the live template with no pin at all.
//   J  R-C4-3  the DEFAULT/PRODUCTION (monerod) arm rebuilds when the parent
//              tip moves and at no other time -- the pre-seam rule, character
//              for character. Driven over the production parse_miner_data and
//              checked against BOTH the pre-seam oracle and the size-derived
//              rule that regressed it.
//
// OPT-IN LIVE PARITY: `--parity-json <file>` replaces the embedded capture with
// a fresh one (same schema; tools/xmr-c4-parity/capture_miner_data.py produces
// it against a read-only daemon). ctest never passes it: CI must not depend on
// a network, and a golden that only ever ran against a live daemon is a golden
// nobody can reproduce.
//
// SCOPE FENCE: src/impl/xmr/ only; no consensus digest; src/sharechain/v37 is
// not touched.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_view.hpp"
#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/consensus/xmr_weight.hpp"
#include "impl/xmr/native/contracts/fakes/fakes.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/native/template/xmr_native_miner_data.hpp"
#include "impl/xmr/native/template/xmr_template_arm.hpp"

#include "xmr_c2a_golden.hpp"
#include "xmr_c4_parity_golden.hpp"

using namespace c2pool::xmr::native;
namespace G2 = c2pool::xmr::native::golden_c2a;
namespace G4 = c2pool::xmr::native::golden_c4;

namespace {

int g_fail = 0;
int g_checks = 0;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
    } while (0)

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------
Hash hash_from_hex(const char* h) {
    Hash out{};
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (std::size_t i = 0; i < 32 && h[2 * i] && h[2 * i + 1]; ++i)
        out[i] = static_cast<std::uint8_t>((nib(h[2 * i]) << 4) | nib(h[2 * i + 1]));
    return out;
}

std::string hex_of(const Hash& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::uint8_t b : h) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}

Hash synthetic_id(std::uint64_t height) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>(height >> (8 * i));
    h[31] = 0xC4;
    return h;
}

U128 u128_of(std::uint64_t lo, std::uint64_t hi) { U128 d; d.lo = lo; d.hi = hi; return d; }

// ---------------------------------------------------------------------------
// The parity fixture: what the native arm is judged against.
//
// Either the embedded capture, or a fresh one supplied with --parity-json. The
// JSON reader is deliberately tiny and only understands the fields it needs.
// ---------------------------------------------------------------------------
struct ParityExpectation {
    std::uint64_t height = G4::MD_HEIGHT;
    Hash          prev_id{};
    Hash          seed_hash{};
    std::uint64_t difficulty_lo = G4::MD_DIFFICULTY_LO;
    std::uint64_t difficulty_hi = G4::MD_DIFFICULTY_HI;
    std::uint64_t median_weight = G4::MD_MEDIAN_WEIGHT;
    std::uint64_t already_generated_coins = G4::MD_ALREADY_GENERATED_COINS;
    std::uint8_t  major_version = G4::MD_MAJOR_VERSION;
    std::string   raw_json = G4::MD_RAW_JSON;
    std::string   provenance =
        std::string("embedded capture: monerod ") + G4::MONEROD_VERSION + " " + G4::NETWORK;
};

// ---------------------------------------------------------------------------
// Rebuild the native chain state at G4::MD_HEIGHT - 1.
//
// Seeds are the C2a golden's captured windows (its long-term window is the only
// 100 000-entry object in this repository and re-capturing it would be pure
// cost), then rolled forward with the C4 golden's rows, which are the rows
// between the two captures. Every number pushed here is monerod's.
// ---------------------------------------------------------------------------
struct BuiltState {
    ChainStateView view{XmrNet::Stagenet};
    std::uint64_t  agc = 0;
    std::uint64_t  median_timestamp_expected = 0;
};

std::vector<std::uint64_t> c2a_long_term_seed() {
    std::vector<std::uint64_t> v;
    v.reserve(G2::LT_WINDOW_SIZE);
    for (std::size_t i = 0; i < G2::LT_SEED_HEAD_COUNT; ++i) v.push_back(G2::LT_SEED_HEAD[i]);
    for (std::size_t i = 0; i < G2::LT_SEED_TAIL_RUNS_COUNT; ++i)
        for (std::uint64_t k = 0; k < G2::LT_SEED_TAIL_RUNS[i].count; ++k)
            v.push_back(G2::LT_SEED_TAIL_RUNS[i].value);
    return v;
}

const G2::GoldenHeader& c2a_header_at(std::uint64_t h) {
    return G2::HEADERS[h - G2::HEADERS_FIRST_HEIGHT];
}

// The C2a seeds, which are the windows as they stood just below TEST_FIRST.
std::vector<DifficultyRow> c2a_difficulty_seed() {
    std::vector<DifficultyRow> v;
    for (std::uint64_t h = G2::TEST_FIRST - DIFFICULTY_BLOCKS_COUNT; h < G2::TEST_FIRST; ++h) {
        const auto& r = c2a_header_at(h);
        v.push_back(DifficultyRow{r.timestamp,
                                  u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi)});
    }
    return v;
}
std::vector<std::uint64_t> c2a_short_term_seed() {
    std::vector<std::uint64_t> v;
    for (std::uint64_t h = G2::TEST_FIRST - CRYPTONOTE_REWARD_BLOCKS_WINDOW; h < G2::TEST_FIRST; ++h)
        v.push_back(c2a_header_at(h).block_weight);
    return v;
}
std::vector<std::uint64_t> c2a_timestamp_seed() {
    std::vector<std::uint64_t> v;
    for (std::uint64_t h = G2::TEST_FIRST - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; h < G2::TEST_FIRST; ++h)
        v.push_back(c2a_header_at(h).timestamp);
    return v;
}

// Roll the state from the C2a seed position to `stop_height` inclusive, using
// the C4 golden's rows. Returns the view seeded at that tip.
void build_state(BuiltState& out, std::uint64_t stop_height, bool with_seed_id = true) {
    std::vector<DifficultyRow> diff  = c2a_difficulty_seed();
    std::vector<std::uint64_t> shortw = c2a_short_term_seed();
    std::vector<std::uint64_t> longw  = c2a_long_term_seed();
    std::vector<std::uint64_t> times  = c2a_timestamp_seed();
    std::uint64_t agc = G2::AGC_BEFORE_FIRST;

    WeightState ws;
    ws.seed(shortw, longw);

    const G4::GoldenRow* last = nullptr;
    for (std::size_t i = 0; i < G4::ROWS_COUNT; ++i) {
        const G4::GoldenRow& r = G4::ROWS[i];
        if (r.height > stop_height) break;
        const std::uint8_t  v   = r.major_version;
        const std::uint64_t eff = ws.effective_median(v);
        const std::uint64_t pen = penalty_median(eff, ws.short_term_median(), v);
        std::uint64_t base = 0;
        get_block_reward(pen, r.block_weight, agc, v, base);
        agc = accumulate_generated_coins(agc, base);
        ws.push(r.block_weight, r.long_term_weight);

        diff.push_back(DifficultyRow{r.timestamp,
                                     u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi)});
        shortw.push_back(r.block_weight);
        longw.push_back(r.long_term_weight);
        times.push_back(r.timestamp);
        last = &r;
    }

    auto tail_of = [](auto& v, std::size_t keep) {
        if (v.size() > keep) v.erase(v.begin(), v.begin() + static_cast<long>(v.size() - keep));
    };
    tail_of(diff,   static_cast<std::size_t>(DIFFICULTY_BLOCKS_COUNT));
    tail_of(shortw, static_cast<std::size_t>(CRYPTONOTE_REWARD_BLOCKS_WINDOW));
    tail_of(longw,  static_cast<std::size_t>(G2::LT_WINDOW_SIZE));
    tail_of(times,  static_cast<std::size_t>(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW));

    {
        // monerod's median (epee::misc_utils::median), restated here rather
        // than borrowed, so the comparison is against the RULE and not against
        // the same code the state uses: sort, and for an even count take
        // epee's get_mid = floor((a+b)/2) of the two middle values, formed
        // without ever summing a and b.
        std::vector<std::uint64_t> t = times;
        std::sort(t.begin(), t.end());
        if (t.empty()) {
            out.median_timestamp_expected = 0;
        } else if (t.size() % 2) {
            out.median_timestamp_expected = t[t.size() / 2];
        } else {
            const std::uint64_t a = t[t.size() / 2 - 1];
            const std::uint64_t b = t[t.size() / 2];
            out.median_timestamp_expected =
                (a / 2) + (b / 2) + ((a - 2 * (a / 2)) + (b - 2 * (b / 2))) / 2;
        }
    }

    ChainRow tip;
    tip.height                = last->height;
    tip.timestamp             = last->timestamp;
    tip.major_version         = last->major_version;
    tip.minor_version         = last->minor_version;
    tip.block_weight          = last->block_weight;
    tip.long_term_weight      = last->long_term_weight;
    tip.difficulty            = u128_of(last->difficulty_lo, last->difficulty_hi);
    tip.cumulative_difficulty = u128_of(last->cumulative_difficulty_lo, last->cumulative_difficulty_hi);
    tip.pow_verified          = true;
    tip.already_generated_coins = agc;
    tip.id = (last->height == G4::ROWS_LAST_HEIGHT) ? hash_from_hex(G4::TIP_ID)
                                                    : synthetic_id(last->height);

    std::vector<std::pair<std::uint64_t, Hash>> seed_ids;
    if (with_seed_id) seed_ids.emplace_back(G4::SEED_HEIGHT, hash_from_hex(G4::SEED_ID));

    out.view.seed_direct(tip, diff, shortw, longw, times, seed_ids);
    out.view.set_synced(true);
    out.agc = agc;
}

// ---------------------------------------------------------------------------
// A fake IMonerodTransport that answers one canned JSON body.
// ---------------------------------------------------------------------------
class CannedTransport final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    explicit CannedTransport(std::string body) : body_(std::move(body)) {}

    void set_body(std::string b) { body_ = std::move(b); }
    void set_error(std::string e) { error_ = std::move(e); }
    std::uint64_t calls() const { return calls_; }

    void rpc_post(const std::string& /*json_body*/,
                  std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ++calls_;
        ::c2pool::xmr::node::RpcResponse r;
        if (!error_.empty()) { r.error = error_; cb(r); return; }
        r.body.assign(body_.begin(), body_.end());
        cb(r);
    }
    void zmq_subscribe(const std::string&,
                       std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}

private:
    std::string   body_;
    std::string   error_;
    std::uint64_t calls_ = 0;
};

// ---------------------------------------------------------------------------
// Suite A -- K-C4-2 + the P-TPL determinism table, native arm.
// ---------------------------------------------------------------------------
void suite_native_parity(const ParityExpectation& exp) {
    std::printf("== A. native arm vs monerod get_miner_data (P-TPL EQUALITY) ==\n");
    std::printf("   provenance: %s\n", exp.provenance.c_str());

    BuiltState st;
    build_state(st, exp.height - 1);

    fakes::FakeTxpool pool;   // empty pool: the capture's backlog was empty too
    tmpl::NativeMinerDataSource src(st.view, pool);

    CHECK(std::string(src.name()) == "native", "arm name is \"native\"");

    const MinerDataReadiness rdy = src.readiness();
    CHECK(rdy.ok(), "readiness ok (%s)", rdy.why.empty() ? "all inputs present" : rdy.why.c_str());

    std::string why;
    const auto md = src.snapshot(&why);
    CHECK(md.has_value(), "snapshot built with no daemon call (%s)", why.c_str());
    if (!md) return;

    // --- ALIGNMENT KEY -------------------------------------------------------
    CHECK(md->height == exp.height, "height %llu == monerod %llu",
          (unsigned long long)md->height, (unsigned long long)exp.height);
    CHECK(md->prev_id == exp.prev_id, "prev_id %s == monerod", hex_of(md->prev_id).c_str());

    // --- EQUALITY ------------------------------------------------------------
    CHECK(md->major_version == exp.major_version, "major_version %u == monerod %u",
          (unsigned)md->major_version, (unsigned)exp.major_version);
    CHECK(md->seed_hash == exp.seed_hash, "seed_hash %s == monerod", hex_of(md->seed_hash).c_str());
    CHECK(md->difficulty.lo == exp.difficulty_lo && md->difficulty.hi == exp.difficulty_hi,
          "difficulty {lo=%llu, hi=%llu} == monerod {lo=%llu, hi=%llu}",
          (unsigned long long)md->difficulty.lo, (unsigned long long)md->difficulty.hi,
          (unsigned long long)exp.difficulty_lo, (unsigned long long)exp.difficulty_hi);
    CHECK(md->median_weight == exp.median_weight, "median_weight %llu == monerod %llu",
          (unsigned long long)md->median_weight, (unsigned long long)exp.median_weight);
    CHECK(md->already_generated_coins == exp.already_generated_coins,
          "already_generated_coins %llu == monerod %llu",
          (unsigned long long)md->already_generated_coins,
          (unsigned long long)exp.already_generated_coins);

    // --- DERIVED (monerod does not expose it; the rule is the check) ---------
    CHECK(md->median_timestamp == st.median_timestamp_expected,
          "median_timestamp %llu == median of monerod's own last-60 timestamps %llu",
          (unsigned long long)md->median_timestamp,
          (unsigned long long)st.median_timestamp_expected);

    // --- INVARIANT: valid() is what the provider gates on --------------------
    CHECK(md->valid(), "MinerData::valid(): height, prev_id and difficulty all set");

    // --- NEGATIVE CONTROL: a wrong window must not still pass ---------------
    // Drop one row from the difficulty window and the derived difficulty must
    // move. If it did not, the parity above would be proving nothing.
    {
        BuiltState shifted;
        build_state(shifted, exp.height - 2);
        fakes::FakeTxpool p2;
        tmpl::NativeMinerDataSource s2(shifted.view, p2);
        std::string w2;
        const auto md2 = s2.snapshot(&w2);
        CHECK(md2.has_value() && md2->height == exp.height - 1,
              "control: state one block back yields height %llu",
              (unsigned long long)(md2 ? md2->height : 0));
        CHECK(md2.has_value() && !(md2->difficulty.lo == exp.difficulty_lo &&
                                   md2->difficulty.hi == exp.difficulty_hi),
              "control: a different window gives a different difficulty");
    }
}

// ---------------------------------------------------------------------------
// Suite B -- K-C4-1: the monerod arm IS the old path.
// ---------------------------------------------------------------------------
void suite_monerod_arm(const ParityExpectation& exp) {
    std::printf("== B. monerod arm == today's get_miner_data path (K-C4-1) ==\n");

    CannedTransport tx(exp.raw_json);
    tmpl::MonerodMinerDataSource src(tx);

    CHECK(std::string(src.name()) == "monerod", "arm name is \"monerod\"");
    CHECK(!src.readiness().ok(), "fail-closed before the first poll");
    CHECK(!src.snapshot(nullptr).has_value(), "no snapshot before the first poll");

    std::string why;
    CHECK(src.poll(&why), "poll() over the captured response (%s)", why.c_str());
    CHECK(tx.calls() == 1, "exactly one RPC per poll");
    CHECK(src.readiness().ok(), "readiness ok after a good poll");

    const auto md = src.snapshot(&why);
    CHECK(md.has_value(), "snapshot after poll");
    if (!md) return;

    // The production parser decoded the hex-string difficulty the daemon really
    // sends; this is the PR #1529 shape, and it is why the raw body is replayed
    // rather than a re-typed struct.
    CHECK(md->difficulty.lo == exp.difficulty_lo && md->difficulty.hi == exp.difficulty_hi,
          "hex-string difficulty decoded by the production parser: lo=%llu hi=%llu",
          (unsigned long long)md->difficulty.lo, (unsigned long long)md->difficulty.hi);

    // The parity claim, stated as one comparison: both arms, same fields.
    BuiltState st;
    build_state(st, exp.height - 1);
    fakes::FakeTxpool pool;
    tmpl::NativeMinerDataSource nat(st.view, pool);
    const auto nmd = nat.snapshot(&why);
    CHECK(nmd.has_value(), "native arm snapshot for the comparison");
    if (!nmd) return;

    const bool same = nmd->major_version == md->major_version
                   && nmd->height == md->height
                   && nmd->prev_id == md->prev_id
                   && nmd->seed_hash == md->seed_hash
                   && nmd->difficulty.lo == md->difficulty.lo
                   && nmd->difficulty.hi == md->difficulty.hi
                   && nmd->median_weight == md->median_weight
                   && nmd->already_generated_coins == md->already_generated_coins;
    CHECK(same, "native arm and monerod arm agree on all seven miner-data fields");

    // The daemon arm holds no bodies, by design: with a daemon armed it is ARM B
    // that relays a found block, out of the daemon's own pool.
    Hash any{};
    CHECK(src.tx_body(any) == nullptr, "daemon arm exposes no tx bodies (ARM B relays)");

    // A transport failure must not destroy the last good snapshot: the provider
    // decides whether to keep serving, and it can only decide that if the cache
    // survives a blip.
    tx.set_error("connection refused");
    CHECK(!src.poll(&why), "poll fails when the transport does");
    CHECK(src.snapshot(nullptr).has_value(), "last good snapshot survives a transport error");
    CHECK(src.failures() == 1, "the failure is counted");
}

// ---------------------------------------------------------------------------
// Suite C -- K-C4-3: the readiness matrix, fail-closed.
// ---------------------------------------------------------------------------
void suite_readiness() {
    std::printf("== C. readiness matrix, fail-closed (K-C4-3) ==\n");

    fakes::FakeTxpool pool;

    // (1) An index with no tip at all.
    {
        ChainStateView empty{XmrNet::Stagenet};
        tmpl::NativeMinerDataSource src(empty, pool);
        const auto r = src.readiness();
        CHECK(!r.ok() && !r.tip_known, "no tip => not ready (%s)", r.why.c_str());
        std::string why;
        CHECK(!src.snapshot(&why).has_value(), "no tip => no template (%s)", why.c_str());
        CHECK(src.last_refusal() == tmpl::NativeRefusal::NoTip, "refusal is NoTip");
    }

    // (2) A populated index that has NOT declared itself synced. This is the
    //     single most important refusal in the component: a half-built index
    //     has plausible-looking windows.
    {
        BuiltState st;
        build_state(st, G4::ROWS_LAST_HEIGHT);
        st.view.set_synced(false);
        tmpl::NativeMinerDataSource src(st.view, pool);
        const auto r = src.readiness();
        CHECK(!r.ok(), "not synced => not ready (%s)", r.why.c_str());
        CHECK(r.tip_known, "...but the tip is still known, and the reason says which input is missing");
        std::string why;
        CHECK(!src.snapshot(&why).has_value(), "not synced => no template");
        CHECK(src.last_refusal() == tmpl::NativeRefusal::NoTemplateInputs, "refusal is NoTemplateInputs");
    }

    // (3) Seed unreachable: the state is built WITHOUT the seed block id, so
    //     seed_hash_for_height() cannot answer. A template served with a wrong
    //     or missing seed makes every share SeedNotResident at the verifier.
    {
        BuiltState st;
        build_state(st, G4::ROWS_LAST_HEIGHT, /*with_seed_id=*/false);
        tmpl::NativeMinerDataSource src(st.view, pool);
        const auto r = src.readiness();
        CHECK(!r.ok(), "no seed id => not ready (%s)", r.why.c_str());
        std::string why;
        CHECK(!src.snapshot(&why).has_value(), "no seed id => no template");
        // The chain view refuses template_inputs() outright when it cannot
        // resolve the seed, so the refusal surfaces as the inputs being absent.
        CHECK(src.last_refusal() == tmpl::NativeRefusal::NoTemplateInputs ||
              src.last_refusal() == tmpl::NativeRefusal::NoSeed,
              "refusal names the seed or the inputs (%s)", to_string(src.last_refusal()));
    }

    // (4) The healthy case, for contrast: every flag true.
    {
        BuiltState st;
        build_state(st, G4::ROWS_LAST_HEIGHT);
        tmpl::NativeMinerDataSource src(st.view, pool);
        const auto r = src.readiness();
        CHECK(r.tip_known && r.seed_reach && r.difficulty_window && r.weight_window
              && r.coins_known && r.hf_known && r.ok(),
              "healthy state: all six readiness flags true");
        CHECK(src.refusals() == 0, "no refusals counted on the healthy path");
    }

    // (5) Thin peers and a stale tip are FLAGS, not refusals. A pool that
    //     stopped serving templates because it lost a peer would stop paying
    //     its miners for no consensus reason.
    {
        BuiltState st;
        build_state(st, G4::ROWS_LAST_HEIGHT);
        tmpl::NativeTemplatePolicy pol;
        pol.min_peers   = 2;
        pol.stale_tip_s = 60;
        tmpl::NativeMinerDataSource src(st.view, pool, pol);
        src.set_peer_count(1);
        src.set_now(G4::ROWS[G4::ROWS_COUNT - 1].timestamp + 3600);
        CHECK(src.thin_peers(), "peer floor raises thin_peers()");
        CHECK(src.stale_tip(), "an hour without a tip raises stale_tip()");
        std::string why;
        CHECK(src.snapshot(&why).has_value(), "...and the template is STILL served");
    }
}

// ---------------------------------------------------------------------------
// Suite D -- K-C4-4: the difficulty sanity band.
// ---------------------------------------------------------------------------
void suite_difficulty_band() {
    std::printf("== D. difficulty sanity band [tip/4, tip*4] (K-C4-4) ==\n");

    fakes::FakeChain chain;
    chain.state.synced = true;

    node::ChainMainBlock tip;
    tip.height     = 1000;
    tip.id         = synthetic_id(1000);
    tip.timestamp  = 1700000000;
    tip.difficulty = u128_of(1000000, 0);
    chain.rows.push_back(tip);

    auto make_inputs = [&](std::uint64_t next_diff) {
        TemplateInputs t;
        t.major_version = 16;
        t.minor_version = 16;
        t.height        = 1001;
        t.prev_id       = tip.id;
        t.seed_hash     = synthetic_id(1);
        t.difficulty    = u128_of(next_diff, 0);
        t.median_weight = 300000;
        t.block_weight_limit = 600000;
        t.already_generated_coins = 18000000000000000000ull;
        t.median_timestamp = 1699999000;
        t.synced = true;
        return t;
    };

    fakes::FakeTxpool pool;

    struct Case { std::uint64_t d; bool ok; const char* note; };
    const Case cases[] = {
        { 1000000,  true,  "unchanged" },
        {  250000,  true,  "exactly tip/4 (the band is closed)" },
        { 4000000,  true,  "exactly tip*4 (the band is closed)" },
        {  249999,  false, "just below tip/4" },
        { 4000001,  false, "just above tip*4" },
        {       1,  false, "a collapsed window" },
    };
    for (const Case& c : cases) {
        chain.inputs = make_inputs(c.d);
        tmpl::NativeMinerDataSource src(chain, pool);
        std::string why;
        const bool served = src.snapshot(&why).has_value();
        CHECK(served == c.ok, "difficulty %llu (%s): %s",
              (unsigned long long)c.d, c.note, served ? "served" : "refused");
        if (!c.ok)
            CHECK(src.last_refusal() == tmpl::NativeRefusal::DifficultyBand,
                  "  ...refused by the band, not by something else (%s)",
                  to_string(src.last_refusal()));
    }

    // With the band disabled the same value is served, which proves the band is
    // what refused above and not an unrelated check.
    {
        chain.inputs = make_inputs(1);
        tmpl::NativeTemplatePolicy pol;
        pol.band_div = 0;
        pol.band_mul = 0;
        tmpl::NativeMinerDataSource src(chain, pool, pol);
        std::string why;
        CHECK(src.snapshot(&why).has_value(), "band disabled => the same difficulty is served");
    }
}

// ---------------------------------------------------------------------------
// Suite E -- K-C4-5: the epoch/rebuild rule.
// ---------------------------------------------------------------------------
void suite_epoch() {
    std::printf("== E. epoch and rebuild policy (K-C4-5) ==\n");

    fakes::FakeChain chain;
    chain.state.synced = true;
    node::ChainMainBlock tip;
    tip.height     = 2000;
    tip.id         = synthetic_id(2000);
    tip.timestamp  = 1700000000;
    tip.difficulty = u128_of(1000000, 0);
    chain.rows.push_back(tip);

    TemplateInputs t;
    t.major_version = 16; t.minor_version = 16;
    t.height = 2001; t.prev_id = tip.id;
    t.seed_hash = synthetic_id(7);
    t.difficulty = u128_of(1000000, 0);
    t.median_weight = 300000; t.block_weight_limit = 600000;
    t.already_generated_coins = 18000000000000000000ull;
    t.median_timestamp = 1699999000; t.synced = true;
    chain.inputs = t;

    fakes::FakeTxpool pool;
    pool.configured.min_peers = 0;

    // --- tip-only (the default) ---------------------------------------------
    {
        tmpl::NativeMinerDataSource src(chain, pool);
        std::string why;
        (void)src.snapshot(&why);
        const MinerDataEpoch e0 = src.epoch();
        CHECK(e0.height == 2001 && e0.prev_id == tip.id, "epoch tracks (tip+1, tip id)");

        // A transaction arrives (and bumps the pool's own backlog_version).
        // Under the tip-only policy the epoch must NOT move: the miners are
        // grinding bytes that the assembler would restamp.
        pool.add(synthetic_id(11), 1500, 30000);
        CHECK(pool.backlog_version() != 0, "the pool's own backlog_version moved");
        const MinerDataEpoch e1 = src.epoch();
        CHECK(e1 == e0, "tip-only: a backlog change does NOT move the epoch");

        // The tip moves: now it must.
        node::ChainMainBlock tip2 = tip;
        tip2.height = 2001; tip2.id = synthetic_id(2001);
        chain.rows.push_back(tip2);
        TemplateInputs t2 = t; t2.height = 2002; t2.prev_id = tip2.id;
        chain.inputs = t2;
        const MinerDataEpoch e2 = src.epoch();
        CHECK(!(e2 == e0), "a tip change DOES move the epoch");
        CHECK(e2.height == 2002 && e2.prev_id == tip2.id, "the new epoch names the new tip");
    }

    // --- refresh_s > 0: at most once per interval, and only on a real change --
    {
        fakes::FakeChain c2;
        c2.state.synced = true;
        c2.rows.push_back(tip);
        c2.inputs = t;
        fakes::FakeTxpool p2;

        tmpl::NativeTemplatePolicy pol;
        pol.backlog_refresh_s = 30;
        tmpl::NativeMinerDataSource src(c2, p2, pol);
        src.set_now(1000);
        std::string why;
        (void)src.snapshot(&why);
        const MinerDataEpoch e0 = src.epoch();

        // Nothing changed in the pool: the sequence is the same, so no rebuild
        // even though the interval elapsed.
        src.set_now(1000 + 60);
        CHECK(src.epoch() == e0, "refresh window elapsed but the set is unchanged => no new epoch");

        // The set changes, but we are inside the interval.
        src.set_now(1010);
        p2.add(synthetic_id(11), 1500, 30000);
        CHECK(src.epoch() == e0, "set changed inside the interval => still no new epoch");

        // Interval elapsed AND the set changed.
        src.set_now(1000 + 31);
        const MinerDataEpoch e1 = src.epoch();
        CHECK(!(e1 == e0), "interval elapsed and the set changed => a new epoch");
        CHECK(e1.height == e0.height && e1.prev_id == e0.prev_id,
              "...on the SAME tip: it is the backlog sequence that moved");
    }
}

// ---------------------------------------------------------------------------
// Suite F -- backlog selection, bodies and pins.
// ---------------------------------------------------------------------------
void suite_backlog_and_bodies() {
    std::printf("== F. backlog policy, bodies and pins ==\n");

    fakes::FakeChain chain;
    chain.state.synced = true;
    node::ChainMainBlock tip;
    tip.height = 3000; tip.id = synthetic_id(3000);
    tip.timestamp = 1700000000; tip.difficulty = u128_of(1000000, 0);
    chain.rows.push_back(tip);
    TemplateInputs t;
    t.major_version = 16; t.minor_version = 16;
    t.height = 3001; t.prev_id = tip.id; t.seed_hash = synthetic_id(9);
    t.difficulty = u128_of(1000000, 0);
    t.median_weight = 300000; t.block_weight_limit = 600000;
    t.already_generated_coins = 18000000000000000000ull;
    t.median_timestamp = 1699999000; t.synced = true;
    chain.inputs = t;

    fakes::FakeTxpool pool;
    // Two transactions: one with the full daemonless evidence, one with only a
    // structural decode. The configured policy admits the first only.
    pool.add(synthetic_id(21), 64, 30000, EVIDENCE_DAEMONLESS_DEFAULT, /*peers=*/2);
    pool.add(synthetic_id(22), 64, 30000, AdmissionEvidence::Structural, /*peers=*/2);
    pool.configured.required  = EVIDENCE_DAEMONLESS_DEFAULT;
    pool.configured.min_peers = 1;

    {
        tmpl::NativeMinerDataSource src(chain, pool, {}, &pool);
        std::string why;
        const auto md = src.snapshot(&why);
        CHECK(md.has_value(), "snapshot with a populated pool");
        if (!md) return;
        CHECK(md->tx_backlog.size() == 1, "configured policy admits 1 of 2 transactions (got %zu)",
              md->tx_backlog.size());
        CHECK(md->tx_backlog.size() == 1 && md->tx_backlog[0].id == synthetic_id(21),
              "...and it is the one with the full evidence");

        // The bodies of what was selected must be resolvable: C5 cannot relay a
        // block it holds only the ids of, and a partial block is never emitted.
        const auto* body = src.tx_body(synthetic_id(21));
        CHECK(body != nullptr && body->size() == 64, "the selected transaction's body is resolvable");
        CHECK(src.tx_body(synthetic_id(22)) == nullptr, "an unselected transaction has no body pinned");
        CHECK(pool.pins.size() == 1, "exactly one pin generation is held");
    }

    // The explicit-policy overload: the shadow arm must be able to select under
    // the SERVED arm's rule, otherwise a template diff says nothing.
    {
        tmpl::NativeTemplatePolicy pol;
        pol.use_explicit_select = true;
        pol.select.required  = AdmissionEvidence::Structural;
        pol.select.min_peers = 1;
        tmpl::NativeMinerDataSource src(chain, pool, pol);
        std::string why;
        const auto md = src.snapshot(&why);
        CHECK(md.has_value() && md->tx_backlog.size() == 2,
              "explicit policy admits both transactions (got %zu)",
              md ? md->tx_backlog.size() : 0);
    }

    // Pin lifetime: RETAINED_EPOCHS generations, oldest unpinned as it falls out.
    {
        fakes::FakeTxpool p2;
        p2.add(synthetic_id(40), 32, 100, EVIDENCE_DAEMONLESS_DEFAULT, /*peers=*/2);
        fakes::FakeChain c2;
        c2.state.synced = true;
        tmpl::NativeMinerDataSource src(c2, p2, {}, &p2);
        const std::size_t N = tmpl::NativeMinerDataSource::RETAINED_EPOCHS;
        for (std::size_t i = 0; i < N + 3; ++i) {
            node::ChainMainBlock tp;
            tp.height = 4000 + i; tp.id = synthetic_id(4000 + i);
            tp.timestamp = 1700000000; tp.difficulty = u128_of(1000000, 0);
            c2.rows.clear(); c2.rows.push_back(tp);
            TemplateInputs ti = t;
            ti.height = tp.height + 1; ti.prev_id = tp.id;
            c2.inputs = ti;
            std::string why;
            (void)src.snapshot(&why);
        }
        CHECK(p2.pins.size() == N, "at most %zu pin generations survive (got %zu)", N, p2.pins.size());
    }
}

// ---------------------------------------------------------------------------
// Suite G -- the arm resolver.
// ---------------------------------------------------------------------------
void suite_arm_resolver(const ParityExpectation& exp) {
    std::printf("== G. arm resolver: serve, shadow, fallback ==\n");

    BuiltState st;
    build_state(st, exp.height - 1);
    fakes::FakeTxpool pool;
    tmpl::NativeMinerDataSource native(st.view, pool);

    CannedTransport tx(exp.raw_json);
    tmpl::MonerodMinerDataSource daemon(tx);
    std::string why;
    (void)daemon.poll(&why);

    // Default: serve monerod, no shadow.
    {
        tmpl::ArmResolver r(&daemon, &native, {});
        CHECK(r.serving() == &daemon, "default serves the daemon arm");
        CHECK(r.shadow() == nullptr, "no shadow by default");
        CHECK(!r.fell_back(), "no fallback when the configured arm is ready");
    }

    // serve=native, shadow=monerod: the M2 configuration.
    {
        tmpl::TemplateArmConfig cfg;
        cfg.serve  = TemplateArm::Native;
        cfg.shadow = TemplateArm::Monerod;
        CHECK(cfg.validate(), "serve != shadow validates");
        tmpl::ArmResolver r(&daemon, &native, cfg);
        CHECK(r.serving() == &native, "serves the native arm");
        CHECK(r.shadow() == &daemon, "shadows the daemon arm");
        CHECK(r.effective_arm() == TemplateArm::Native, "effective arm is native");
        CHECK(std::string(r.describe()) == "native", "describe() names the arm: %s", r.describe().c_str());
    }

    // A shadow equal to the serving arm is a configuration error, not a
    // silently-degraded oracle that compares an arm against itself.
    {
        tmpl::TemplateArmConfig cfg;
        cfg.serve  = TemplateArm::Native;
        cfg.shadow = TemplateArm::Native;
        std::string w;
        CHECK(!cfg.validate(&w), "shadow == serve is rejected (%s)", w.c_str());
    }

    // Fallback: the native arm loses readiness.
    {
        ChainStateView broken{XmrNet::Stagenet};
        tmpl::NativeMinerDataSource dead(broken, pool);
        tmpl::TemplateArmConfig cfg;
        cfg.serve = TemplateArm::Native;
        tmpl::ArmResolver r(&daemon, &dead, cfg);
        CHECK(r.serving() == &daemon, "native not ready => falls back to the daemon");
        CHECK(r.fell_back() && r.fallbacks() == 1, "the fallback is counted once");
        CHECK(!r.last_reason().empty(), "the reason is the native arm's own (%s)", r.last_reason().c_str());
        CHECK(r.describe().find("fallback from native") != std::string::npos,
              "describe() says it fell back: %s", r.describe().c_str());
        // Repeated resolution on the same failed arm must not inflate the count.
        (void)r.serving();
        CHECK(r.fallbacks() == 1, "a persistent fallback is one event, not one per call");
    }

    // fallback disabled: the M5 posture, where a native-only node must be
    // provably native-only.
    {
        ChainStateView broken{XmrNet::Stagenet};
        tmpl::NativeMinerDataSource dead(broken, pool);
        tmpl::TemplateArmConfig cfg;
        cfg.serve    = TemplateArm::Native;
        cfg.fallback = false;
        tmpl::ArmResolver r(&daemon, &dead, cfg);
        CHECK(r.serving() == nullptr, "fallback disabled => no template rather than a daemon template");
        CHECK(r.fallbacks() == 0, "and nothing is counted as a fallback");
    }

    // No daemon at all (the M5 deployment shape).
    {
        tmpl::TemplateArmConfig cfg;
        cfg.serve = TemplateArm::Native;
        tmpl::ArmResolver r(nullptr, &native, cfg);
        CHECK(r.serving() == &native, "a node with no daemon still serves natively");
    }
}

// ---------------------------------------------------------------------------
// Suite H -- REGRESSION R-C4-1: tx_body(id) returns the body OF THAT ID.
//
// ITxBlobSource compacts its `out` vector and names absent ids in `missing`.
// selectable_backlog() and get_blobs() are two separate lock acquisitions, so a
// transaction CAN disappear in between (mined, key-image conflict, expiry). If
// the fill zips out[i] with ids[i], every body after the hole is filed under
// the WRONG id and C5 relays a block whose bytes do not hash to the ids beside
// them. This suite injects exactly that hole and asserts identity per id.
// ---------------------------------------------------------------------------

// A body source that reproduces the race: `holes` were selectable a moment ago
// and are gone by the time the bodies are fetched. Compacts `out` and reports
// them in `missing`, exactly as RelayedTxPool and the contract fake do.
class HolePunchingBlobSource final : public ITxBlobSource {
public:
    explicit HolePunchingBlobSource(fakes::FakeTxpool& pool) : pool_(pool) {}

    std::vector<std::string> holes;   // keys of the ids to report as missing
    std::uint64_t            calls = 0;

    void punch(const Hash& id) { holes.push_back(fakes::FakeTxpool::key_of(id)); }

    bool get_blobs(const std::vector<Hash>& ids,
                   std::vector<std::vector<std::uint8_t>>& out,
                   std::vector<Hash>& missing) override {
        ++calls;
        out.clear();
        missing.clear();
        for (const Hash& id : ids) {
            const std::string k = fakes::FakeTxpool::key_of(id);
            if (std::find(holes.begin(), holes.end(), k) != holes.end()) {
                missing.push_back(id);
                continue;
            }
            std::vector<std::uint8_t> b;
            if (!pool_.get_tx(id, b)) { missing.push_back(id); continue; }
            out.push_back(std::move(b));   // COMPACTED: no placeholder for a hole
        }
        return missing.empty();
    }

    void pin(const Hash& t, const std::vector<Hash>& ids) override { pool_.pin(t, ids); }
    void unpin(const Hash& t) override { pool_.unpin(t); }

private:
    fakes::FakeTxpool& pool_;
};

// A body source that breaks the contract outright: it compacts `out` but never
// reports what it dropped, so out.size() + missing.size() != ids.size().
class LyingBlobSource final : public ITxBlobSource {
public:
    explicit LyingBlobSource(fakes::FakeTxpool& pool) : pool_(pool) {}
    std::string drop;   // key of the id to swallow silently

    bool get_blobs(const std::vector<Hash>& ids,
                   std::vector<std::vector<std::uint8_t>>& out,
                   std::vector<Hash>& missing) override {
        out.clear();
        missing.clear();
        for (const Hash& id : ids) {
            if (fakes::FakeTxpool::key_of(id) == drop) continue;   // no `missing` entry
            std::vector<std::uint8_t> b;
            if (pool_.get_tx(id, b)) out.push_back(std::move(b));
        }
        return true;
    }
    void pin(const Hash& t, const std::vector<Hash>& ids) override { pool_.pin(t, ids); }
    void unpin(const Hash& t) override { pool_.unpin(t); }

private:
    fakes::FakeTxpool& pool_;
};

// A body whose every byte names its own transaction, so a misfiled body is
// visible instead of accidentally equal to its neighbour's.
std::vector<std::uint8_t> distinct_body(std::uint8_t tag, std::size_t len) {
    return std::vector<std::uint8_t>(len, tag);
}

void suite_body_id_alignment() {
    std::printf("== H. R-C4-1: tx_body(id) is the body OF THAT ID, holes and all ==\n");

    fakes::FakeChain chain;
    chain.state.synced = true;
    node::ChainMainBlock tip;
    tip.height = 5000; tip.id = synthetic_id(5000);
    tip.timestamp = 1700000000; tip.difficulty = u128_of(1000000, 0);
    chain.rows.push_back(tip);
    TemplateInputs t;
    t.major_version = 16; t.minor_version = 16;
    t.height = 5001; t.prev_id = tip.id; t.seed_hash = synthetic_id(9);
    t.difficulty = u128_of(1000000, 0);
    t.median_weight = 300000; t.block_weight_limit = 600000;
    t.already_generated_coins = 18000000000000000000ull;
    t.median_timestamp = 1699999000; t.synced = true;
    chain.inputs = t;

    // Four selectable transactions, each with a body nobody else could own: a
    // distinct fill byte AND a distinct length.
    struct Tx { Hash id; std::uint8_t tag; std::size_t len; };
    const std::vector<Tx> txs = {
        {synthetic_id(41), 0xA1, 41},
        {synthetic_id(42), 0xA2, 42},
        {synthetic_id(43), 0xA3, 43},
        {synthetic_id(44), 0xA4, 44},
    };
    fakes::FakeTxpool pool;
    for (const auto& x : txs) {
        pool.add(x.id, static_cast<std::uint64_t>(x.len), 1000);
        pool.entries[fakes::FakeTxpool::key_of(x.id)].blob = distinct_body(x.tag, x.len);
    }

    // Which id the pool hands over first is the pool's business; punch whichever
    // it is, so the hole is genuinely ahead of other bodies.
    tmpl::NativeMinerDataSource probe(chain, pool);
    std::string pwhy;
    const auto ordered = probe.snapshot(&pwhy);
    CHECK(ordered.has_value() && ordered->tx_backlog.size() == 4,
          "the fixture selects all four transactions (got %zu)",
          ordered ? ordered->tx_backlog.size() : 0);
    if (!ordered || ordered->tx_backlog.size() != 4) return;

    const Hash hole_id = ordered->tx_backlog.front().id;

    HolePunchingBlobSource bodies(pool);
    bodies.punch(hole_id);

    tmpl::NativeMinerDataSource src(chain, pool, {}, &bodies);
    std::string why;
    const auto md = src.snapshot(&why);
    CHECK(md.has_value(), "snapshot succeeds even though a selected body went missing");
    if (!md) return;

    CHECK(bodies.calls == 1, "the bodies were fetched exactly once");
    CHECK(src.missing_bodies() == 1, "the missing body is counted (got %llu)",
          static_cast<unsigned long long>(src.missing_bodies()));
    CHECK(src.body_source_violations() == 0, "a compacted-but-honest source is not a violation");

    // NON-VACUOUS: the hole is real and it is not the last id, so bodies really
    // are fetched AFTER it -- the ones an index-zip misfiled.
    std::size_t after_hole = 0;
    bool        seen_hole  = false;
    for (const auto& e : md->tx_backlog) {
        if (e.id == hole_id) { seen_hole = true; continue; }
        if (seen_hole) ++after_hole;
    }
    CHECK(seen_hole, "the punched id is still part of the selected backlog");
    CHECK(after_hole >= 1, "at least one body is fetched after the hole (got %zu)", after_hole);

    // THE PIN: every selected id resolves to ITS OWN body, or to nothing.
    int resolved = 0;
    for (const auto& x : txs) {
        const std::vector<std::uint8_t>* body = src.tx_body(x.id);
        if (x.id == hole_id) {
            CHECK(body == nullptr, "the missing transaction resolves to nothing, not to a neighbour");
            continue;
        }
        const std::vector<std::uint8_t> want  = distinct_body(x.tag, x.len);
        const bool                      exact = (body != nullptr && *body == want);
        if (exact) ++resolved;
        CHECK(exact, "tx_body(tag %02x) is that transaction's own %zu-byte body",
              static_cast<unsigned>(x.tag), x.len);
    }
    CHECK(resolved == 3, "all three surviving bodies resolve exactly (got %d)", resolved);

    // A source that lies about what it dropped files NOTHING: a wrong body is
    // worse than a missing one.
    {
        fakes::FakeTxpool p2;
        for (const auto& x : txs) {
            p2.add(x.id, static_cast<std::uint64_t>(x.len), 1000);
            p2.entries[fakes::FakeTxpool::key_of(x.id)].blob = distinct_body(x.tag, x.len);
        }
        LyingBlobSource liar(p2);
        liar.drop = fakes::FakeTxpool::key_of(hole_id);
        tmpl::NativeMinerDataSource s2(chain, p2, {}, &liar);
        std::string w2;
        const auto  m2 = s2.snapshot(&w2);
        CHECK(m2.has_value(), "a contract-breaking body source does not break the template");
        CHECK(s2.body_source_violations() == 1, "the contract violation is counted");
        int any = 0;
        for (const auto& x : txs) if (s2.tx_body(x.id) != nullptr) ++any;
        CHECK(any == 0, "and NO body is filed on a reply we cannot align (got %d)", any);
    }
}

// ---------------------------------------------------------------------------
// Suite I -- REGRESSION R-C4-2: the pin survives an unchanged-tip re-snapshot.
//
// The pin key IS the epoch's prev_id, so a re-snapshot on the same tip pins and
// then de-duplicates under the SAME key. Unpinning the superseded generation
// AFTER taking the new pin erases the pin just installed and leaves the live
// template with none -- the pool is then free to evict bodies a still-winnable
// template selected, which is the one invariant the body path exists for.
// ---------------------------------------------------------------------------
void suite_pin_same_tip() {
    std::printf("== I. R-C4-2: an unchanged-tip re-snapshot keeps its pin ==\n");

    fakes::FakeChain chain;
    chain.state.synced = true;
    node::ChainMainBlock tip;
    tip.height = 6000; tip.id = synthetic_id(6000);
    tip.timestamp = 1700000000; tip.difficulty = u128_of(1000000, 0);
    chain.rows.push_back(tip);
    TemplateInputs t;
    t.major_version = 16; t.minor_version = 16;
    t.height = 6001; t.prev_id = tip.id; t.seed_hash = synthetic_id(9);
    t.difficulty = u128_of(1000000, 0);
    t.median_weight = 300000; t.block_weight_limit = 600000;
    t.already_generated_coins = 18000000000000000000ull;
    t.median_timestamp = 1699999000; t.synced = true;
    chain.inputs = t;

    fakes::FakeTxpool pool;
    const Hash tx1 = synthetic_id(61);
    pool.add(tx1, 64, 1000);
    pool.entries[fakes::FakeTxpool::key_of(tx1)].blob = distinct_body(0xB1, 64);

    tmpl::NativeMinerDataSource src(chain, pool, {}, &pool);
    std::string why;

    (void)src.snapshot(&why);
    CHECK(pool.pins.size() == 1, "the first snapshot pins its selection");
    CHECK(pool.pins.count(fakes::FakeTxpool::key_of(tip.id)) == 1,
          "...under the tip's id, which is the pin key");

    // The tip has NOT moved. This is the ordinary case: the provider refreshes
    // on its poll cadence for the whole life of a block.
    (void)src.snapshot(&why);
    CHECK(pool.pins.size() == 1, "a same-tip re-snapshot still holds exactly one pin (got %zu)",
          pool.pins.size());
    CHECK(pool.pins.count(fakes::FakeTxpool::key_of(tip.id)) == 1,
          "...and it is still the LIVE template's pin");
    CHECK(src.tx_body(tx1) != nullptr, "the live template's body is still resolvable");

    // Many re-snapshots on the same tip: one pin, never zero, never a growing
    // ring.
    for (int i = 0; i < 5; ++i) (void)src.snapshot(&why);
    CHECK(pool.pins.size() == 1, "seven same-tip snapshots hold one pin (got %zu)", pool.pins.size());
    CHECK(src.snapshots() == 7, "...and all seven were real snapshots (got %llu)",
          static_cast<unsigned long long>(src.snapshots()));

    // A pool change under the same tip: the selection is re-pinned, not
    // un-pinned, and the newly selected body is resolvable.
    const Hash tx2 = synthetic_id(62);
    pool.add(tx2, 96, 2000);
    pool.entries[fakes::FakeTxpool::key_of(tx2)].blob = distinct_body(0xB2, 96);
    (void)src.snapshot(&why);
    CHECK(pool.pins.size() == 1, "still one pin after the selection grew");
    CHECK(pool.pins[fakes::FakeTxpool::key_of(tip.id)].size() == 2,
          "the pin names both selected transactions (got %zu)",
          pool.pins[fakes::FakeTxpool::key_of(tip.id)].size());
    CHECK(src.tx_body(tx2) != nullptr, "the newly selected body is resolvable");

    // The tip moves: a second generation appears, and the first is still
    // pinned, because an in-flight share can still name it.
    node::ChainMainBlock tip2;
    tip2.height = 6001; tip2.id = synthetic_id(6001);
    tip2.timestamp = 1700000120; tip2.difficulty = u128_of(1000000, 0);
    chain.rows.push_back(tip2);
    TemplateInputs t2 = t; t2.height = 6002; t2.prev_id = tip2.id;
    chain.inputs = t2;
    (void)src.snapshot(&why);
    CHECK(pool.pins.size() == 2, "a tip move opens a second pin generation (got %zu)",
          pool.pins.size());
    CHECK(pool.pins.count(fakes::FakeTxpool::key_of(tip.id)) == 1,
          "the previous tip's pin survives for its retained template");

    // And a re-snapshot on the NEW tip does not drop the new pin either.
    (void)src.snapshot(&why);
    CHECK(pool.pins.size() == 2, "a same-tip re-snapshot on the new tip keeps both pins");
    CHECK(pool.pins.count(fakes::FakeTxpool::key_of(tip2.id)) == 1,
          "...including the live one");

    // An empty selection under the same tip releases the superseded pin rather
    // than leaking it: there is nothing left to pin.
    {
        fakes::FakeTxpool p2;
        p2.add(synthetic_id(63), 32, 500);
        fakes::FakeChain c2;
        c2.state.synced = true;
        c2.rows.push_back(tip);
        c2.inputs = t;
        tmpl::NativeMinerDataSource s2(c2, p2, {}, &p2);
        std::string w2;
        (void)s2.snapshot(&w2);
        CHECK(p2.pins.size() == 1, "pinned while the selection was non-empty");
        p2.entries.clear();                       // every candidate left the pool
        (void)s2.snapshot(&w2);
        CHECK(p2.pins.empty(), "an empty same-tip selection leaves no stale pin behind");
    }
}

// ---------------------------------------------------------------------------
// Suite J -- REGRESSION R-C4-3: the DEFAULT/PRODUCTION arm's rebuild rule is
// the pre-seam rule, unchanged.
//
// The consumer rebuilds when the epoch moves. The pre-seam rule was "the parent
// tip moved" and nothing else, so the daemon arm reports NO backlog sequence
// (frozen at 0) and the epoch term the seam added is 0 == 0 on every refresh of
// the production path. A size-derived sequence would instead force a full
// reassemble -- fresh header timestamp, new template id -- every time the
// daemon's txpool changed size under an unchanged tip, at the poll cadence.
//
// The suite drives the real MonerodMinerDataSource through the production
// parse_miner_data and compares, at every step, the observed decision against
// BOTH oracles: the pre-seam rule and the size-derived rule that regressed it.
// ---------------------------------------------------------------------------
std::string miner_data_json(const char* prev_id_hex, std::uint64_t height,
                            std::size_t n_backlog) {
    std::string s =
        "{\"id\":\"0\",\"jsonrpc\":\"2.0\",\"result\":{"
        "\"already_generated_coins\":18164488901536847281,"
        "\"difficulty\":\"0x39d402\","
        "\"height\":" + std::to_string(height) + ","
        "\"major_version\":16,"
        "\"median_weight\":300000,"
        "\"median_timestamp\":1700000000,"
        "\"prev_id\":\"" + std::string(prev_id_hex) + "\","
        "\"seed_hash\":\"5bd07b3c898f74aa3923d10f2749c9d4ee7b36461a55948f389e6044acacb321\","
        "\"tx_backlog\":[";
    static const char* d = "0123456789abcdef";
    for (std::size_t i = 0; i < n_backlog; ++i) {
        if (i) s += ",";
        std::string id_hex(64, '0');
        id_hex[0] = d[(i >> 4) & 0xf];
        id_hex[1] = d[i & 0xf];
        s += "{\"id\":\"" + id_hex + "\",\"weight\":2000,\"fee\":30000,\"blob_size\":2000}";
    }
    s += "],\"status\":\"OK\",\"untrusted\":false}}";
    return s;
}

void suite_daemon_arm_rebuild_identity() {
    std::printf("== J. R-C4-3: the production (monerod) arm rebuilds on the tip, only ==\n");

    const char* TIP_A = "a1a18db281797fb6c9651a95500725a22f51e293b814bb62606607c76877a035";
    const char* TIP_B = "b2b28dc392890fc7da762ba6611836b33f62f3a4c925cc73717718d87988b146";

    // A scripted daemon: the same tip with a txpool that grows, holds, drains
    // and empties, then a tip move. Exactly the shape a live monerod produces
    // between two blocks at a 5-second poll cadence.
    struct Step { const char* tip; std::uint64_t height; std::size_t backlog; const char* what; };
    const std::vector<Step> script = {
        {TIP_A, 2204960, 0, "first response, empty pool"},
        {TIP_A, 2204960, 3, "same tip, three transactions arrived"},
        {TIP_A, 2204960, 3, "same tip, nothing changed"},
        {TIP_A, 2204960, 9, "same tip, the pool grew again"},
        {TIP_A, 2204960, 1, "same tip, the pool drained"},
        {TIP_A, 2204960, 0, "same tip, the pool emptied"},
        {TIP_B, 2204961, 4, "THE TIP MOVED"},
        {TIP_B, 2204961, 7, "new tip, the pool grew"},
    };

    CannedTransport            tx(miner_data_json(TIP_A, 2204960, 0));
    tmpl::MonerodMinerDataSource daemon(tx);

    MinerDataEpoch prev_epoch{};
    std::uint64_t  prev_height  = 0;
    Hash           prev_tip{};
    std::size_t    prev_backlog = 0;
    bool           first        = true;

    int rebuilds_observed = 0, rebuilds_pre_seam = 0, rebuilds_size_rule = 0;
    int same_tip_pool_moves = 0;

    for (const Step& s : script) {
        tx.set_body(miner_data_json(s.tip, s.height, s.backlog));
        std::string why;
        const bool  polled = daemon.poll(&why);
        CHECK(polled, "poll: %s (%s)", s.what, why.empty() ? "ok" : why.c_str());
        if (!polled) return;

        const MinerDataEpoch e  = daemon.epoch();
        const auto           md = daemon.snapshot(&why);
        CHECK(md.has_value() && md->tx_backlog.size() == s.backlog,
              "the decoded backlog is the daemon's (%zu)", s.backlog);

        // THE PIN: this arm never reports a backlog sequence.
        CHECK(e.backlog_seq == 0, "backlog_seq stays 0 with %zu transactions in the pool",
              s.backlog);

        const Hash tip_now = md ? md->prev_id : Hash{};

        const bool observed  = first || !(e == prev_epoch);
        const bool pre_seam  = first || s.height != prev_height || !(tip_now == prev_tip);
        const bool size_rule = pre_seam || (s.backlog != prev_backlog);

        CHECK(observed == pre_seam,
              "rebuild decision matches the PRE-SEAM rule at '%s' (%s)",
              s.what, observed ? "rebuild" : "keep the template");

        if (observed)  ++rebuilds_observed;
        if (pre_seam)  ++rebuilds_pre_seam;
        if (size_rule) ++rebuilds_size_rule;
        if (!pre_seam && s.backlog != prev_backlog) ++same_tip_pool_moves;

        prev_epoch   = e;
        prev_height  = s.height;
        prev_tip     = tip_now;
        prev_backlog = s.backlog;
        first        = false;
    }

    CHECK(rebuilds_observed == rebuilds_pre_seam,
          "the arm rebuilt %d times, the pre-seam rule rebuilds %d",
          rebuilds_observed, rebuilds_pre_seam);
    CHECK(rebuilds_observed == 2,
          "two rebuilds over eight refreshes: the first template and the tip move (got %d)",
          rebuilds_observed);

    // NON-VACUOUS: the script really does move the pool under an unchanged tip,
    // and the size-derived sequence really would have rebuilt there. Without
    // these two the equality above would hold for an empty reason.
    CHECK(same_tip_pool_moves >= 3,
          "the script moves the txpool under an unchanged tip %d times", same_tip_pool_moves);
    CHECK(rebuilds_size_rule > rebuilds_observed,
          "a size-derived sequence would have rebuilt %d times instead of %d -- "
          "that is the regression this suite pins",
          rebuilds_size_rule, rebuilds_observed);

    // And the tip term is still load-bearing: the restored rule is not
    // "never rebuild".
    {
        tx.set_body(miner_data_json(TIP_A, 2204962, 0));
        std::string why;
        CHECK(daemon.poll(&why), "poll a third tip");
        const MinerDataEpoch e3 = daemon.epoch();
        CHECK(!(e3 == prev_epoch), "a tip change still moves the epoch");
        CHECK(e3.height == 2204962, "...and the epoch names the new height");
    }
}

// ---------------------------------------------------------------------------
// --parity-json: swap the embedded capture for a fresh one.
// ---------------------------------------------------------------------------
bool load_parity_json(const std::string& path, ParityExpectation& exp) {
    std::ifstream f(path);
    if (!f) { std::printf("  [FAIL] cannot open %s\n", path.c_str()); return false; }
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string all = ss.str();

    // Only the fields the KAT compares; the raw body is handed to the real
    // parser, so nothing here needs to understand the JSON deeply.
    auto find_u64 = [&](const char* key, std::uint64_t& out) {
        const std::string k = std::string("\"") + key + "\":";
        const auto p = all.find(k);
        if (p == std::string::npos) return false;
        out = std::strtoull(all.c_str() + p + k.size(), nullptr, 10);
        return true;
    };
    auto find_hex = [&](const char* key, Hash& out) {
        const std::string k = std::string("\"") + key + "\":\"";
        const auto p = all.find(k);
        if (p == std::string::npos) return false;
        out = hash_from_hex(all.c_str() + p + k.size());
        return true;
    };

    std::uint64_t v = 0;
    if (!find_u64("height", v)) return false;
    exp.height = v;
    if (!find_hex("prev_id", exp.prev_id)) return false;
    if (!find_hex("seed_hash", exp.seed_hash)) return false;
    if (find_u64("median_weight", v)) exp.median_weight = v;
    if (find_u64("already_generated_coins", v)) exp.already_generated_coins = v;
    if (find_u64("major_version", v)) exp.major_version = static_cast<std::uint8_t>(v);
    {
        const std::string k = "\"difficulty\":";
        const auto p = all.find(k);
        if (p != std::string::npos) {
            const char* s = all.c_str() + p + k.size();
            if (*s == '"') exp.difficulty_lo = std::strtoull(s + 1, nullptr, 16);
            else           exp.difficulty_lo = std::strtoull(s, nullptr, 10);
        }
    }
    exp.raw_json   = all;
    exp.provenance = "--parity-json " + path;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    std::printf("=== xmr_native_template_kat (C4: the IMinerDataSource seam) ===\n");

    ParityExpectation exp;
    exp.prev_id   = hash_from_hex(G4::MD_PREV_ID);
    exp.seed_hash = hash_from_hex(G4::MD_SEED_HASH);

    bool live = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--parity-json") == 0 && i + 1 < argc) {
            if (!load_parity_json(argv[++i], exp)) return 2;
            live = true;
        }
    }
    if (live) {
        std::printf("NOTE: comparing against an EXTERNAL capture; the chain rows below the\n"
                    "      tip still come from the embedded golden, so this mode is only\n"
                    "      meaningful when the capture is the same height as the golden.\n");
    }

    suite_native_parity(exp);
    suite_monerod_arm(exp);
    suite_readiness();
    suite_difficulty_band();
    suite_epoch();
    suite_backlog_and_bodies();
    suite_arm_resolver(exp);
    suite_body_id_alignment();
    suite_pin_same_tip();
    suite_daemon_arm_rebuild_identity();

    std::printf("=== %d checks, %d failed ===\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
