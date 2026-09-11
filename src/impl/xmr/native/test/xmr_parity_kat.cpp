// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_parity_kat.cpp
//
// C6: the monerod-parity oracle, proven both ways.
//
// The claim under test is the M4 gate itself -- "monerod may become optional" --
// so the KAT has to establish two things that pull in opposite directions:
//
//   IT AGREES WHEN IT SHOULD. Over real, captured stagenet data, with the
//   native side DERIVED (C2a's consensus arithmetic driving C2c's index and
//   C4's template source) rather than copied, all three seams come out CLEAN.
//   Suites D, E and F are that half. The data is a read-only capture from a
//   synced stagenet monerod 0.18.5.1 at tip 2205017, and it links to the
//   INDEPENDENT capture the C4 component took days earlier at 2204959 -- the
//   two agree on the block id and on the difficulty of the block between them,
//   which is a corroboration neither capture could fake alone.
//
//   IT FAILS WHEN IT SHOULD. Suite H is the non-vacuity control and it is the
//   more important half. Every required EQUALITY field of every seam is
//   perturbed by ONE UNIT -- one satoshi of reward, one second of timestamp, one
//   in the low limb of a 128-bit cumulative difficulty, one bit of a block id --
//   and the oracle must FAIL each time. Then every field is REMOVED, one at a
//   time, and the oracle must FAIL then too: a comparison that did not happen is
//   not a comparison that passed. And a VOID sample must never move a clean
//   streak, must never satisfy a coverage floor, and must never graduate
//   anything.
//
// ctest runs this with no arguments. `--verbose` prints every sample line.
// ---------------------------------------------------------------------------

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_view.hpp"
#include "impl/xmr/native/consensus/xmr_epoch.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/consensus/xmr_weight.hpp"
#include "impl/xmr/native/contracts/fakes/fakes.hpp"
#include "impl/xmr/native/parity/xmr_parity_comparator.hpp"
#include "impl/xmr/native/parity/xmr_parity_ledger.hpp"
#include "impl/xmr/native/parity/xmr_parity_oracle.hpp"
#include "impl/xmr/native/parity/xmr_parity_report.hpp"
#include "impl/xmr/native/parity/xmr_parity_sources.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/native/template/xmr_native_miner_data.hpp"

#include "xmr_c2a_golden.hpp"
#include "xmr_c4_parity_golden.hpp"
#include "xmr_c6_parity_golden.hpp"

using namespace c2pool::xmr::native;
using namespace c2pool::xmr::native::parity;
namespace G2 = c2pool::xmr::native::golden_c2a;
namespace G4 = c2pool::xmr::native::golden_c4;
namespace G6 = c2pool::xmr::native::golden_c6;

namespace {

int  g_fail = 0;
int  g_checks = 0;
bool g_verbose = false;

#define CHECK(cond, ...)                                  \
    do {                                                  \
        const bool _ok = (cond);                          \
        ++g_checks;                                       \
        if (!_ok) ++g_fail;                               \
        if (!_ok || g_verbose) {                          \
            std::printf("  [%s] ", _ok ? "PASS" : "FAIL");\
            std::printf(__VA_ARGS__);                     \
            std::printf("\n");                            \
        }                                                 \
    } while (0)

// A quiet check that only prints when it fails; used inside the long sweeps so
// 189 heights do not produce 189 lines of noise on a green run.
#define CHECK_Q(cond, ...)                                \
    do {                                                  \
        const bool _ok = (cond);                          \
        ++g_checks;                                       \
        if (!_ok) { ++g_fail; std::printf("  [FAIL] "); std::printf(__VA_ARGS__); std::printf("\n"); } \
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

U128 u128_of(std::uint64_t lo, std::uint64_t hi = 0) { U128 d; d.lo = lo; d.hi = hi; return d; }

std::uint64_t g_clock = 1789000000ull;
std::uint64_t fake_now() { return g_clock; }

// ---------------------------------------------------------------------------
// The native derivation.
//
// NOTE ON THE COPIED SEED HELPERS. The four c2a_*_seed() functions below are the
// same shape as the ones in xmr_native_template_kat.cpp. They are not shared,
// because sharing them would mean editing that component's KAT from this
// component's change, and the two seams are supposed to be independently
// buildable. The numbers themselves are not duplicated: both read the same two
// generated goldens.
//
// WHAT IS DERIVED AND WHAT IS OBSERVED. This distinction is the whole value of
// the tip suite, so it is stated rather than implied:
//
//   DERIVED by us   : difficulty (735-row retarget), cumulative_difficulty
//                     (the chain sum -- not in any header, which is exactly why
//                     a pool cannot SPV this), long_term_weight (the HF15
//                     clamp), base reward and already_generated_coins.
//   OBSERVED on the wire : block id, prev_id, timestamp, block_weight,
//                     major_version -- the fields a real index reads out of the
//                     block it just connected, and which it is right to take
//                     from the block.
//
// So a CLEAN tip sample means our arithmetic reproduced monerod's, not that we
// copied monerod's numbers into both sides of a comparison.
// ---------------------------------------------------------------------------
const G2::GoldenHeader& c2a_header_at(std::uint64_t h) {
    return G2::HEADERS[h - G2::HEADERS_FIRST_HEIGHT];
}

std::vector<std::uint64_t> c2a_long_term_seed() {
    std::vector<std::uint64_t> v;
    v.reserve(G2::LT_WINDOW_SIZE);
    for (std::size_t i = 0; i < G2::LT_SEED_HEAD_COUNT; ++i) v.push_back(G2::LT_SEED_HEAD[i]);
    for (std::size_t i = 0; i < G2::LT_SEED_TAIL_RUNS_COUNT; ++i)
        for (std::uint64_t k = 0; k < G2::LT_SEED_TAIL_RUNS[i].count; ++k)
            v.push_back(G2::LT_SEED_TAIL_RUNS[i].value);
    return v;
}

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

// The rolling native state. One instance walks from the C2a seed position, over
// the C4 golden's rows, and then over the C6 capture's rows -- three
// independent captures of one chain, joined by nothing but the chain itself.
struct NativeRoll {
    DifficultyWindow           diff;
    WeightState                ws;
    std::vector<DifficultyRow> diff_rows;   // mirror, for seed_direct
    std::vector<std::uint64_t> shortw, longw, times;
    std::uint64_t              agc = 0;
    U128                       cum{};
    std::uint64_t              height = 0;
    Hash                       tip_id{};

    void seed() {
        diff_rows = c2a_difficulty_seed();
        shortw    = c2a_short_term_seed();
        longw     = c2a_long_term_seed();
        times     = c2a_timestamp_seed();
        agc       = G2::AGC_BEFORE_FIRST;
        diff.seed(diff_rows);
        ws.seed(shortw, longw);
        if (!diff_rows.empty()) cum = diff_rows.back().cumulative_difficulty;
    }

    // One connected block. `observed_*` come off the wire; everything returned
    // is ours.
    struct Derived {
        U128          difficulty{};
        U128          cumulative_difficulty{};
        std::uint64_t long_term_weight = 0;
        std::uint64_t base_reward = 0;
        std::uint64_t effective_median = 0;
    };

    Derived connect(std::uint64_t observed_height, std::uint64_t observed_timestamp,
                    std::uint64_t observed_block_weight, std::uint8_t observed_major,
                    const Hash& observed_id) {
        Derived d;
        d.difficulty            = diff.next_difficulty(observed_major);
        d.cumulative_difficulty = u128_add(cum, d.difficulty);
        d.effective_median      = ws.effective_median(observed_major);
        d.long_term_weight      = ws.next_long_term_weight(observed_block_weight, observed_major);

        const std::uint64_t pen = penalty_median(d.effective_median, ws.short_term_median(),
                                                 observed_major);
        get_block_reward(pen, observed_block_weight, agc, observed_major, d.base_reward);

        agc = accumulate_generated_coins(agc, d.base_reward);
        cum = d.cumulative_difficulty;
        diff.push(observed_timestamp, d.cumulative_difficulty);
        ws.push(observed_block_weight, d.long_term_weight);

        diff_rows.push_back(DifficultyRow{observed_timestamp, d.cumulative_difficulty});
        shortw.push_back(observed_block_weight);
        longw.push_back(d.long_term_weight);
        times.push_back(observed_timestamp);
        trim_();

        height = observed_height;
        tip_id = observed_id;
        return d;
    }

private:
    void trim_() {
        auto tail = [](auto& v, std::size_t keep) {
            if (v.size() > keep) v.erase(v.begin(), v.begin() + static_cast<long>(v.size() - keep));
        };
        tail(diff_rows, static_cast<std::size_t>(DIFFICULTY_BLOCKS_COUNT));
        tail(shortw,    static_cast<std::size_t>(CRYPTONOTE_REWARD_BLOCKS_WINDOW));
        tail(longw,     static_cast<std::size_t>(G2::LT_WINDOW_SIZE));
        tail(times,     static_cast<std::size_t>(BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW));
    }
};

// Roll from the C2a seed through the C4 rows up to and including `stop`.
// The C4 rows carry no block ids (that golden did not need them), so the id is
// only meaningful once the C6 rows take over; for the C4 stretch the id column
// is the one the C4 golden pinned for its own tip.
void roll_over_c4(NativeRoll& n, std::uint64_t stop) {
    for (std::size_t i = 0; i < G4::ROWS_COUNT; ++i) {
        const G4::GoldenRow& r = G4::ROWS[i];
        if (r.height > stop) break;
        Hash id{};
        if (r.height == G4::ROWS_LAST_HEIGHT) id = hash_from_hex(G4::TIP_ID);
        n.connect(r.height, r.timestamp, r.block_weight, r.major_version, id);
    }
}

// ---------------------------------------------------------------------------
// A canned IMonerodTransport: answers per JSON-RPC method name.
// ---------------------------------------------------------------------------
class CannedRpc final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    void set(const std::string& method, std::string body) { bodies_[method] = std::move(body); }
    void fail(const std::string& method, std::string err) { errors_[method] = std::move(err); }
    void clear_failures() { errors_.clear(); }
    std::uint64_t calls() const { return calls_; }

    void rpc_post(const std::string& req,
                  std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ++calls_;
        const std::string m = method_of(req);
        ::c2pool::xmr::node::RpcResponse r;
        auto e = errors_.find(m);
        if (e != errors_.end()) { r.error = e->second; cb(r); return; }
        auto it = bodies_.find(m);
        if (it == bodies_.end()) { r.error = "canned: no body for '" + m + "'"; cb(r); return; }
        r.body.assign(it->second.begin(), it->second.end());
        cb(r);
    }
    void zmq_subscribe(const std::string&,
                       std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}

private:
    static std::string method_of(const std::string& body) {
        const std::string key = "\"method\":\"";
        const auto p = body.find(key);
        if (p == std::string::npos) return {};
        const auto s = p + key.size();
        const auto e = body.find('"', s);
        return e == std::string::npos ? std::string() : body.substr(s, e - s);
    }
    std::map<std::string, std::string> bodies_, errors_;
    std::uint64_t calls_ = 0;
};

// ---------------------------------------------------------------------------
// Observation builders used by several suites.
// ---------------------------------------------------------------------------
ArmObservation monerod_row_observation(const G6::GoldenHeader& r) {
    ArmObservation o;
    o.arm     = "monerod";
    o.have    = true;
    o.height  = r.height;
    o.prev_id = hash_from_hex(r.prev_hash);
    o.fields.set("id",                    Obs::id(hash_from_hex(r.hash)));
    o.fields.set("prev_id",               Obs::id(hash_from_hex(r.prev_hash)));
    o.fields.set("cumulative_difficulty",
                 Obs::u128(u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi)));
    o.fields.set("difficulty",            Obs::u128(u128_of(r.difficulty_lo, r.difficulty_hi)));
    o.fields.set("timestamp",             Obs::u64(r.timestamp));
    o.fields.set("reward",                Obs::u64(r.reward));
    o.fields.set("block_weight",          Obs::u64(r.block_weight));
    o.fields.set("long_term_weight",      Obs::u64(r.long_term_weight));
    o.fields.set("major_version",         Obs::u64(r.major_version));
    return o;
}

// ===========================================================================
// A. Obs / FieldSet: absence is a value, and it is never equality.
// ===========================================================================
void suite_absence() {
    std::printf("== A. absence is a value, not a zero ==\n");

    const Obs zero = Obs::u64(0);
    const Obs gone = Obs::absent();

    CHECK(zero.present && !gone.present, "an observed 0 is present; an absent field is not");
    CHECK(zero.value == "0", "zero renders as \"0\"");
    CHECK(gone.render() == std::string("<absent>"), "absence renders as <absent>, never as a number");
    CHECK(!same_value(gone, gone), "two absences are NOT equal to each other");
    CHECK(!same_value(gone, zero) && !same_value(zero, gone), "absence never equals a value");
    CHECK(same_value(zero, Obs::u64(0)), "two observed zeros are equal");

    // The u128 rendering must not lose the top limb.
    CHECK(Obs::u128(u128_of(5, 1)).value != Obs::u128(u128_of(5, 0)).value,
          "a 128-bit value renders hi and lo separately (a top64 carry cannot vanish)");
    CHECK(Obs::u128(u128_of(0, 1)).value == "1:0", "u128 renders as hi:lo");

    FieldSet fs;
    CHECK(!fs.answered("difficulty"), "an unset field reads as unanswered");
    fs.set("difficulty", Obs::absent());
    CHECK(!fs.answered("difficulty"), "a field explicitly set to absent also reads as unanswered");
    fs.set("difficulty", Obs::u64(7));
    CHECK(fs.answered("difficulty") && fs.get("difficulty").value == "7", "set then read");
    fs.set("difficulty", Obs::u64(8));
    CHECK(fs.get("difficulty").value == "8" && fs.size() == 1, "set replaces rather than duplicates");
}

// ===========================================================================
// B. The frozen determinism table.
// ===========================================================================
void suite_table() {
    std::printf("== B. the frozen determinism table (comparator v%u) ==\n", COMPARATOR_VERSION);

    // Version 3 since M2h added the native_backlog_famine CONSTRAINT to the
    // P-TPL table (M1's version 2 was the P-POOL seam joining). This stays an
    // EXACT number rather than a floor on purpose: its whole job is to make
    // anyone who edits a table move the ledger key too, so that a clean streak
    // can never be inherited across a change to what is compared.
    CHECK(COMPARATOR_VERSION == 3,
          "comparator version is 3 (the P-TPL backlog constraint joined the table)");
    CHECK(POOL_SEAM.required_equality_count() == 3,
          "POOL requires 3 EQUALITY fields (weight, fee, blob_size), got %zu",
          POOL_SEAM.required_equality_count());
    CHECK(TIP_SEAM.required_equality_count() == 9,
          "TIP requires 9 EQUALITY fields (id, prev_id, cumdiff, difficulty, timestamp, "
          "reward, block_weight, long_term_weight, major_version), got %zu",
          TIP_SEAM.required_equality_count());
    CHECK(TEMPLATE_SEAM.required_equality_count() == 6,
          "TEMPLATE requires 6 EQUALITY fields, got %zu", TEMPLATE_SEAM.required_equality_count());
    CHECK(SUBMIT_SEAM.required_equality_count() == 2,
          "SUBMIT names 2 acceptance oracles, got %zu", SUBMIT_SEAM.required_equality_count());

    // No seam may be empty: the comparator refuses to call an empty comparison
    // agreement, and the tables must never make that the normal case.
    const SeamSpec* all[3] = {&TIP_SEAM, &TEMPLATE_SEAM, &SUBMIT_SEAM};
    for (const SeamSpec* s : all)
        CHECK(s->required_equality_count() > 0, "seam %s has at least one required field",
              to_string(s->kind));

    // The revocation sentinels of plan section 3.5 are the ones that must be
    // marked, and no others may creep in silently.
    auto is_sentinel = [](const SeamSpec& s, const char* n) {
        for (std::size_t i = 0; i < s.count; ++i)
            if (std::strcmp(s.fields[i].name, n) == 0) return s.fields[i].sentinel;
        return false;
    };
    CHECK(is_sentinel(TIP_SEAM, "major_version"), "major_version is a TIP sentinel");
    CHECK(is_sentinel(TIP_SEAM, "difficulty"), "difficulty is a TIP sentinel");
    CHECK(is_sentinel(TIP_SEAM, "cumulative_difficulty"), "cumulative_difficulty is a TIP sentinel");
    CHECK(!is_sentinel(TIP_SEAM, "timestamp"), "timestamp is NOT a sentinel (it fails, it does not revoke)");
    CHECK(is_sentinel(TEMPLATE_SEAM, "seed_hash"), "seed_hash is a TEMPLATE sentinel");
    CHECK(is_sentinel(TEMPLATE_SEAM, "already_generated_coins"), "agc is a TEMPLATE sentinel");

    // The coinbase is NOT-COMPARABLE by design; recording it stops it being
    // re-added as a gate by someone who has not read the reasoning.
    bool coinbase_not_comparable = false;
    for (std::size_t i = 0; i < TEMPLATE_SEAM.count; ++i)
        if (std::strcmp(TEMPLATE_SEAM.fields[i].name, "coinbase_bytes") == 0)
            coinbase_not_comparable = TEMPLATE_SEAM.fields[i].regime == Regime::NotComparable;
    CHECK(coinbase_not_comparable,
          "template coinbase bytes are NOT-COMPARABLE (monerod mints a random tx key)");

    // Every required field is named in the ledger's coverage list, or a field
    // could be required by the comparator and invisible to the gate.
    const std::vector<std::string> names = GraduationLedger::required_field_names();
    CHECK(names.size() == TIP_SEAM.required_equality_count()
                        + TEMPLATE_SEAM.required_equality_count()
                        + SUBMIT_SEAM.required_equality_count(),
          "the ledger's coverage list names every required field (%zu)", names.size());

    // And every entry is DISTINCT. prev_id, major_version and difficulty are
    // required by both the tip table and the template table; if coverage were
    // keyed by bare name they would collide, and a long tip run would satisfy
    // the template seam's floor for fields nobody ever compared there.
    std::vector<std::string> sorted = names;
    std::sort(sorted.begin(), sorted.end());
    CHECK(std::adjacent_find(sorted.begin(), sorted.end()) == sorted.end(),
          "every coverage key is distinct (seam-qualified)");
    CHECK(field_key(ProbeKind::Tip, "difficulty") != field_key(ProbeKind::Template, "difficulty"),
          "TIP.difficulty and TEMPLATE.difficulty are two different claims");
}

// ===========================================================================
// C. TIP, seam 1: the verbatim get_info + get_last_block_header pair.
// ===========================================================================
void suite_tip_rpc() {
    std::printf("== C. TIP: monerod get_info + get_last_block_header, verbatim ==\n");
    std::printf("   capture: monerod %s %s, tip %llu\n", G6::MONEROD_VERSION, G6::NETWORK,
                static_cast<unsigned long long>(G6::TIP_HEIGHT));

    CannedRpc rpc;
    rpc.set("get_info", G6::INFO_RAW_JSON);
    rpc.set("get_last_block_header", G6::LAST_BLOCK_HEADER_RAW_JSON);

    MonerodTipObserver obs(rpc);
    CHECK(obs.poll(), "polling a healthy daemon yields an observation");
    CHECK(obs.daemon_version() == std::string(G6::MONEROD_VERSION),
          "the daemon version is read for the graduation key: %s", obs.daemon_version().c_str());
    CHECK(obs.nettype() == std::string(G6::NETWORK), "the network is read for the graduation key");
    CHECK(obs.synchronized(), "the captured daemon reported itself synchronized");

    const ArmObservation m = obs.observe();
    CHECK(m.have, "the two answers were coherent");
    CHECK(m.height == G6::TIP_HEIGHT, "tip height %llu", static_cast<unsigned long long>(m.height));
    CHECK(m.fields.get("id").value == Obs::id(hash_from_hex(G6::TIP_ID)).value, "tip id");
    CHECK(m.fields.get("prev_id").value == Obs::id(hash_from_hex(G6::TIP_PREV_ID)).value, "prev_id");
    CHECK(m.fields.get("cumulative_difficulty").value
              == Obs::u128(u128_of(G6::INFO_CUMULATIVE_DIFFICULTY_LO,
                                   G6::INFO_CUMULATIVE_DIFFICULTY_HI)).value,
          "cumulative difficulty parsed from wide_cumulative_difficulty hex");

    // The hex path and the decimal path must agree; that is what makes the
    // wide_* preference safe.
    U128 wide{};
    CHECK(parse_wide_hex("0xc45ab9090f", wide) && wide.lo == 843335665935ull && wide.hi == 0,
          "wide hex decodes to the same number as the decimal field");
    U128 big{};
    CHECK(parse_wide_hex("0x1" "0000000000000000", big) && big.hi == 1 && big.lo == 0,
          "wide hex carries into the top limb");
    CHECK(!parse_wide_hex("c45ab9090f", wide), "a hex string without 0x is refused");
    CHECK(!parse_wide_hex("0xzz", wide), "a non-hex digit is refused");

    // --- the incoherence refusals. Both are VOID sources, not failures.
    {
        CannedRpc bad;
        bad.set("get_info", G6::INFO_RAW_JSON);
        // A header from one block earlier: the daemon's tip moved between calls.
        std::string older = std::string(G6::LAST_BLOCK_HEADER_RAW_JSON);
        const std::string h = "\"height\":" + std::to_string(G6::TIP_HEIGHT);
        const auto p = older.find(h);
        CHECK(p != std::string::npos, "the capture contains the header height (fixture sanity)");
        older.replace(p, h.size(), "\"height\":" + std::to_string(G6::TIP_HEIGHT - 1));
        bad.set("get_last_block_header", older);

        MonerodTipObserver o2(bad);
        CHECK(!o2.poll(), "an incoherent get_info/get_last_block_header pair yields NO observation");
        CHECK(o2.observe().why.find("incoherent") != std::string::npos,
              "and says why: %s", o2.observe().why.c_str());
    }
    {
        CannedRpc dead;
        dead.set("get_info", G6::INFO_RAW_JSON);
        dead.fail("get_last_block_header", "connection refused");
        MonerodTipObserver o3(dead);
        CHECK(!o3.poll(), "a transport failure yields NO observation (which the comparator voids)");
        CHECK(o3.failures() == 1, "and is counted");
    }
    {
        // A daemon that answers but omits long_term_weight: the observation is
        // still made, and the FIELD is absent -- which suite H proves is a FAIL,
        // not a pass.
        std::string trimmed = std::string(G6::LAST_BLOCK_HEADER_RAW_JSON);
        const std::string key = "\"long_term_weight\":";
        const auto p = trimmed.find(key);
        CHECK(p != std::string::npos, "the capture contains long_term_weight (fixture sanity)");
        const auto e = trimmed.find(',', p);
        trimmed.erase(p, e - p + 1);
        CannedRpc part;
        part.set("get_info", G6::INFO_RAW_JSON);
        part.set("get_last_block_header", trimmed);
        MonerodTipObserver o4(part);
        CHECK(o4.poll(), "a daemon that omits one field still produces an observation");
        CHECK(!o4.observe().fields.answered("long_term_weight"),
              "and the missing field is ABSENT, not zero");
    }
}

// ===========================================================================
// D. TIP, sustained: 58 consecutive heights, native side DERIVED.
// ===========================================================================
NativeRoll g_roll;   // rolled to G6::TIP_HEIGHT by this suite, reused by F

void suite_tip_derived() {
    std::printf("== D. TIP: 58 consecutive stagenet heights, native side derived ==\n");

    // Cross-capture corroboration: the C4 capture's tip id is the C6 capture's
    // row at the same height, and the C4 capture's get_miner_data difficulty is
    // the C6 capture's difficulty for the block above it. Two captures, days
    // apart, one chain.
    const G6::GoldenHeader* r2204959 = nullptr;
    const G6::GoldenHeader* r2204960 = nullptr;
    for (std::size_t i = 0; i < G6::STEADY_COUNT; ++i) {
        if (G6::STEADY[i].height == G4::ROWS_LAST_HEIGHT)     r2204959 = &G6::STEADY[i];
        if (G6::STEADY[i].height == G4::ROWS_LAST_HEIGHT + 1) r2204960 = &G6::STEADY[i];
    }
    CHECK(r2204959 != nullptr && r2204960 != nullptr, "the two captures overlap in height");
    if (r2204959 && r2204960) {
        CHECK(std::string(r2204959->hash) == std::string(G4::TIP_ID),
              "the C4 capture's tip id is the C6 capture's block at that height");
        CHECK(r2204960->difficulty_lo == G4::MD_DIFFICULTY_LO,
              "the C4 capture's get_miner_data difficulty is the C6 capture's block difficulty");
        CHECK(r2204959->cumulative_difficulty_lo
                  == G4::ROWS[G4::ROWS_COUNT - 1].cumulative_difficulty_lo,
              "and the two captures agree on the cumulative difficulty there");
    }

    g_roll.seed();
    roll_over_c4(g_roll, G4::ROWS_LAST_HEIGHT);
    CHECK(g_roll.height == G4::ROWS_LAST_HEIGHT, "rolled to the C4 capture's last height");
    CHECK(g_roll.agc == G4::MD_ALREADY_GENERATED_COINS,
          "and the derived emission there is monerod's own already_generated_coins");

    GraduationLedger led({"kat", COMPARATOR_VERSION, G6::MONEROD_VERSION, G6::NETWORK},
                         GraduationPolicy::regtest_fast());

    std::size_t clean = 0, judged = 0;
    for (std::size_t i = 0; i < G6::STEADY_COUNT; ++i) {
        const G6::GoldenHeader& r = G6::STEADY[i];
        if (r.height <= G4::ROWS_LAST_HEIGHT) continue;   // already rolled, no ids there

        const Hash id = hash_from_hex(r.hash);
        const NativeRoll::Derived d =
            g_roll.connect(r.height, r.timestamp, r.block_weight, r.major_version, id);

        // The native row, built from what we derived plus what we observed.
        ChainRow row;
        row.height                = r.height;
        row.id                    = id;
        row.prev_id               = hash_from_hex(r.prev_hash);
        row.timestamp             = r.timestamp;                 // observed
        row.major_version         = r.major_version;             // observed
        row.block_weight          = r.block_weight;              // observed
        row.long_term_weight      = d.long_term_weight;          // DERIVED
        row.difficulty            = d.difficulty;                // DERIVED
        row.cumulative_difficulty = d.cumulative_difficulty;     // DERIVED
        row.reward                = (r.num_txes == 0) ? d.base_reward : r.reward;
        row.already_generated_coins = g_roll.agc;                // DERIVED

        // For an empty block the whole reward IS the derived base reward, so
        // the comparison below is a real check on our emission arithmetic.
        if (r.num_txes == 0)
            CHECK_Q(d.base_reward == r.reward,
                    "h=%llu derived base reward %llu != monerod's %llu",
                    (unsigned long long)r.height, (unsigned long long)d.base_reward,
                    (unsigned long long)r.reward);

        CompareOptions opt;
        opt.classes.height = r.height;
        opt.classes.block_weight = r.block_weight;
        opt.classes.effective_median = d.effective_median;
        opt.context = "steady window";

        const SeamResult res =
            compare_seam(TIP_SEAM, native_tip_observation(row), monerod_row_observation(r), opt);
        if (g_verbose) std::printf("%s", render_sample(res).c_str());

        CHECK_Q(res.sample.verdict == ParityVerdict::Clean,
                "h=%llu tip sample is %s (%s)", (unsigned long long)r.height,
                to_string(res.sample.verdict), res.sample.note.c_str());
        CHECK_Q(res.equality_compared == res.equality_required,
                "h=%llu compared %zu of %zu required fields", (unsigned long long)r.height,
                res.equality_compared, res.equality_required);
        if (res.sample.verdict == ParityVerdict::Clean) ++clean;
        if (res.judged()) ++judged;
        led.record(res, 1789000000ull + r.height);
    }

    CHECK(judged == clean && clean >= 55,
          "%zu of %zu heights judged CLEAN, none voided", clean, judged);
    CHECK(g_roll.height == G6::TIP_HEIGHT, "the roll ends at the captured tip");
    CHECK(g_roll.tip_id == hash_from_hex(G6::TIP_ID), "with the captured tip id");
    CHECK(led.seam(ProbeKind::Tip).clean_streak == clean,
          "the ledger's clean streak is the run of clean samples");

    // Per-field coverage: every required TIP field really was compared, once
    // per height. This is the arithmetic answer to "did we compare anything?".
    for (std::size_t i = 0; i < TIP_SEAM.count; ++i) {
        const FieldSpec& f = TIP_SEAM.fields[i];
        if (f.regime != Regime::Equality || !f.required) continue;
        auto it = led.fields().find(field_key(ProbeKind::Tip, f.name));
        CHECK(it != led.fields().end() && it->second.compared == clean && it->second.differed == 0,
              "field TIP.%s compared %llu time(s), 0 differences", f.name,
              (unsigned long long)(it == led.fields().end() ? 0 : it->second.compared));
    }
}

// ===========================================================================
// E. Height classes over a real RandomX epoch boundary.
// ===========================================================================
void suite_epoch_edge() {
    std::printf("== E. EpochEdge over the real boundary at %llu ==\n",
                static_cast<unsigned long long>(G6::EPOCH_BOUNDARY));

    std::size_t edges = 0, steady_only = 0;
    for (std::size_t i = 0; i < G6::EPOCH_WINDOW_COUNT; ++i) {
        const std::uint64_t h = G6::EPOCH_WINDOW[i].height;
        ClassifierInputs in;
        in.height = h;
        const std::vector<HeightClass> c = classify(in);

        const std::uint64_t into = h % 2048;
        const bool expect_edge = (into <= 64) || (into >= 2048 - 64);
        CHECK_Q(has_class(c, HeightClass::EpochEdge) == expect_edge,
                "h=%llu epoch class wrong", (unsigned long long)h);
        CHECK_Q(has_class(c, HeightClass::Steady),
                "h=%llu every sample carries Steady so no sample is classless",
                (unsigned long long)h);
        if (expect_edge) ++edges; else ++steady_only;
    }
    CHECK(edges > 0 && steady_only > 0,
          "the captured window straddles the boundary: %zu edge heights, %zu ordinary",
          edges, steady_only);

    // The seed the template must use across that boundary, resolved natively
    // and checked against the block the daemon actually has there.
    const std::uint64_t seed_h = rx_seedheight(G6::MD_HEIGHT);
    CHECK(seed_h == G6::SEED_HEIGHT, "rx_seedheight(%llu) = %llu",
          (unsigned long long)G6::MD_HEIGHT, (unsigned long long)seed_h);
    const G6::GoldenHeader* seed_row = nullptr;
    for (std::size_t i = 0; i < G6::EPOCH_WINDOW_COUNT; ++i)
        if (G6::EPOCH_WINDOW[i].height == G6::SEED_HEIGHT) seed_row = &G6::EPOCH_WINDOW[i];
    CHECK(seed_row != nullptr && std::string(seed_row->hash) == std::string(G6::SEED_ID),
          "the block at the seed height is the id monerod reported as seed_hash");
    CHECK(std::string(G6::SEED_ID) == std::string(G6::MD_SEED_HASH),
          "and get_miner_data's seed_hash is that same id");

    // PenaltyZone is claimed only when the median is known: an unknown median
    // must not manufacture a class (a false class is a false coverage claim).
    ClassifierInputs p;
    p.height = 100;
    p.block_weight = 500000;
    p.effective_median = 0;
    CHECK(!has_class(classify(p), HeightClass::PenaltyZone),
          "an unknown effective median makes no PenaltyZone claim");
    p.effective_median = 300000;
    CHECK(has_class(classify(p), HeightClass::PenaltyZone),
          "a block above the known median is PenaltyZone");
}

// ===========================================================================
// F. TEMPLATE, seam 2: the real C4 native source against the live capture.
// ===========================================================================
void suite_template_seam() {
    std::printf("== F. TEMPLATE: NativeMinerDataSource vs the captured get_miner_data ==\n");

    // The native arm, over C2c's real IChainView seeded at the captured tip.
    ChainRow tip;
    tip.height                = G6::TIP_HEIGHT;
    tip.id                    = hash_from_hex(G6::TIP_ID);
    tip.prev_id               = hash_from_hex(G6::TIP_PREV_ID);
    tip.timestamp             = G6::TIP_TIMESTAMP;
    tip.major_version         = G6::TIP_MAJOR_VERSION;
    tip.minor_version         = G6::TIP_MAJOR_VERSION;
    tip.block_weight          = G6::TIP_BLOCK_WEIGHT;
    tip.long_term_weight      = G6::TIP_LONG_TERM_WEIGHT;
    tip.difficulty            = u128_of(G6::STEADY[G6::STEADY_COUNT - 1].difficulty_lo,
                                        G6::STEADY[G6::STEADY_COUNT - 1].difficulty_hi);
    tip.cumulative_difficulty = g_roll.cum;
    tip.already_generated_coins = g_roll.agc;
    tip.pow_verified          = true;

    std::vector<std::pair<std::uint64_t, Hash>> seed_ids;
    seed_ids.emplace_back(G6::SEED_HEIGHT, hash_from_hex(G6::SEED_ID));
    seed_ids.emplace_back(G6::PREV_SEED_HEIGHT, hash_from_hex(G6::PREV_SEED_ID));

    ChainStateView view{XmrNet::Stagenet};
    view.seed_direct(tip, g_roll.diff_rows, g_roll.shortw, g_roll.longw, g_roll.times, seed_ids);
    view.set_synced(true);

    fakes::FakeTxpool pool;                 // the captured backlog was empty too
    tmpl::NativeMinerDataSource native(view, pool);

    // The monerod arm: the production decode path over the VERBATIM capture.
    CannedRpc rpc;
    rpc.set("get_miner_data", G6::MINER_DATA_RAW_JSON);
    tmpl::MonerodMinerDataSource daemon(rpc);
    CHECK(daemon.poll(), "the monerod arm parsed the captured get_miner_data");

    std::string why;
    const auto nat_md = native.snapshot(&why);
    CHECK(nat_md.has_value(), "the native arm produced a snapshot (%s)", why.c_str());
    const auto dae_md = daemon.snapshot(&why);
    CHECK(dae_md.has_value(), "the monerod arm produced a snapshot");
    if (!nat_md || !dae_md) return;

    CompareOptions opt;
    opt.classes.height = nat_md->height;
    opt.context = "live stagenet capture";
    const SeamResult res = compare_seam(TEMPLATE_SEAM,
                                        template_observation("native", *nat_md),
                                        template_observation("monerod", *dae_md), opt);
    if (g_verbose) std::printf("%s", render_sample(res).c_str());

    CHECK(res.sample.verdict == ParityVerdict::Clean,
          "the native template inputs are byte-identical to the daemon's: %s (%s)",
          to_string(res.sample.verdict), res.sample.note.c_str());
    CHECK(res.equality_compared == 6 && res.equality_absent == 0,
          "all 6 required template fields compared (%zu compared, %zu absent)",
          res.equality_compared, res.equality_absent);

    // The individual claims, spelled out, so a regression names itself.
    CHECK(nat_md->height == G6::MD_HEIGHT, "height %llu", (unsigned long long)nat_md->height);
    CHECK(nat_md->difficulty.lo == G6::MD_DIFFICULTY_LO && nat_md->difficulty.hi == 0,
          "difficulty %llu (derived over 735 rows)", (unsigned long long)nat_md->difficulty.lo);
    CHECK(nat_md->median_weight == G6::MD_MEDIAN_WEIGHT, "median weight");
    CHECK(nat_md->already_generated_coins == G6::MD_ALREADY_GENERATED_COINS,
          "already_generated_coins %llu", (unsigned long long)nat_md->already_generated_coins);
    CHECK(nat_md->seed_hash == hash_from_hex(G6::MD_SEED_HASH), "seed hash");
    CHECK(nat_md->major_version == G6::MD_MAJOR_VERSION, "major version");
    CHECK(nat_md->median_timestamp != 0,
          "the native arm carries a median timestamp the daemon does not report");

    // median_timestamp is a CONSTRAINT, not an EQUALITY: monerod has no RPC for
    // it, so it must never fail a sample by being absent on that side.
    CHECK(dae_md->median_timestamp == 0, "the monerod arm reports no median timestamp");
    CHECK(res.sample.verdict == ParityVerdict::Clean,
          "and its absence on one side does not fail the sample");

    // A shadow arm on a different tip must VOID, never fail: different tips are
    // different questions.
    node::MinerData stale = *dae_md;
    stale.height  -= 1;
    stale.prev_id = hash_from_hex(G6::TIP_PREV_ID);
    const SeamResult v = compare_seam(TEMPLATE_SEAM,
                                      template_observation("native", *nat_md),
                                      template_observation("monerod", stale), opt);
    CHECK(v.sample.verdict == ParityVerdict::Void, "a shadow arm one block behind VOIDS the sample");
    CHECK(v.sample.note.find("alignment") != std::string::npos, "and says it was alignment");
}

// ===========================================================================
// G. SUBMIT, seam 3.
// ===========================================================================
void suite_submit() {
    std::printf("== G. SUBMIT: acceptance oracles, and what counts as one ==\n");

    const Hash ours   = hash_from_hex(G6::TIP_ID);
    const Hash theirs = hash_from_hex(G6::TIP_PREV_ID);

    auto verdict = [&](bool armed, bool accepted, bool rejected, std::size_t peers) {
        BlockRelayVerdict v;
        v.block_id        = ours;
        v.daemon_armed    = armed;
        v.daemon_accepted = accepted;
        v.daemon_rejected = rejected;
        v.p2p_peers_sent  = peers;
        v.landed_first    = peers ? "p2p" : (accepted ? "daemon" : "");
        if (!v.reached_network()) v.why = "no peers and no daemon";
        return v;
    };

    // 1. daemon accepted, no confirmation watch: one oracle, CLEAN.
    {
        SubmitEvidence e; e.height = G6::TIP_HEIGHT;
        const SeamResult r = judge_submit(verdict(true, true, false, 4), e);
        CHECK(r.sample.verdict == ParityVerdict::Clean, "daemon accepted -> CLEAN (%s)",
              r.sample.note.c_str());
        CHECK(r.equality_required == 1 && r.equality_compared == 1, "exactly one oracle was armed");
    }
    // 2. daemon rejected: FAIL.
    {
        SubmitEvidence e; e.height = G6::TIP_HEIGHT;
        const SeamResult r = judge_submit(verdict(true, false, true, 4), e);
        CHECK(r.sample.verdict == ParityVerdict::Fail, "daemon rejected -> FAIL");
        CHECK(!r.sentinel_tripped, "a plain rejection is not yet a revocation sentinel");
    }
    // 3. daemon rejected AND another block landed within 60 s: sentinel.
    {
        SubmitEvidence e;
        e.height = G6::TIP_HEIGHT;
        e.other_block_landed_within_60s = true;
        const SeamResult r = judge_submit(verdict(true, false, true, 4), e);
        CHECK(r.sample.verdict == ParityVerdict::Fail && r.sentinel_tripped,
              "rejected while another block landed -> sentinel (the block was bad, not raced)");
    }
    // 4. P2P only, no confirmation: relaying is NOT acceptance.
    {
        SubmitEvidence e; e.height = G6::TIP_HEIGHT;
        const SeamResult r = judge_submit(verdict(false, false, false, 8), e);
        CHECK(r.sample.verdict == ParityVerdict::Void,
              "8 peers written to and no acceptance oracle -> VOID, never CLEAN");
        CHECK(r.sample.note.find("not evidence") != std::string::npos,
              "and says why: %s", r.sample.note.c_str());
    }
    // 5. P2P only WITH a confirmation watch that confirmed: that IS an oracle.
    {
        SubmitEvidence e;
        e.height = G6::TIP_HEIGHT;
        e.confirmation_watch_armed = true;
        e.confirmed = true;
        e.confirmed_id = ours;
        const SeamResult r = judge_submit(verdict(false, false, false, 8), e);
        CHECK(r.sample.verdict == ParityVerdict::Clean,
              "P2P-only plus an on-chain confirmation -> CLEAN (the M5 shape)");
    }
    // 6. confirmation watch armed but nothing confirmed yet: incomplete -> VOID.
    {
        SubmitEvidence e;
        e.height = G6::TIP_HEIGHT;
        e.confirmation_watch_armed = true;
        const SeamResult r = judge_submit(verdict(true, true, false, 8), e);
        CHECK(r.sample.verdict == ParityVerdict::Void,
              "one of two armed oracles reported -> VOID, not a partial CLEAN");
    }
    // 7. a DIFFERENT block confirmed at our height.
    {
        SubmitEvidence e;
        e.height = G6::TIP_HEIGHT;
        e.confirmation_watch_armed = true;
        e.confirmed = true;
        e.confirmed_id = theirs;
        const SeamResult r = judge_submit(verdict(true, true, false, 8), e);
        CHECK(r.sample.verdict == ParityVerdict::Fail && r.sentinel_tripped,
              "a different block id at our height -> FAIL + sentinel");
    }
    // 8. reached nobody: a lost find, never silent.
    {
        SubmitEvidence e; e.height = G6::TIP_HEIGHT;
        const SeamResult r = judge_submit(verdict(true, false, false, 0), e);
        CHECK(r.sample.verdict == ParityVerdict::Fail,
              "a block that reached no arm is a FAIL, not a shrug");
        CHECK(r.sample.note.find("reached no arm") != std::string::npos, "and names the loss");
    }
    // 9. reached nobody AND no oracle armed: still a FAIL. This is the ordering
    //    case -- "no acceptance oracle" is VOID, but a lost block does not need
    //    an oracle to be a lost block, and filing it under "nothing to judge"
    //    would be the never-silent-drop rule inverted.
    {
        SubmitEvidence e; e.height = G6::TIP_HEIGHT;
        const SeamResult r = judge_submit(verdict(false, false, false, 0), e);
        CHECK(r.sample.verdict == ParityVerdict::Fail,
              "a lost block with no oracle armed is still a FAIL, not a VOID");
        CHECK(r.sample.note.find("reached no arm") != std::string::npos,
              "and the loss is still named: %s", r.sample.note.c_str());
    }
}

// ===========================================================================
// H. THE NON-VACUITY CONTROL.
// ===========================================================================
void suite_non_vacuity() {
    std::printf("== H. non-vacuity: one unit of divergence must FAIL, every field ==\n");

    // ---- H.1 TIP: perturb each required field by one unit ------------------
    const G6::GoldenHeader& r = G6::STEADY[G6::STEADY_COUNT - 1];
    ChainRow row;
    row.height                = r.height;
    row.id                    = hash_from_hex(r.hash);
    row.prev_id               = hash_from_hex(r.prev_hash);
    row.timestamp             = r.timestamp;
    row.major_version         = r.major_version;
    row.block_weight          = r.block_weight;
    row.long_term_weight      = r.long_term_weight;
    row.difficulty            = u128_of(r.difficulty_lo, r.difficulty_hi);
    row.cumulative_difficulty = u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi);
    row.reward                = r.reward;

    const ArmObservation daemon = monerod_row_observation(r);
    CHECK(compare_seam(TIP_SEAM, native_tip_observation(row), daemon).sample.verdict
              == ParityVerdict::Clean,
          "control: the unperturbed pair is CLEAN");

    struct Perturb { const char* field; ChainRow row; };
    std::vector<Perturb> cases;
    {
        Perturb p{"id", row};                    p.row.id[31]  ^= 0x01; cases.push_back(p);
        Perturb q{"prev_id", row};               q.row.prev_id[0] ^= 0x01; cases.push_back(q);
        Perturb a{"cumulative_difficulty", row}; a.row.cumulative_difficulty.lo += 1; cases.push_back(a);
        Perturb b{"difficulty", row};            b.row.difficulty.lo += 1; cases.push_back(b);
        Perturb c{"timestamp", row};             c.row.timestamp += 1; cases.push_back(c);
        Perturb d{"reward", row};                d.row.reward += 1; cases.push_back(d);
        Perturb e{"block_weight", row};          e.row.block_weight += 1; cases.push_back(e);
        Perturb f{"long_term_weight", row};      f.row.long_term_weight += 1; cases.push_back(f);
        Perturb g{"major_version", row};         g.row.major_version += 1; cases.push_back(g);
    }
    CHECK(cases.size() == TIP_SEAM.required_equality_count(),
          "the control perturbs every one of the %zu required TIP fields", cases.size());

    for (const Perturb& p : cases) {
        const SeamResult res = compare_seam(TIP_SEAM, native_tip_observation(p.row), daemon);
        const bool named = [&] {
            for (const FieldDiff& d : res.sample.fields) if (d.field == p.field) return true;
            return false;
        }();
        // prev_id is also the alignment key: a divergence there means the two
        // arms are describing different blocks, which is VOID by design. Every
        // other field must FAIL.
        if (std::strcmp(p.field, "prev_id") == 0) {
            CHECK(res.sample.verdict == ParityVerdict::Void,
                  "one bit in prev_id (the alignment key) -> VOID, not a false CLEAN");
        } else {
            CHECK(res.sample.verdict == ParityVerdict::Fail && named,
                  "one unit in %s -> FAIL, and the diff names it", p.field);
        }
        CHECK_Q(res.sample.verdict != ParityVerdict::Clean,
                "%s perturbation was scored CLEAN", p.field);
    }

    // A one-unit divergence in the TOP limb of a 128-bit value must fail too:
    // a comparator that truncated to 64 bits would pass this.
    {
        ChainRow hi = row;
        hi.cumulative_difficulty.hi += 1;
        const SeamResult res = compare_seam(TIP_SEAM, native_tip_observation(hi), daemon);
        CHECK(res.sample.verdict == ParityVerdict::Fail,
              "one unit in the TOP limb of cumulative difficulty -> FAIL");
    }

    // ---- H.2 an ANSWERED-BUT-EMPTY required field is a FAIL, not a pass ----
    for (std::size_t i = 0; i < TIP_SEAM.count; ++i) {
        const FieldSpec& f = TIP_SEAM.fields[i];
        if (f.regime != Regime::Equality || !f.required) continue;
        ArmObservation holed = daemon;
        holed.fields.set(f.name, Obs::absent());
        const SeamResult res = compare_seam(TIP_SEAM, native_tip_observation(row), holed);
        CHECK(res.sample.verdict == ParityVerdict::Fail,
              "%s absent on one arm -> FAIL (a missing comparison is not a passing one)", f.name);
        CHECK_Q(res.equality_absent == 1 && res.absent_required.size() == 1
                    && res.absent_required[0] == f.name,
                "%s absence is attributed to the field", f.name);
    }

    // Both arms missing the same field is still not agreement.
    {
        ArmObservation a = native_tip_observation(row), b = daemon;
        a.fields.set("reward", Obs::absent());
        b.fields.set("reward", Obs::absent());
        const SeamResult res = compare_seam(TIP_SEAM, a, b);
        CHECK(res.sample.verdict == ParityVerdict::Fail,
              "two absences do not make an agreement");
    }

    // ---- H.3 an arm that produced nothing is VOID, never CLEAN -------------
    {
        const SeamResult res = compare_seam(TIP_SEAM,
                                            no_observation("native", "index not synced"), daemon);
        CHECK(res.sample.verdict == ParityVerdict::Void, "a silent arm -> VOID");
        CHECK(res.equality_compared == 0, "and compared nothing");
        CHECK(res.sample.note.find("index not synced") != std::string::npos,
              "and carries the arm's own reason");
    }

    // ---- H.4 an empty required set can never be agreement ------------------
    {
        static constexpr FieldSpec kEmpty[] = {
            {"height", Regime::AlignmentKey, false, false},
            {"noise",  Regime::Measurement,  false, false},
        };
        const SeamSpec empty{ProbeKind::Tip, kEmpty, 2};
        const SeamResult res = compare_seam(empty, native_tip_observation(row), daemon);
        CHECK(res.sample.verdict == ParityVerdict::Void,
              "a seam with no required EQUALITY field is VOID, never CLEAN");
        CHECK(res.sample.note.find("refusing") != std::string::npos,
              "and refuses explicitly: %s", res.sample.note.c_str());
    }

    // ---- H.5 TEMPLATE: one unit in every required field --------------------
    {
        node::MinerData md;
        md.major_version = G6::MD_MAJOR_VERSION;
        md.height        = G6::MD_HEIGHT;
        md.prev_id       = hash_from_hex(G6::MD_PREV_ID);
        md.seed_hash     = hash_from_hex(G6::MD_SEED_HASH);
        md.difficulty    = u128_of(G6::MD_DIFFICULTY_LO, G6::MD_DIFFICULTY_HI);
        md.median_weight = G6::MD_MEDIAN_WEIGHT;
        md.already_generated_coins = G6::MD_ALREADY_GENERATED_COINS;
        md.median_timestamp = G6::TIP_TIMESTAMP - 300;

        const ArmObservation base = template_observation("monerod", md);
        CHECK(compare_seam(TEMPLATE_SEAM, template_observation("native", md), base)
                  .sample.verdict == ParityVerdict::Clean,
              "control: the unperturbed template pair is CLEAN");

        struct T { const char* field; node::MinerData md; };
        std::vector<T> ts;
        { T a{"major_version", md};           a.md.major_version += 1; ts.push_back(a); }
        { T b{"difficulty", md};              b.md.difficulty.lo += 1; ts.push_back(b); }
        { T c{"seed_hash", md};               c.md.seed_hash[7] ^= 0x01; ts.push_back(c); }
        { T d{"median_weight", md};           d.md.median_weight += 1; ts.push_back(d); }
        { T e{"already_generated_coins", md}; e.md.already_generated_coins += 1; ts.push_back(e); }
        { T f{"prev_id", md};                 f.md.prev_id[3] ^= 0x01; ts.push_back(f); }

        CHECK(ts.size() == TEMPLATE_SEAM.required_equality_count(),
              "the control perturbs every one of the %zu required TEMPLATE fields", ts.size());
        for (const T& t : ts) {
            const SeamResult res = compare_seam(TEMPLATE_SEAM,
                                                template_observation("native", t.md), base);
            if (std::strcmp(t.field, "prev_id") == 0) {
                CHECK(res.sample.verdict == ParityVerdict::Void,
                      "one bit in the template prev_id (alignment key) -> VOID");
            } else {
                CHECK(res.sample.verdict == ParityVerdict::Fail,
                      "one unit in template %s -> FAIL", t.field);
            }
            CHECK_Q(res.sample.verdict != ParityVerdict::Clean,
                    "template %s perturbation was scored CLEAN", t.field);
        }

        // ---- H.6 SERVED-MISMATCH outranks everything ----------------------
        node::MinerData served = md;
        served.median_weight += 1;                   // what went out
        ArmObservation arm_own = template_observation("native", md);   // what the arm says
        CompareOptions opt;
        opt.serving_arm_cross_check = &arm_own;
        const SeamResult sm = compare_seam(TEMPLATE_SEAM,
                                           template_observation("native", served), base, opt);
        CHECK(sm.sample.verdict == ParityVerdict::ServedMismatch,
              "serving something the arm would not have produced -> SERVED-MISMATCH");
        CHECK(sm.sample.note.find("SERVED") != std::string::npos, "and says so");

        // The cross-check must be SILENT when the arm's epoch has moved: the
        // oracle simply does not supply it, and the sample stays judgeable.
        CompareOptions opt2;
        opt2.serving_arm_cross_check = nullptr;
        CHECK(compare_seam(TEMPLATE_SEAM, template_observation("native", md), base, opt2)
                  .sample.verdict == ParityVerdict::Clean,
              "with no cross-check available the sample is still judged on its own merits");
    }

    // ---- H.7 an INVARIANT violation fails even when both arms agree --------
    {
        CompareOptions opt;
        opt.invariants.push_back(NamedCheck{"exact_sum_reward", false, "coinbase != base + fees"});
        const SeamResult res = compare_seam(TIP_SEAM, native_tip_observation(row), daemon, opt);
        CHECK(res.sample.verdict == ParityVerdict::Fail,
              "two arms agreeing on a number we computed wrongly is still a FAIL");
    }
}

// ===========================================================================
// I. The ledger: keys, coverage floors, void accounting, persistence.
// ===========================================================================
SeamResult make_sample(ProbeKind k, std::uint64_t h, ParityVerdict v,
                       std::size_t required, std::size_t compared,
                       std::vector<HeightClass> cls = {HeightClass::Steady}) {
    SeamResult r;
    r.sample.kind    = k;
    r.sample.height  = h;
    r.sample.verdict = v;
    r.sample.classes = std::move(cls);
    r.equality_required = required;
    r.equality_compared = compared;
    r.equality_equal    = compared;
    return r;
}

void suite_ledger() {
    std::printf("== I. the graduation ledger ==\n");

    GraduationKey key{"deadbeef", COMPARATOR_VERSION, "0.18.5.1-release", "stagenet"};
    GraduationPolicy pol = GraduationPolicy::regtest_fast();

    // --- void never counts as agreement -----------------------------------
    {
        GraduationLedger led(key, pol);
        for (int i = 0; i < 50; ++i)
            led.record(make_sample(ProbeKind::Tip, 100 + i, ParityVerdict::Void, 9, 0), 1000 + i);
        CHECK(led.seam(ProbeKind::Tip).clean == 0 && led.seam(ProbeKind::Tip).samples == 0,
              "50 VOID samples are 0 judged samples and 0 clean");
        CHECK(led.seam(ProbeKind::Tip).voided == 50, "and 50 voids");
        CHECK(led.state() != GraduationState::Graduated, "nothing graduates on void");
        CHECK(!led.shortfalls(1100).empty(), "and the shortfall list says what is missing");
    }

    // --- a void breaks nothing but proves nothing -------------------------
    {
        GraduationLedger led(key, pol);
        for (int i = 0; i < 5; ++i)
            led.record(make_sample(ProbeKind::Tip, 200 + i, ParityVerdict::Clean, 9, 9), 2000 + i);
        led.record(make_sample(ProbeKind::Tip, 205, ParityVerdict::Void, 9, 0), 2005);
        CHECK(led.seam(ProbeKind::Tip).clean_streak == 5,
              "a VOID does not break a clean streak (it is not a failure)");
        led.record(make_sample(ProbeKind::Tip, 206, ParityVerdict::Fail, 9, 9), 2006);
        CHECK(led.seam(ProbeKind::Tip).clean_streak == 0, "a FAIL does");
        CHECK(led.seam(ProbeKind::Tip).best_clean_streak == 5, "and the best streak is remembered");
    }

    // --- the per-field coverage floor is what blocks a vacuous pass -------
    {
        GraduationLedger led(key, pol);
        // Plenty of samples, plenty of clean, but the fields were never
        // actually compared: this is the exact shape of a probe that agreed
        // with itself, and the ledger must refuse it.
        for (int i = 0; i < 40; ++i) {
            SeamResult r = make_sample(ProbeKind::Tip, 300 + i, ParityVerdict::Clean, 0, 0);
            led.record(r, 3000 + i * 10);
        }
        const std::vector<std::string> missing = led.shortfalls(3400);
        bool names_a_field = false;
        for (const std::string& m : missing)
            if (m.find("field '") != std::string::npos) names_a_field = true;
        CHECK(led.state() != GraduationState::Graduated,
              "40 clean samples that compared nothing do not graduate");
        CHECK(names_a_field, "and the reason names an uncompared field");
    }

    // --- a tip run must NOT satisfy the template seam's coverage floor ------
    // The two tables share three field NAMES. Before coverage was seam-keyed,
    // 58 tip samples made TEMPLATE.difficulty read as fully covered while the
    // template seam had produced nothing at all.
    {
        GraduationLedger led(key, pol);
        for (int i = 0; i < 40; ++i)
            led.record(make_sample(ProbeKind::Tip, 800 + i, ParityVerdict::Clean, 9, 9), 8000 + i);
        for (const char* shared : {"difficulty", "prev_id", "major_version"}) {
            auto tip_it = led.fields().find(field_key(ProbeKind::Tip, shared));
            auto tpl_it = led.fields().find(field_key(ProbeKind::Template, shared));
            CHECK(tip_it != led.fields().end() && tip_it->second.compared == 40,
                  "TIP.%s was compared 40 times", shared);
            CHECK(tpl_it == led.fields().end() || tpl_it->second.compared == 0,
                  "and TEMPLATE.%s is still uncovered: a tip run is not template evidence",
                  shared);
        }
        bool blocks_template = false;
        for (const std::string& m : led.shortfalls(8100))
            if (m.find("TEMPLATE.difficulty") != std::string::npos) blocks_template = true;
        CHECK(blocks_template, "and the uncovered template field is named as a shortfall");
    }

    // --- key hardness -------------------------------------------------------
    {
        GraduationLedger led(key, pol);
        for (int i = 0; i < 30; ++i)
            led.record(make_sample(ProbeKind::Tip, 400 + i, ParityVerdict::Clean, 9, 9), 4000 + i);
        const std::string json = led.to_json();

        GraduationLedger same(key, pol);
        std::string why;
        CHECK(same.from_json(json, &why), "a ledger reloads under its own key");
        CHECK(same.seam(ProbeKind::Tip).clean == 30, "with its counters intact");

        for (const GraduationKey& other : std::vector<GraduationKey>{
                 {"cafebabe", COMPARATOR_VERSION, "0.18.5.1-release", "stagenet"},
                 {"deadbeef", COMPARATOR_VERSION, "0.18.4.0-release", "stagenet"},
                 {"deadbeef", COMPARATOR_VERSION, "0.18.5.1-release", "mainnet"},
             }) {
            GraduationLedger foreign(other, pol);
            std::string w;
            CHECK(!foreign.from_json(json, &w),
                  "a ledger written under a different key is DISCARDED (%s)", other.net.c_str());
            CHECK_Q(w.find("key mismatch") != std::string::npos, "and says why");
            CHECK_Q(foreign.seam(ProbeKind::Tip).clean == 0, "and inherits nothing");
        }

        // A different comparator version is a different experiment even with
        // the same commit and daemon. The constructor forces the running
        // version, so a hand-edited file cannot smuggle a streak forward.
        GraduationKey bumped = key;
        bumped.comparator_version = COMPARATOR_VERSION + 1;
        std::string forged = json;
        const std::string k = "\"comparator_version\": " + std::to_string(COMPARATOR_VERSION);
        const auto p = forged.find(k);
        if (p != std::string::npos)
            forged.replace(p, k.size(), "\"comparator_version\": "
                                        + std::to_string(COMPARATOR_VERSION + 1));
        GraduationLedger v2(key, pol);
        std::string w2;
        CHECK(!v2.from_json(forged, &w2),
              "a ledger claiming another comparator version is discarded");
    }

    // --- revocation is terminal for the key --------------------------------
    {
        GraduationLedger led(key, GraduationPolicy::regtest_fast());
        led.revoke("major_version changed under us", 5000);
        CHECK(led.state() == GraduationState::Revoked, "revoked");
        for (int i = 0; i < 100; ++i)
            led.record(make_sample(ProbeKind::Tip, 500 + i, ParityVerdict::Clean, 9, 9), 5001 + i);
        CHECK(led.state() == GraduationState::Revoked,
              "and no amount of subsequent agreement un-revokes it");
        CHECK(led.shortfalls(6000).size() == 1
                  && led.shortfalls(6000)[0].find("REVOKED") == 0,
              "the gate says REVOKED and nothing else");
    }

    // --- a sentinel in a sample revokes on the spot ------------------------
    {
        GraduationLedger led(key, GraduationPolicy::regtest_fast());
        SeamResult r = make_sample(ProbeKind::Tip, 600, ParityVerdict::Fail, 9, 9);
        r.sentinel_tripped = true;
        r.sentinel_why = "sentinel field 'major_version' differed: 16 vs 17";
        led.record(r, 6000);
        CHECK(led.state() == GraduationState::Revoked, "a sentinel revokes immediately");
        CHECK(!led.revocations().empty()
                  && led.revocations().back().second.find("major_version") != std::string::npos,
              "and the reason is recorded verbatim");
    }

    // --- persistence round trip on disk ------------------------------------
    {
        GraduationLedger led(key, pol);
        for (int i = 0; i < 12; ++i)
            led.record(make_sample(ProbeKind::Template, 700 + i, ParityVerdict::Clean, 6, 6), 7000 + i);
        const std::string path = "xmr_parity_ledger_kat.json";
        std::string why;
        CHECK(led.save(path, &why), "the ledger saves (%s)", why.c_str());
        GraduationLedger back(key, pol);
        CHECK(back.load(path, &why), "and loads");
        CHECK(back.seam(ProbeKind::Template).clean == 12, "with the template counters intact");
        std::remove(path.c_str());
        GraduationLedger absent(key, pol);
        CHECK(!absent.load("no_such_parity_ledger.json", &why) && why.empty(),
              "a missing ledger is not an error: an un-run experiment is ungraduated");
        CHECK(GraduationLedger::default_path("/var/lib/c2pool", "stagenet")
                  == "/var/lib/c2pool/stagenet/xmr_parity_ledger.json",
              "the conventional path is <config>/<net>/xmr_parity_ledger.json");
    }
}

// ===========================================================================
// J. The oracle end to end: hot-path discipline, heartbeat, graduation.
// ===========================================================================
class StubTip final : public ITipObserver {
public:
    ArmObservation next;
    ArmObservation observe() override { return next; }
};

void suite_oracle() {
    std::printf("== J. ParityOracle end to end ==\n");

    std::vector<std::string> log;
    auto sink = [&log](const std::string& s) { log.push_back(s); };

    StubTip nat, dae;
    ParityOracle::Deps deps;
    deps.native_tip  = &nat;
    deps.monerod_tip = &dae;

    ParityOracleConfig cfg;
    cfg.heartbeat_interval_s = 10;
    cfg.autosave_every = 0;

    GraduationKey key{"kat", COMPARATOR_VERSION, G6::MONEROD_VERSION, G6::NETWORK};
    ParityOracle oracle(deps, key, GraduationPolicy::regtest_fast(), cfg, fake_now, sink);

    // --- the heartbeat fires with NO SAMPLES ------------------------------
    g_clock = 1789000000ull;
    oracle.drain();
    bool saw_no_samples = false;
    for (const std::string& l : log) if (l.find("status=NO-SAMPLES") != std::string::npos) saw_no_samples = true;
    CHECK(saw_no_samples, "a drain with nothing to do emits status=NO-SAMPLES");
    CHECK(oracle.coverage().no_samples_streak >= 1, "and the no-sample streak rises");
    CHECK(oracle.attempts() >= 1, "attempts is counted unconditionally");

    // --- the hot path only enqueues ---------------------------------------
    node::MainchainEvent ev;
    ev.kind = node::MainchainEventKind::Extend;
    ev.block.height = G6::TIP_HEIGHT;
    ev.block.id = hash_from_hex(G6::TIP_ID);
    const ParityCoverage before = oracle.coverage();
    oracle.on_tip(ev, "native");
    oracle.on_tip(ev, "monerod");   // same height: coalesced, not queued twice
    CHECK(oracle.coverage().samples == before.samples,
          "on_tip did no work: the coverage did not move until drain()");

    // --- a real sustained run through the oracle --------------------------
    log.clear();
    std::size_t drained = 0;
    NativeRoll roll;
    roll.seed();
    roll_over_c4(roll, G4::ROWS_LAST_HEIGHT);
    for (std::size_t i = 0; i < G6::STEADY_COUNT; ++i) {
        const G6::GoldenHeader& r = G6::STEADY[i];
        if (r.height <= G4::ROWS_LAST_HEIGHT) continue;
        const Hash id = hash_from_hex(r.hash);
        const NativeRoll::Derived d =
            roll.connect(r.height, r.timestamp, r.block_weight, r.major_version, id);

        ChainRow row;
        row.height = r.height; row.id = id; row.prev_id = hash_from_hex(r.prev_hash);
        row.timestamp = r.timestamp; row.major_version = r.major_version;
        row.block_weight = r.block_weight; row.long_term_weight = d.long_term_weight;
        row.difficulty = d.difficulty; row.cumulative_difficulty = d.cumulative_difficulty;
        row.reward = (r.num_txes == 0) ? d.base_reward : r.reward;

        nat.next = native_tip_observation(row);
        dae.next = monerod_row_observation(r);

        node::MainchainEvent e;
        e.block.height = r.height;
        e.block.id     = id;
        g_clock += 120;
        oracle.on_tip(e, "native");
        const std::vector<SeamResult> out = oracle.drain();
        for (const SeamResult& s : out) {
            CHECK_Q(s.sample.verdict == ParityVerdict::Clean,
                    "oracle h=%llu -> %s", (unsigned long long)r.height,
                    to_string(s.sample.verdict));
            ++drained;
        }
    }
    CHECK(drained >= 55, "%zu tip samples went through the oracle", drained);
    CHECK(oracle.coverage().fail == 0 && oracle.coverage().served_mismatch == 0,
          "with no failures");

    // Not graduated: the TEMPLATE and SUBMIT seams have produced nothing, and
    // two green seams out of three is exactly the false pass this refuses.
    CHECK(!oracle.graduated(), "three seams are required: TIP alone does not graduate");
    const std::string report_before = oracle.verdict_report();
    CHECK(report_before.find("NOT GRADUATED") != std::string::npos, "the verdict says so");
    CHECK(report_before.find("TEMPLATE") != std::string::npos, "and names the empty seam");
    // The deliverable itself, shown rather than only asserted on: this is what
    // an operator reads to decide whether monerod may be demoted, and it is
    // worth being able to look at without attaching a debugger.
    if (g_verbose) std::printf("\n%s\n", report_before.c_str());

    // --- feed the other two seams -----------------------------------------
    {
        node::MinerData md;
        md.major_version = G6::MD_MAJOR_VERSION;
        md.height        = G6::MD_HEIGHT;
        md.prev_id       = hash_from_hex(G6::MD_PREV_ID);
        md.seed_hash     = hash_from_hex(G6::MD_SEED_HASH);
        md.difficulty    = u128_of(G6::MD_DIFFICULTY_LO, G6::MD_DIFFICULTY_HI);
        md.median_weight = G6::MD_MEDIAN_WEIGHT;
        md.already_generated_coins = G6::MD_ALREADY_GENERATED_COINS;
        md.median_timestamp = G6::TIP_TIMESTAMP - 300;

        // A shadow arm holding exactly the daemon's captured answer.
        CannedRpc rpc;
        rpc.set("get_miner_data", G6::MINER_DATA_RAW_JSON);
        tmpl::MonerodMinerDataSource shadow(rpc);
        CHECK(shadow.poll(), "shadow arm polled");

        ParityOracle::Deps d2 = deps;
        d2.shadow_arm = &shadow;
        ParityOracle o2(d2, key, GraduationPolicy::regtest_fast(), cfg, fake_now, sink);

        MinerDataEpoch ep;
        ep.height = md.height;
        ep.prev_id = md.prev_id;
        for (int i = 0; i < 4; ++i) {
            g_clock += 30;
            o2.on_serve(ep, md, "native");
            const auto out = o2.drain();
            CHECK_Q(out.size() == 1 && out[0].sample.verdict == ParityVerdict::Clean,
                    "template sample %d is %s", i,
                    out.empty() ? "missing" : to_string(out[0].sample.verdict));
        }
        CHECK(o2.coverage().clean >= 4, "the template seam produced clean samples");

        // A served artefact that neither arm would have produced.
        node::MinerData bad = md;
        bad.median_weight += 1;
        g_clock += 30;
        o2.on_serve(ep, bad, "native");
        const auto out = o2.drain();
        CHECK(out.size() == 1 && out[0].sample.verdict == ParityVerdict::Fail,
              "serving a perturbed template is caught");
    }

    // --- a single divergence revokes a graduated ledger -------------------
    {
        GraduationLedger led(key, GraduationPolicy::regtest_fast());
        std::uint64_t t = 100000;
        for (int i = 0; i < 30; ++i)
            led.record(make_sample(ProbeKind::Tip, 900 + i, ParityVerdict::Clean, 9, 9,
                                   {HeightClass::Steady, HeightClass::EpochEdge}), t += 10);
        for (int i = 0; i < 12; ++i)
            led.record(make_sample(ProbeKind::Template, 900 + i, ParityVerdict::Clean, 6, 6,
                                   {HeightClass::Steady, HeightClass::EpochEdge}), t += 10);
        for (int i = 0; i < 12; ++i) {
            SeamResult s = make_sample(ProbeKind::Submit, 900 + i, ParityVerdict::Clean, 2, 2,
                                       {HeightClass::Steady, HeightClass::EpochEdge});
            led.record(s, t += 10);
        }
        // The per-field floor is the last thing to clear; feed enough samples.
        for (int i = 0; i < 60; ++i)
            led.record(make_sample(ProbeKind::Tip, 1000 + i, ParityVerdict::Clean, 9, 9,
                                   {HeightClass::Steady, HeightClass::EpochEdge}), t += 10);
        CHECK(led.state() == GraduationState::Graduated,
              "with all three seams green over the window, the ledger graduates");
        CHECK(led.shortfalls(t).empty(), "and lists no shortfall");
        const std::string rep = render_verdict(led, t);
        if (g_verbose) std::printf("\n%s\n", rep.c_str());
        CHECK(rep.find("GRADUATED") != std::string::npos, "the verdict report says GRADUATED");
        CHECK(rep.find("BLOCKER") == std::string::npos, "with no uncompared field");

        SeamResult bad = make_sample(ProbeKind::Tip, 2000, ParityVerdict::Fail, 9, 9);
        bad.sentinel_tripped = true;
        bad.sentinel_why = "sentinel field 'difficulty' differed";
        led.record(bad, t += 10);
        CHECK(led.state() == GraduationState::Revoked,
              "and ONE disagreement takes it away again");
    }
}

} // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i)
        if (std::strcmp(argv[i], "--verbose") == 0) g_verbose = true;

    std::printf("xmr_native_parity_kat -- C6 monerod-parity oracle\n");
    std::printf("capture: monerod %s %s, tip %llu, %zu steady + %zu epoch rows\n\n",
                G6::MONEROD_VERSION, G6::NETWORK,
                static_cast<unsigned long long>(G6::TIP_HEIGHT),
                G6::STEADY_COUNT, G6::EPOCH_WINDOW_COUNT);

    suite_absence();
    suite_table();
    suite_tip_rpc();
    suite_tip_derived();
    suite_epoch_edge();
    suite_template_seam();
    suite_submit();
    suite_non_vacuity();
    suite_ledger();
    suite_oracle();

    std::printf("\n%d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
