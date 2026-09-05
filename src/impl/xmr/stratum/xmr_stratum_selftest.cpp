/*
 * xmr_stratum_selftest.cpp — self-contained KAT / behavioural check for the
 * V37 Monero/RandomX stratum front-end. No network, no RandomX engine: fakes
 * stand in for the four seams. Exercises the wire (de)serialization goldens and
 * the full login/submit control flow, including the load-bearing details:
 * nonce inserted at offset 39, PoW recomputed (never trust the client result),
 * network-block vs lane-share vs low-diff branching, stale + invalid-job-id.
 *
 * This file is part of c2pool (frstrtr/c2pool).
 * Copyright (c) 2026 The c2pool developers.
 *
 * Licensed under the GNU Affero General Public License, version 3 or later.
 * See <https://www.gnu.org/licenses/>. WITHOUT ANY WARRANTY.
 *
 * Build (light, single-invocation):
 *   g++ -std=c++20 -O1 -Wall -Wextra xmr_stratum.cpp xmr_stratum_selftest.cpp \
 *       -o /tmp/xmr_stratum_selftest && /tmp/xmr_stratum_selftest
 */

#include "xmr_stratum.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace v37::xmr::stratum;

static int g_fail = 0;
static int g_pass = 0;
#define CHECK(cond, name) do { \
    if (cond) { ++g_pass; } \
    else { ++g_fail; std::printf("FAIL: %s  (line %d)\n", name, __LINE__); } \
} while (0)

// --- fake seams -------------------------------------------------------------
struct FakeTemplateSource : ITemplateSource {
    std::vector<std::uint8_t> base_blob;
    std::size_t nonce_offset = EXPECTED_NONCE_OFFSET_V16;
    std::uint32_t template_id = 7;
    std::uint64_t height = 3'000'000;
    std::uint64_t lane_target = 0x0000FFFFFFFFFFFFULL;      // easy
    std::uint64_t mainchain_target = 0x00000000000000FFULL; // hard
    std::array<std::uint8_t, HASH_SIZE> seed_hash{};
    bool have_next = true;
    std::array<std::uint8_t, HASH_SIZE> next_seed{};
    bool fail_rebuild = false;
    std::uint32_t last_extra_nonce = 0;

    FakeTemplateSource() {
        base_blob.assign(HASHING_BLOB_TYPICAL_SIZE, 0x11);
        for (std::size_t i = 0; i < NONCE_SIZE; ++i) base_blob[nonce_offset + i] = 0x00;
        seed_hash.fill(0xAA);
        next_seed.fill(0xBB);
    }
    void fill(TemplateJob& out, std::uint32_t extra_nonce) {
        out.blob = base_blob;                 // fresh copy each call
        out.nonce_offset = nonce_offset;
        out.template_id = template_id;
        out.height = height;
        out.lane_target = lane_target;
        out.mainchain_target = mainchain_target;
        out.seed_hash = seed_hash;
        if (have_next) out.next_seed_hash = next_seed;
        out.monero_major_version = 16;
        last_extra_nonce = extra_nonce;
    }
    bool get_job(std::uint32_t extra_nonce, TemplateJob& out) override {
        fill(out, extra_nonce); return true;
    }
    bool rebuild_blob(std::uint32_t tid, std::uint32_t extra_nonce, TemplateJob& out) override {
        if (fail_rebuild || tid != template_id) return false;
        fill(out, extra_nonce); return true;
    }
    std::uint32_t max_extra_nonces() const override { return 1u << 20; }
};

struct FakeVerifier : IPowVerifier {
    std::array<std::uint8_t, HASH_SIZE> preset{};
    std::vector<std::uint8_t> last_blob;   // captured to prove nonce insertion
    bool fail_hash = false;

    void set_top_word(std::uint64_t w) {
        preset.fill(0);
        for (int i = 0; i < 8; ++i)
            preset[HASH_SIZE - 8 + i] = static_cast<std::uint8_t>(w >> (8 * i));
    }
    bool randomx_hash(const std::uint8_t* blob, std::size_t n, std::uint64_t,
                      const std::array<std::uint8_t, HASH_SIZE>&,
                      std::array<std::uint8_t, HASH_SIZE>& out, bool) override {
        if (fail_hash) return false;
        last_blob.assign(blob, blob + n);
        out = preset;
        return true;
    }
    bool meets_target(const std::array<std::uint8_t, HASH_SIZE>& h,
                      std::uint64_t target) const override {
        std::uint64_t top = 0;
        for (int i = 0; i < 8; ++i)
            top |= static_cast<std::uint64_t>(h[HASH_SIZE - 8 + i]) << (8 * i);
        return top <= target;   // larger target == easier
    }
};

struct FakeSink : IShareSink {
    int accepted = 0;
    int network_submits = 0;
    AcceptedShare last;
    void on_accepted_share(const AcceptedShare& s) override { ++accepted; last = s; }
    void submit_network_block(std::uint32_t, std::uint32_t, std::uint32_t) override {
        ++network_submits;
    }
};

struct FakeTransport : ITransport {
    std::vector<std::string> lines;
    bool send_line(std::uint64_t, std::string_view l) override {
        lines.emplace_back(l); return true;
    }
    void close(std::uint64_t) override {}
    const std::string& last() const { return lines.back(); }
    void clear() { lines.clear(); }
};

static bool contains(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

// --- tests ------------------------------------------------------------------
static void test_hex_and_target() {
    std::uint8_t bytes[4]; std::uint8_t b0;
    CHECK(StratumDialect::from_hex_byte('0','a', b0) && b0 == 0x0a, "from_hex 0a");
    CHECK(StratumDialect::from_hex_byte('F','f', b0) && b0 == 0xff, "from_hex Ff");
    CHECK(!StratumDialect::from_hex_byte('g','0', b0), "from_hex reject g");
    bytes[0]=0xde; bytes[1]=0xad; bytes[2]=0xbe; bytes[3]=0xef;
    CHECK(StratumDialect::to_hex(bytes,4) == "deadbeef", "to_hex deadbeef");

    // full 8-byte target (small target / high diff): LE bytes
    CHECK(StratumDialect::encode_target(0x0000000012345678ULL) == "7856341200000000",
          "encode_target full-8");
    // exactly the limit (2^32) -> 4-byte compact high word
    CHECK(StratumDialect::encode_target(TARGET_4_BYTES_LIMIT) == "01000000",
          "encode_target compact @limit");
    // large target (low diff) -> 4-byte compact
    CHECK(StratumDialect::encode_target(0xABCD000100000000ULL) == "0100cdab",
          "encode_target compact large");
    // just below the limit -> full 8 bytes
    CHECK(StratumDialect::encode_target(0x00000000FFFFFFFFULL) == "ffffffff00000000",
          "encode_target full below-limit");
}

static void test_login_string() {
    auto a = StratumDialect::parse_login_string("48abcXYZ");
    CHECK(a.address == "48abcXYZ" && !a.custom_diff && a.worker.empty(), "login plain");
    auto b = StratumDialect::parse_login_string("48abc+5000");
    CHECK(b.address == "48abc" && b.custom_diff && *b.custom_diff == 5000 && b.worker.empty(),
          "login +diff");
    auto c = StratumDialect::parse_login_string("48abc.rig1");
    CHECK(c.address == "48abc" && !c.custom_diff && c.worker == "rig1", "login .worker");
    auto d = StratumDialect::parse_login_string("48abc+5000.rig1");
    CHECK(d.address == "48abc" && d.custom_diff && *d.custom_diff == 5000 && d.worker == "rig1",
          "login +diff.worker");
    auto e = StratumDialect::parse_login_string("48abc/rig2");
    CHECK(e.address == "48abc" && e.worker == "rig2", "login /worker");
}

static void test_submit_parse() {
    SubmitFields f;
    f.rpc_id = "cafebabe"; f.job_id = "00000001";
    f.nonce = "0a000000";  // LE bytes 0a 00 00 00 -> u32 0x0000000a
    f.result.assign(64, 'a');
    ParsedSubmit ps;
    CHECK(StratumDialect::parse_submit(f, ps) == SubmitError::None, "submit parse ok");
    CHECK(ps.job_id == 1, "submit job_id=1");
    CHECK(ps.nonce == 0x0000000aU, "submit nonce LE");
    CHECK(ps.result[0] == 0xaa && ps.result[31] == 0xaa, "submit result bytes");

    SubmitFields bad = f; bad.nonce = "0a0000";           // too short
    CHECK(StratumDialect::parse_submit(bad, ps) == SubmitError::MalformedField, "submit short nonce");
    bad = f; bad.result = std::string(62, 'a');            // wrong length
    CHECK(StratumDialect::parse_submit(bad, ps) == SubmitError::MalformedField, "submit short result");
    bad = f; bad.nonce = "0a0000zz";                        // bad hex
    CHECK(StratumDialect::parse_submit(bad, ps) == SubmitError::MalformedField, "submit bad hex");
    bad = f; bad.job_id = "00000000";                       // zero job id
    CHECK(StratumDialect::parse_submit(bad, ps) == SubmitError::InvalidJobId, "submit zero job id");
}

static void test_response_goldens() {
    CHECK(StratumDialect::build_status_ok(1) ==
          "{\"id\":1,\"jsonrpc\":\"2.0\",\"error\":null,\"result\":{\"status\":\"OK\"}}\n",
          "status_ok golden");
    CHECK(StratumDialect::build_error(1, "Stale share") ==
          "{\"id\":1,\"jsonrpc\":\"2.0\",\"error\":{\"message\":\"Stale share\"}}\n",
          "error golden");

    JobNotify j;
    j.blob.assign(4, 0x11);
    j.job_id = 1;
    j.target = 0x00000000FFFFFFFFULL;
    j.height = 3'000'000;
    j.seed_hash.fill(0xAA);
    j.next_seed_hash = std::array<std::uint8_t, HASH_SIZE>{}; j.next_seed_hash->fill(0xBB);
    std::string login_ok = StratumDialect::build_login_ok(42, 0xcafebabe, j);
    CHECK(contains(login_ok, "\"id\":42,"), "login_ok req id");
    CHECK(contains(login_ok, "\"id\":\"cafebabe\""), "login_ok rpc id hex");
    CHECK(contains(login_ok, "\"job_id\":\"00000001\""), "login_ok job id hex");
    CHECK(contains(login_ok, "\"algo\":\"rx/0\""), "login_ok algo rx/0");
    CHECK(contains(login_ok, "\"target\":\"ffffffff00000000\""), "login_ok target");
    CHECK(contains(login_ok, "\"seed_hash\":\"aaaaaaaa"), "login_ok seed_hash");
    CHECK(contains(login_ok, "\"next_seed_hash\":\"bbbbbbbb"), "login_ok next_seed_hash");
    CHECK(contains(login_ok, "\"extensions\":[\"algo\"],\"status\":\"OK\"}}\n"), "login_ok tail");

    std::string notify = StratumDialect::build_job_notify(j);
    CHECK(contains(notify, "\"method\":\"job\""), "notify method job");
    CHECK(contains(notify, "\"algo\":\"rx/0\""), "notify algo");
    CHECK(contains(notify, "\"next_seed_hash\":\"bbbbbbbb"), "notify next_seed_hash");
}

// Drive a full login then submit; returns the transport line for the submit.
static std::string do_submit(XmrStratumServer& srv, XmrStratumSession& s,
                             FakeTransport& tx, std::uint32_t nonce_u32) {
    SubmitFields f;
    f.rpc_id = "00000000";
    f.job_id = "00000001";  // job id 1, fixed-width u32 hex (matches u32_hex)
    std::uint8_t nb[4] = { static_cast<std::uint8_t>(nonce_u32),
                           static_cast<std::uint8_t>(nonce_u32 >> 8),
                           static_cast<std::uint8_t>(nonce_u32 >> 16),
                           static_cast<std::uint8_t>(nonce_u32 >> 24) };
    f.nonce = StratumDialect::to_hex(nb, 4);
    f.result.assign(64, '0');
    tx.clear();
    srv.handle_submit(s, 2, f);
    return tx.last();
}

static void test_submit_flow() {
    // --- accepted lane share (not a network block) ---
    {
        FakeTemplateSource ts; FakeVerifier vf; FakeSink sk; FakeTransport tx;
        XmrStratumServer srv(ts, vf, sk, tx);
        XmrStratumSession s(1);
        CHECK(srv.handle_login(s, 1, "48addr+100000.rig"), "login returns true");
        CHECK(s.logged_in(), "session logged in");
        CHECK(contains(tx.last(), "\"status\":\"OK\""), "login_ok sent");

        vf.set_top_word(0x0000000000001000ULL);  // <= lane, > mainchain
        std::string r = do_submit(srv, s, tx, 0x0000000aU);
        CHECK(contains(r, "\"status\":\"OK\""), "accepted share status OK");
        CHECK(sk.accepted == 1, "sink accepted 1");
        CHECK(sk.network_submits == 0, "no network submit");
        CHECK(!sk.last.is_network_block, "not a network block");
        // nonce inserted little-endian at offset 39
        CHECK(vf.last_blob.size() >= EXPECTED_NONCE_OFFSET_V16 + 4, "blob big enough");
        CHECK(vf.last_blob[39] == 0x0a && vf.last_blob[40] == 0x00 &&
              vf.last_blob[41] == 0x00 && vf.last_blob[42] == 0x00, "nonce @ offset 39 LE");
    }
    // --- network block (also clears mainchain target) ---
    {
        FakeTemplateSource ts; FakeVerifier vf; FakeSink sk; FakeTransport tx;
        XmrStratumServer srv(ts, vf, sk, tx);
        XmrStratumSession s(1);
        srv.handle_login(s, 1, "48addr");
        vf.set_top_word(0x0000000000000010ULL);  // <= mainchain target 0xFF
        std::string r = do_submit(srv, s, tx, 1);
        CHECK(contains(r, "\"status\":\"OK\""), "network share status OK");
        CHECK(sk.network_submits == 1, "network submit called");
        CHECK(sk.accepted == 1 && sk.last.is_network_block, "accepted + flagged network");
    }
    // --- low diff (clears neither) ---
    {
        FakeTemplateSource ts; FakeVerifier vf; FakeSink sk; FakeTransport tx;
        XmrStratumServer srv(ts, vf, sk, tx);
        XmrStratumSession s(1);
        srv.handle_login(s, 1, "48addr");
        vf.set_top_word(0xFFFFFFFFFFFFFFFFULL);   // > lane target
        std::string r = do_submit(srv, s, tx, 1);
        CHECK(contains(r, "Low diff share"), "low diff rejected");
        CHECK(sk.accepted == 0, "low diff not accepted");
    }
    // --- stale (template gone) ---
    {
        FakeTemplateSource ts; FakeVerifier vf; FakeSink sk; FakeTransport tx;
        XmrStratumServer srv(ts, vf, sk, tx);
        XmrStratumSession s(1);
        srv.handle_login(s, 1, "48addr");
        ts.fail_rebuild = true;
        vf.set_top_word(0x0000000000001000ULL);
        std::string r = do_submit(srv, s, tx, 1);
        CHECK(contains(r, "Stale share"), "stale rejected");
        CHECK(sk.accepted == 0, "stale not accepted");
    }
    // --- invalid job id ---
    {
        FakeTemplateSource ts; FakeVerifier vf; FakeSink sk; FakeTransport tx;
        XmrStratumServer srv(ts, vf, sk, tx);
        XmrStratumSession s(1);
        srv.handle_login(s, 1, "48addr");
        SubmitFields f; f.rpc_id = "0"; f.job_id = "00000009"; // != saved job 1
        f.nonce = "01000000"; f.result.assign(64, '0');
        tx.clear();
        srv.handle_submit(s, 2, f);
        CHECK(contains(tx.last(), "Invalid job id"), "invalid job id rejected");
    }
    // --- malformed submit drops connection (handle_submit returns false) ---
    {
        FakeTemplateSource ts; FakeVerifier vf; FakeSink sk; FakeTransport tx;
        XmrStratumServer srv(ts, vf, sk, tx);
        XmrStratumSession s(1);
        srv.handle_login(s, 1, "48addr");
        SubmitFields f; f.rpc_id = "0"; f.job_id = "00000001";
        f.nonce = "0a00";  // too short -> MalformedField
        f.result.assign(64, '0');
        CHECK(srv.handle_submit(s, 2, f) == false, "malformed submit -> drop");
    }
    // --- duplicate login on one connection drops ---
    {
        FakeTemplateSource ts; FakeVerifier vf; FakeSink sk; FakeTransport tx;
        XmrStratumServer srv(ts, vf, sk, tx);
        XmrStratumSession s(1);
        srv.handle_login(s, 1, "48addr");
        CHECK(srv.handle_login(s, 1, "48addr") == false, "duplicate login -> drop");
    }
}

int main() {
    test_hex_and_target();
    test_login_string();
    test_submit_parse();
    test_response_goldens();
    test_submit_flow();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
