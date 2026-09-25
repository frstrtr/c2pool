// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_lane_suspend_selfcheck.cpp   (R-C rework-2)
//
// The stratum side of LANE SUSPEND, over a real loopback socket. Before the
// rework, set_lane_suspended() was only an atomic flip: nothing was pushed, a
// connected miner kept hashing the withdrawn (stale-root) job, a reconnect was
// handed the same job at login. Proves:
//   LS1  a logged-in session gets a job;
//   LS2  the suspend EDGE disconnects it (the job is withdrawn), counted once;
//   LS3  repeated set_lane_suspended(true) calls are not new edges;
//   LS4  a login while suspended is PARKED (no job handed out);
//   LS6  the RESUME edge serves the parked login a fresh job.
// R-C rework-3:
//   LS8  (D4) a template push whose seed-prefetch hook is running when the
//        lane suspends pushes NO job afterwards (rework-2 pushed it);
//   LS9  (D4) set_lane_suspended(true) does not return while a share hand-off
//        is in flight, and no share is handed off after it returns;
//   LS10 (D5 + contested) the lane-suspend state machine counts every cause on
//        its own rising edge (HELD-LAG during a LAG suspension is counted),
//        CONTESTED suspends and auto-resumes only when every cause is clear.
// Stub template source + stub verifier (no RandomX). Port 5771 (loopback;
// falls back to an ephemeral port if taken).
// Nonzero exit on any failure.
//   LS11 (D2, ruling D-1 = C) CONVERGING and DIVERGED are ALARMS: their edges
//        are counted and named, they never suspend the lane, never hold it
//        suspended, and never delay a resume of the real causes.
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include <atomic>
#include <condition_variable>
#include <mutex>

#include "c2pool/v37/xmr/xmr_lane_suspend_state.hpp"
#include "c2pool/v37/xmr/xmr_stratum_listener.hpp"

namespace strat = ::v37::xmr::stratum;

namespace {

struct StubTemplates final : strat::ITemplateSource {
    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
        out.blob.assign(76, 0);
        out.blob[0] = 16;   // major
        out.blob[70] = static_cast<std::uint8_t>(extra_nonce);
        out.template_id = 7;
        out.height = 100;
        out.mainchain_target = 1;
        out.lane_target = 1;
        out.monero_major_version = 16;
        return true;
    }
    bool rebuild_blob(std::uint32_t, std::uint32_t en, strat::TemplateJob& out) override { return get_job(en, out); }
    std::uint32_t max_extra_nonces() const override { return 16; }
};
struct StubVerifier final : strat::IPowVerifier {
    bool randomx_hash(const std::uint8_t*, std::size_t, std::uint64_t, const std::array<std::uint8_t, strat::HASH_SIZE>&,
                      std::array<std::uint8_t, strat::HASH_SIZE>& out, bool) override { out.fill(0xff); return true; }
    bool meets_target(const std::array<std::uint8_t, strat::HASH_SIZE>&, std::uint64_t) const override { return false; }
};
struct CountingSink final : strat::IShareSink {
    int shares = 0, blocks = 0;
    void on_accepted_share(const strat::AcceptedShare&) override { ++shares; }
    void submit_network_block(std::uint32_t, std::uint32_t, std::uint32_t) override { ++blocks; }
};

int connect_to(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) { ::close(fd); return -1; }
    return fd;
}
void send_line(int fd, const std::string& s) { const std::string l = s + "\n"; (void)!::write(fd, l.data(), l.size()); }
// Read until a newline, EOF (returns "<EOF>") or the timeout (returns "").
std::string read_line(int fd, int timeout_ms) {
    std::string buf;
    const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < until) {
        pollfd p{fd, POLLIN, 0};
        const int rc = ::poll(&p, 1, 50);
        if (rc <= 0) continue;
        char c;
        const ssize_t n = ::read(fd, &c, 1);
        if (n == 0) return buf.empty() ? "<EOF>" : buf;
        if (n < 0) return "<EOF>";
        if (c == '\n') return buf;
        buf.push_back(c);
    }
    return buf;
}
const char* kLogin = R"({"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"4TESTADDRESS.w1","pass":"x","agent":"selfcheck/1"}})";

// A one-shot latch: wait() blocks until open().
struct Latch {
    std::mutex m; std::condition_variable cv; bool is_open = false;
    void open() { { std::lock_guard<std::mutex> g(m); is_open = true; } cv.notify_all(); }
    void wait() { std::unique_lock<std::mutex> g(m); cv.wait(g, [&] { return is_open; }); }
};
// Templates whose lane target (2) differs from the mainchain target (1), so a
// verifier that meets only target 2 produces SHARES, never network blocks.
struct ShareTemplates final : strat::ITemplateSource {
    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
        out.blob.assign(76, 0); out.blob[0] = 16; out.blob[70] = static_cast<std::uint8_t>(extra_nonce);
        out.template_id = 9; out.height = 100; out.mainchain_target = 1; out.lane_target = 2;
        out.monero_major_version = 16; return true;
    }
    bool rebuild_blob(std::uint32_t, std::uint32_t en, strat::TemplateJob& out) override { return get_job(en, out); }
    std::uint32_t max_extra_nonces() const override { return 16; }
};
struct ShareVerifier final : strat::IPowVerifier {
    bool randomx_hash(const std::uint8_t*, std::size_t, std::uint64_t, const std::array<std::uint8_t, strat::HASH_SIZE>&,
                      std::array<std::uint8_t, strat::HASH_SIZE>& out, bool) override { out.fill(0x01); return true; }
    bool meets_target(const std::array<std::uint8_t, strat::HASH_SIZE>&, std::uint64_t t) const override { return t == 2; }
};
// The inner sink of LS9: the first share blocks inside the hand-off until released.
struct BlockingSink final : strat::IShareSink {
    std::atomic<int> shares{0}, blocks{0};
    Latch entered, release;
    void on_accepted_share(const strat::AcceptedShare&) override {
        if (shares.load() == 0) { entered.open(); release.wait(); }
        ++shares;
    }
    void submit_network_block(std::uint32_t, std::uint32_t, std::uint32_t) override { ++blocks; }
};
std::string job_id_of(const std::string& line) {
    const std::string k = "\"job_id\":\"";
    const std::size_t p = line.find(k);
    if (p == std::string::npos) return "";
    const std::size_t b = p + k.size(), e = line.find('"', b);
    return e == std::string::npos ? "" : line.substr(b, e - b);
}

} // namespace

int main() {
    StubTemplates tpl; StubVerifier ver; CountingSink sink;
    c2pool::v37n::xmr::o2::StratumListenerOptions lo;
    lo.bind_host = "127.0.0.1"; lo.bind_port = 5771; lo.parked_login_ttl_ms = 60000;
    // 5771 first; if it is taken (a concurrent CI leg on the same host) fall back
    // to an ephemeral port rather than flake.
    {
        c2pool::v37n::xmr::o2::StratumListener probe(tpl, ver, sink, lo);
        if (!probe.bind().empty()) lo.bind_port = 0;
        probe.stop();
    }
    c2pool::v37n::xmr::o2::StratumListener L(tpl, ver, sink, lo);
    int fails = 0, n = 0;
    auto check = [&](const char* name, bool ok, const std::string& detail = {}) {
        ++n; if (!ok) ++fails;
        std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
    };
    std::printf("== v37_xmr_lane_suspend_selfcheck ==\n");
    if (std::string e = L.bind(); !e.empty()) { std::printf("  [FAIL] bind: %s\n", e.c_str()); return 1; }
    L.notify_new_template();
    L.start();

    const int c1 = connect_to(L.bound_port());
    send_line(c1, kLogin);
    const std::string r1 = read_line(c1, 3000);
    check("LS1 logged-in session is handed a job", r1.find("\"job\"") != std::string::npos, r1.substr(0, 60));

    L.set_lane_suspended(true);
    const std::string r2 = read_line(c1, 3000);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const auto s1 = L.stats();
    check("LS2 the suspend EDGE disconnects the session (job withdrawn), counted", r2 == "<EOF>" && s1.suspend_edges == 1 &&
          s1.suspend_disconnects == 1, "read=" + r2 + " edges=" + std::to_string(s1.suspend_edges) +
          " disconnects=" + std::to_string(s1.suspend_disconnects));
    ::close(c1);

    L.set_lane_suspended(true); L.set_lane_suspended(true);
    check("LS3 repeated set_lane_suspended(true) is not a new edge", L.stats().suspend_edges == 1);

    const int c2 = connect_to(L.bound_port());
    send_line(c2, kLogin);
    const std::string r3 = read_line(c2, 800);
    check("LS4 a login while suspended is PARKED (the withdrawn job is never handed out)", r3.empty(), "read=" + r3.substr(0, 60));

    L.set_lane_suspended(false);
    const std::string r5 = read_line(c2, 3000);
    check("LS6 the RESUME edge serves the parked login a fresh job", r5.find("\"job\"") != std::string::npos, r5.substr(0, 60));
    ::close(c2);

    L.stop();
    check("LS7 no share / block reached the sink during the exercise", sink.shares == 0 && sink.blocks == 0);

    // ── LS8 (D4): the template-push window ─────────────────────────────────
    {
        StubTemplates t8; StubVerifier v8; CountingSink s8;
        c2pool::v37n::xmr::o2::StratumListenerOptions o8 = lo; o8.bind_port = 0;
        c2pool::v37n::xmr::o2::StratumListener L8(t8, v8, s8, o8);
        Latch hook_in, hook_go; std::atomic<int> hook_calls{0};
        L8.set_template_hook([&](const strat::TemplateJob&) {
            if (hook_calls.fetch_add(1) == 1) { hook_in.open(); hook_go.wait(); }   // block the 2nd push (the 1st serves the login)
        });
        if (std::string e = L8.bind(); !e.empty()) { check("LS8 bind", false, e); return 1; }
        L8.notify_new_template(); L8.start();
        const int c = connect_to(L8.bound_port());
        send_line(c, kLogin);
        const std::string first = read_line(c, 3000);
        const auto pushes0 = L8.stats().job_pushes;
        L8.notify_new_template();          // the listener enters the hook and blocks there
        hook_in.wait();
        L8.set_lane_suspended(true);       // returns at once: the hook does not hold the gate
        hook_go.open();                    // the template push resumes AFTER the flip
        std::string got, l;
        while ((l = read_line(c, 2000)) != "<EOF>" && !l.empty()) got += l;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        const auto s8s = L8.stats();
        check("LS8 D4: a template push whose seed-prefetch hook straddles the suspend flip pushes NO job afterwards (gate re-checked per push); the session sees only the disconnect",
              first.find("\"job\"") != std::string::npos && got.find("\"job\"") == std::string::npos &&
              s8s.job_pushes == pushes0 && s8s.suspended_push_refused >= 1,
              "after-flip read='" + got.substr(0, 60) + "' pushes " + std::to_string(pushes0) + "->" + std::to_string(s8s.job_pushes) +
              " gate_refused=" + std::to_string(s8s.suspended_push_refused));
        ::close(c);
        L8.stop();
    }

    // ── LS9 (D4): the share hand-off window ────────────────────────────────
    {
        ShareTemplates t9; ShareVerifier v9; BlockingSink s9;
        c2pool::v37n::xmr::o2::StratumListenerOptions o9 = lo; o9.bind_port = 0;
        c2pool::v37n::xmr::o2::StratumListener L9(t9, v9, s9, o9);
        if (std::string e = L9.bind(); !e.empty()) { check("LS9 bind", false, e); return 1; }
        L9.notify_new_template(); L9.start();
        const int c = connect_to(L9.bound_port());
        send_line(c, kLogin);
        const std::string first = read_line(c, 3000);
        const std::string jid = job_id_of(first);
        send_line(c, std::string(R"({"id":2,"jsonrpc":"2.0","method":"submit","params":{"id":"1","job_id":")") + jid +
                     R"(","nonce":"01000000","result":")" + std::string(64, '0') + R"("}})");
        s9.entered.wait();                 // the share is INSIDE the hand-off (validated, not yet accepted)
        std::atomic<bool> returned{false}; int shares_at_return = -1;
        std::thread flipper([&] { L9.set_lane_suspended(true); shares_at_return = s9.shares.load(); returned.store(true); });
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        const bool blocked_while_in_flight = !returned.load();
        s9.release.open();
        flipper.join();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const int shares_final = s9.shares.load();
        check("LS9 D4: set_lane_suspended(true) does NOT return while a share hand-off is in flight (serialized by the suspend gate); the in-flight share completed BEFORE the flip returned and nothing was handed off after it",
              !jid.empty() && blocked_while_in_flight && shares_at_return == 1 && shares_final == 1 && s9.blocks.load() == 0,
              "jid=" + jid + " blocked=" + std::to_string(blocked_while_in_flight) + " shares@return=" + std::to_string(shares_at_return) +
              " final=" + std::to_string(shares_final));
        ::close(c);
        L9.stop();
    }

    // ── LS10 (D5 + contested): the lane-suspend state machine ──────────────
    {
        using S = c2pool::v37n::xmr::LaneSuspendState;
        S st(3);                                    // D_conf 3: suspend at lag > 6, resume at lag <= 3
        auto e1 = st.update(7, false, false, false);   // LAG trips
        auto e2 = st.update(9, false, true, false);    // HELD-LAG fires while already lag-suspended (the rework-2 D5 miss)
        auto e3 = st.update(2, false, true, false);    // lag clears, held still holds the lane
        auto e4 = st.update(0, false, false, false);   // held clears -> RESUME
        auto e5 = st.update(0, false, false, true);    // CONTESTED -> suspend
        auto e6 = st.update(8, false, false, true);    // lag joins the contested suspension
        auto e7 = st.update(0, false, false, false);   // vote CONVERGED + lag cleared -> auto-RESUME
        check("LS10 D5: every cause counted on ITS OWN rising edge -- HELD-LAG during a LAG suspension is cause=held (rework-2 never counted it); CONTESTED suspends and the lane auto-resumes only when every cause (lag, held, contested) is clear",
              e1.suspend_edge && e1.causes == S::kLag && !e2.suspend_edge && (e2.added & S::kHeld) && st.n_held == 1 &&
              !e3.resume_edge && e3.causes == S::kHeld && e4.resume_edge && e5.suspend_edge && e5.causes == S::kContested &&
              (e6.added & S::kLag) && !e6.suspend_edge && e7.resume_edge && st.n_lag == 2 && st.n_contested == 1 &&
              st.n_resume == 2 && st.n_suspend == 2 && S::names(e6.causes) == "lag+contested",
              "n lag/held/contested/resume/suspend=" + std::to_string(st.n_lag) + "/" + std::to_string(st.n_held) + "/" +
              std::to_string(st.n_contested) + "/" + std::to_string(st.n_resume) + "/" + std::to_string(st.n_suspend));
    }
    // ── LS11 (D2): CONVERGING / DIVERGED are causes of their own ───────────
    {
        using S = c2pool::v37n::xmr::LaneSuspendState;
        S st(3);
        auto e1 = st.update(0, false, false, false, true, false);    // minority detected -> CONVERGING: alarm, lane stays served
        auto e2 = st.update(8, false, false, false, true, false);    // lag (a real cause) suspends
        auto e3 = st.update(8, false, false, false, false, true);    // no candidate reproduces -> DIVERGED: alarm only
        auto e4 = st.update(2, false, false, false, false, true);    // lag clears -> RESUME although DIVERGED persists
        auto e5 = st.update(0, false, false, false, false, false);   // DIVERGED cleared: no edge on the lane
        auto e6 = st.update(0, false, false, false, true, false);    // a later run
        auto e7 = st.update(0, false, false, false, false, false);   // adopted
        check("LS11 D2 (D-1 = C): CONVERGING and DIVERGED are ALARM-ONLY -- counted + named, never a suspend edge, never in causes, never hold the lane (lag resumes while DIVERGED persists)",
              !e1.suspend_edge && e1.causes == 0 && e1.alarm_added == S::kConverging && !st.suspended() &&
              (e2.added & S::kLag) && e2.suspend_edge && e2.causes == S::kLag &&
              e3.alarm_added == S::kDiverged && e3.alarm_cleared == S::kConverging && e3.causes == S::kLag &&
              e4.resume_edge && e4.causes == 0 && e4.alarm_added == 0 && e4.alarm_cleared == 0 &&
              !e5.resume_edge && !e5.suspend_edge && e5.alarm_cleared == S::kDiverged &&
              !e6.suspend_edge && e6.alarm_added == S::kConverging && !e7.resume_edge && !e7.suspend_edge &&
              st.n_converging == 2 && st.n_diverged == 1 && st.n_suspend == 1 && st.n_resume == 1 &&
              S::names(S::kConverging | S::kDiverged) == "converging+diverged",
              "n converging/diverged/suspend/resume=" + std::to_string(st.n_converging) + "/" + std::to_string(st.n_diverged) + "/" +
              std::to_string(st.n_suspend) + "/" + std::to_string(st.n_resume));
    }
    std::printf("== %s (%d/%d passed) ==\n", fails ? "FAIL" : "OK", n - fails, n);
    return fails ? 1 : 0;
}
