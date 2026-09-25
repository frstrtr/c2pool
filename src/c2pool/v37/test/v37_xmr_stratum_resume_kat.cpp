// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_stratum_resume_kat.cpp   (STRATUM-RESUME)
//
// Cold-boot smoke D3: while the lane was SUSPENDED (or before the first
// template) a miner's login was PARKED, then EXPIRED with "No job available".
// With a single pool xmrig treats that login error as non-fatal: it keeps the
// connection open, never logs in again and idles forever -- after the lane
// resumed nothing could reach it (the session was never logged in and was no
// longer parked). Proves, over a real loopback socket with a fake template
// provider that goes unavailable -> available:
//   SR1  a login with NO template is parked and is never answered with an
//        error, however long it waits (base: "No job available" after the TTL);
//   SR2  the first template (notify_new_template) completes that parked login
//        with a real login result carrying a job (base: nothing, ever);
//   SR3  the D3 shape: a miner mining before the suspension (disconnected on the
//        suspend edge, reconnects) and a miner logging in DURING the suspension
//        both wait parked, with no error, past the TTL;
//   SR4  the RESUME edge hands BOTH of them a login result with a job;
//   SR5  a template gap that ends WITHOUT a notify (same template id) still
//        serves a parked login (the idle-tick re-probe);
//   SR6  no job storm: the idle tick never re-pushes logged-in sessions, and one
//        template change is exactly one job per connected miner.
//   SR7  with the DEFAULT options a parked login is sent a benign keepalive
//        (unknown id 0, no error, no job) within 10 s -- xmrig 6.22 drops a login
//        unanswered for 20 s, and any received line resets that timer -- and is
//        still served its login result afterwards.
// Stub verifier (no RandomX), no monerod. Ephemeral loopback port.
// Nonzero exit on any failure.
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>

#include "c2pool/v37/xmr/xmr_stratum_listener.hpp"

namespace strat = ::v37::xmr::stratum;
using Clock = std::chrono::steady_clock;

namespace {

// The fake provider: a template exists only while `available`.
struct ToggleTemplates final : strat::ITemplateSource {
    std::atomic<bool> available{false};
    std::atomic<std::uint32_t> tid{1};
    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
        if (!available.load()) return false;
        out.blob.assign(76, 0);
        out.blob[0] = 16;
        out.blob[70] = static_cast<std::uint8_t>(extra_nonce);
        out.template_id = tid.load();
        out.height = 100 + tid.load();
        out.mainchain_target = 1;
        out.lane_target = 1;
        out.monero_major_version = 16;
        return true;
    }
    bool rebuild_blob(std::uint32_t, std::uint32_t en, strat::TemplateJob& out) override { return get_job(en, out); }
    std::uint32_t max_extra_nonces() const override { return 64; }
};
struct StubVerifier final : strat::IPowVerifier {
    bool randomx_hash(const std::uint8_t*, std::size_t, std::uint64_t, const std::array<std::uint8_t, strat::HASH_SIZE>&,
                      std::array<std::uint8_t, strat::HASH_SIZE>& out, bool) override { out.fill(0xff); return true; }
    bool meets_target(const std::array<std::uint8_t, strat::HASH_SIZE>&, std::uint64_t) const override { return false; }
};
struct NullSink final : strat::IShareSink {
    void on_accepted_share(const strat::AcceptedShare&) override {}
    void submit_network_block(std::uint32_t, std::uint32_t, std::uint32_t) override {}
};

int connect_to(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) { ::close(fd); return -1; }
    return fd;
}
void send_line(int fd, const std::string& s) { const std::string l = s + "\n"; (void)!::write(fd, l.data(), l.size()); }
// Read one line: "" on timeout, "<EOF>" on close.
std::string read_line(int fd, int timeout_ms) {
    std::string buf;
    const auto until = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (Clock::now() < until) {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, 20) <= 0) continue;
        char c;
        const ssize_t n = ::read(fd, &c, 1);
        if (n <= 0) return buf.empty() ? "<EOF>" : buf;
        if (c == '\n') return buf;
        buf.push_back(c);
    }
    return buf;
}
// Every line that arrives within the window (stops early on EOF).
std::string read_all(int fd, int window_ms, int* lines = nullptr) {
    std::string got; int n = 0;
    const auto until = Clock::now() + std::chrono::milliseconds(window_ms);
    while (Clock::now() < until) {
        const int left = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now()).count());
        const std::string l = read_line(fd, left > 0 ? left : 1);
        if (l == "<EOF>") { got += "<EOF>"; break; }
        if (!l.empty()) { got += l + "\n"; ++n; }
    }
    if (lines) *lines = n;
    return got;
}
const char* kLogin = R"({"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"4TESTADDRESS.w1","pass":"x","agent":"XMRig/6.22.2"}})";
bool is_login_result(const std::string& l) {   // what xmrig needs: the reply to request id 1 with result.job
    return l.find("\"id\":1") != std::string::npos && l.find("\"result\"") != std::string::npos &&
           l.find("\"job\"") != std::string::npos && l.find("\"error\":{") == std::string::npos;
}
bool has_error(const std::string& s) { return s.find("\"error\":{") != std::string::npos; }
int count_job_pushes(const std::string& s) {
    int n = 0; std::size_t p = 0;
    while ((p = s.find("\"method\":\"job\"", p)) != std::string::npos) { ++n; ++p; }
    return n;
}
long ms_since(Clock::time_point t) {
    return static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t).count());
}
std::string first_line(const std::string& s) { return s.substr(0, std::min<std::size_t>(s.find('\n'), 90)); }

} // namespace

int main() {
    ToggleTemplates tpl; StubVerifier ver; NullSink sink;
    c2pool::v37n::xmr::o2::StratumListenerOptions lo;
    lo.bind_host = "127.0.0.1"; lo.bind_port = 0;
    lo.parked_login_ttl_ms = 200;          // short: the pre-fix expiry fires inside the waits below
    c2pool::v37n::xmr::o2::StratumListener L(tpl, ver, sink, lo);
    int fails = 0, n = 0;
    auto check = [&](const char* name, bool ok, const std::string& detail = {}) {
        ++n; if (!ok) ++fails;
        std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
    };
    std::printf("== v37_xmr_stratum_resume_kat ==\n");
    if (std::string e = L.bind(); !e.empty()) { std::printf("  [FAIL] bind: %s\n", e.c_str()); return 1; }
    L.start();

    // ── SR1/SR2: cold boot -- no template, then the first one ─────────────
    const int a = connect_to(L.bound_port());
    send_line(a, kLogin);
    const std::string waitA = read_all(a, 1000);            // 5x the TTL
    check("SR1 a login with NO template is parked and never answered with an error (kept open past the TTL)",
          waitA.empty(), "read='" + first_line(waitA) + "'");
    tpl.available = true;
    auto t0 = Clock::now();
    L.notify_new_template();
    const std::string gotA = read_line(a, 3000);
    const long dA = ms_since(t0);
    check("SR2 the first template completes the parked login with a real login result + job",
          is_login_result(gotA), "after " + std::to_string(dA) + " ms: '" + gotA.substr(0, 90) + "'");

    // ── SR3/SR4: the D3 shape -- suspend, reconnect + fresh login, resume ──
    L.set_lane_suspended(true);
    const std::string dropA = read_all(a, 1000);
    ::close(a);
    const int a2 = connect_to(L.bound_port());   // the miner that was mining before: reconnects
    const int b  = connect_to(L.bound_port());   // a miner that logs in during the suspension
    send_line(a2, kLogin);
    send_line(b, kLogin);
    const std::string waitA2 = read_all(a2, 1000);
    const std::string waitB  = read_all(b, 1000);
    check("SR3 while SUSPENDED the reconnected miner and the new miner wait PARKED -- no error, no job, connection open, past the TTL",
          dropA.find("<EOF>") != std::string::npos && waitA2.empty() && waitB.empty(),
          "drop='" + first_line(dropA) + "' a2='" + first_line(waitA2) + "' b='" + first_line(waitB) + "'");
    tpl.tid = 2;
    t0 = Clock::now();
    L.set_lane_suspended(false);                  // the resume edge
    const std::string gotA2 = read_line(a2, 3000);
    const long dA2 = ms_since(t0);
    const std::string gotB = read_line(b, 3000);
    const long dB = ms_since(t0);
    check("SR4 the RESUME edge hands BOTH parked miners a login result + job (no reconnect needed)",
          is_login_result(gotA2) && is_login_result(gotB),
          "a2 " + std::to_string(dA2) + " ms '" + gotA2.substr(0, 60) + "' / b " + std::to_string(dB) + " ms '" +
              gotB.substr(0, 60) + "'");

    // ── SR5: a template gap that ends without a notify ────────────────────
    tpl.available = false;
    const int c = connect_to(L.bound_port());
    send_line(c, kLogin);
    const std::string waitC = read_all(c, 800);
    tpl.available = true;                         // same template id: the main loop would not signal
    t0 = Clock::now();
    const std::string gotC = read_line(c, 3000);
    const long dC = ms_since(t0);
    check("SR5 a template gap that ends WITHOUT a notify still serves the parked login (idle-tick re-probe), no error while waiting",
          waitC.empty() && is_login_result(gotC),
          "wait='" + first_line(waitC) + "' then " + std::to_string(dC) + " ms '" + gotC.substr(0, 60) + "'");

    // ── SR6: no job storm ──────────────────────────────────────────────────
    const auto p0 = L.stats().job_pushes;
    int la = 0, lb = 0, lc = 0;
    const std::string idleA = read_all(a2, 800, &la);
    const std::string idleB = read_all(b, 1, &lb);
    const std::string idleC = read_all(c, 1, &lc);
    const auto p1 = L.stats().job_pushes;
    tpl.tid = 3;
    L.notify_new_template();
    const std::string jA = read_all(a2, 800, &la), jB = read_all(b, 300, &lb), jC = read_all(c, 300, &lc);
    const auto p2 = L.stats().job_pushes;
    const int ja = count_job_pushes(jA), jb = count_job_pushes(jB), jc = count_job_pushes(jC);
    check("SR6 no job storm: the idle tick pushes nothing to logged-in sessions; one template change = exactly one job per connected miner",
          idleA.empty() && idleB.empty() && idleC.empty() && p1 == p0 && ja == 1 && jb == 1 && jc == 1 && p2 - p1 == 3,
          "idle pushes " + std::to_string(p1 - p0) + ", jobs per miner " + std::to_string(ja) + "/" + std::to_string(jb) + "/" +
              std::to_string(jc) + ", pushes " + std::to_string(p2 - p1));

    ::close(a2); ::close(b); ::close(c);
    L.stop();

    // ── SR7: parked keepalive with the default options ─────────────────────
    long d7 = -1;
    {
        ToggleTemplates t7; StubVerifier v7; NullSink s7;
        c2pool::v37n::xmr::o2::StratumListenerOptions o7;   // defaults (keepalive + TTL as shipped)
        o7.bind_host = "127.0.0.1"; o7.bind_port = 0;
        c2pool::v37n::xmr::o2::StratumListener L7(t7, v7, s7, o7);
        if (std::string e = L7.bind(); !e.empty()) { check("SR7 bind", false, e); return 1; }
        L7.start();
        const int k = connect_to(L7.bound_port());
        send_line(k, kLogin);
        int nk = 0;
        const std::string waitK = read_all(k, 11500, &nk);
        const bool only_keepalive = nk >= 1 && !has_error(waitK) && waitK.find("\"job\"") == std::string::npos &&
                                    waitK.find("\"id\":0,") != std::string::npos && waitK.find("KEEPALIVED") != std::string::npos &&
                                    waitK.find("<EOF>") == std::string::npos;
        t7.available = true;
        const auto t7s = Clock::now();
        L7.notify_new_template();
        const std::string gotK = read_line(k, 3000);
        d7 = ms_since(t7s);
        check("SR7 default options: a parked login gets a benign keepalive (id 0, no error, no job) within 10 s and is still served its login result",
              only_keepalive && is_login_result(gotK),
              std::to_string(nk) + " line(s) in 11.5 s: '" + first_line(waitK) + "' then " + std::to_string(d7) + " ms '" +
                  gotK.substr(0, 50) + "'");
        ::close(k);
        L7.stop();
    }
    std::printf("  timing: cold-boot first job %ld ms, resume a2 %ld ms / b %ld ms, gap-end %ld ms\n", dA, dA2, dB, dC);
    std::printf("== %s (%d/%d passed) ==\n", fails ? "FAIL" : "OK", n - fails, n);
    return fails ? 1 : 0;
}
