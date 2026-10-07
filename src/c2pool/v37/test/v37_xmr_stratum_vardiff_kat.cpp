// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_stratum_vardiff_kat.cpp   (NET-DOS, stratum vardiff)
//
// The XMR stratum listener's per-connection submit-rate budget tracking the
// lane window from the tip, over real loopback sockets with a stub template
// source (configurable lane / Monero targets) and a counting stub verifier
// (no RandomX, no monerod). Clients dial from 127.0.0.x source addresses.
//   VD1  the budget values follow the lane constants: upper-bound refill
//        2 x S_t = 2 x 2^k x n* / (COVERAGE x 120), the floor 2 x 2^k / T
//   VD2  s = 100 % (lane difficulty / Monero network difficulty at the tip):
//        the refill is the upper-bound 2 x S_t; a connection at the payout-floor
//        rate S_t for one lane window (~3 full-difficulty shares) is never
//        throttled; a connection far above the budget is closed and banned
//   VD3  s = 50 %: the refill halves with the window; the floor-rate connection
//        is still never throttled, a connection far above the budget is closed
//   VD4  s unknown (no Monero tip): the refill falls back to the honest-safe
//        floor; the #1932 SD7/SD8 behaviour holds (2^k / T submits/s never
//        closed, 2 x the floor closed within 60 submits)
// Nonzero exit on any failure.
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <random>
#include <string>
#include <thread>

#include "c2pool/v37/xmr/xmr_stratum_listener.hpp"

namespace strat = ::v37::xmr::stratum;
namespace o2 = ::c2pool::v37n::xmr::o2;
namespace xc = ::c2pool::v37n::xmr;
using Clock = std::chrono::steady_clock;

namespace {

constexpr std::uint64_t kMax = 0xFFFFFFFFFFFFFFFFULL;

// Budget values from the lane constants (never a literal).
const double kTwoK      = double(std::uint64_t(1) << xc::kXmrDropsFloorShift);   // 2^k = 64
const double kNStar     = double(xc::kXmrVardiffSharesPerWindow);                // n* = 3
const double kStMax     = kTwoK * kNStar / double(xc::kXmrWindowCoverage * xc::kXmrMoneroBlockIntervalS);  // 0.80/s
const double kBudgetMax = 2.0 * kStMax;                                          // 1.60/s (s = 100 %)
const double kFloorRate = double(2u << xc::kXmrDropsFloorShift) / double(xc::kXmrTargetIntervalS);         // 12.8/s
const double kWindowS   = double(xc::kXmrWindowCoverage * xc::kXmrMoneroBlockIntervalS);                   // t_W at s=100 %, 240 s

// A template source whose lane / Monero targets are set to realise a chosen
// pool share s of Monero hashrate: s = 120 x mainchain_target / (T x lane_target),
// so lane_target = 120 x mainchain_target / (T x s). mainchain_target = 0 means
// no Monero tip (s unknown).
struct Templates final : strat::ITemplateSource {
    std::atomic<std::uint64_t> lane_target{kMax / 1000000};
    std::atomic<std::uint64_t> mainchain_target{0};
    void set_share(double s) {
        const std::uint64_t mct = 1000000;                              // an arbitrary Monero target
        mainchain_target.store(mct);
        lane_target.store(static_cast<std::uint64_t>(
            120.0 * double(mct) / (double(xc::kXmrTargetIntervalS) * s) + 0.5));
    }
    void set_unknown() { mainchain_target.store(0); lane_target.store(kMax / 1000000); }
    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
        out.blob.assign(76, 0);
        out.blob[0] = 16;
        out.blob[70] = static_cast<std::uint8_t>(extra_nonce);
        out.template_id = 1;
        out.height = 100;
        out.mainchain_target = mainchain_target.load();
        out.lane_target = lane_target.load();
        out.monero_major_version = 16;
        return true;
    }
    bool rebuild_blob(std::uint32_t, std::uint32_t en, strat::TemplateJob& out) override { return get_job(en, out); }
    std::uint32_t max_extra_nonces() const override { return 1u << 20; }
};
struct Verifier final : strat::IPowVerifier {
    bool randomx_hash(const std::uint8_t*, std::size_t, std::uint64_t, const std::array<std::uint8_t, strat::HASH_SIZE>&,
                      std::array<std::uint8_t, strat::HASH_SIZE>& out, bool) override { out.fill(0); return true; }
    bool meets_target(const std::array<std::uint8_t, strat::HASH_SIZE>&, std::uint64_t) const override { return true; }
};
struct Sink final : strat::IShareSink {
    void on_accepted_share(const strat::AcceptedShare&) override {}
    void submit_network_block(std::uint32_t, std::uint32_t, std::uint32_t) override {}
};

int dial_from(const char* src, std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in s{}; s.sin_family = AF_INET; s.sin_port = 0;
    ::inet_pton(AF_INET, src, &s.sin_addr);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&s), sizeof s) != 0) { ::close(fd); return -1; }
    sockaddr_in d{}; d.sin_family = AF_INET; d.sin_port = htons(port); d.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&d), sizeof d) != 0) { ::close(fd); return -1; }
    return fd;
}
void send_line(int fd, const std::string& s) { const std::string l = s + "\n"; (void)!::write(fd, l.data(), l.size()); }
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
bool closed_within(int fd, int ms) {
    const auto until = Clock::now() + std::chrono::milliseconds(ms);
    while (Clock::now() < until) {
        const int left = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now()).count());
        if (read_line(fd, left > 0 ? left : 1) == "<EOF>") return true;
    }
    return false;
}
std::string login_req(const std::string& suffix) {
    return R"({"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"4TESTADDRESS)" + suffix +
           R"(.w1","pass":"x","agent":"XMRig/6.22.2"}})";
}
std::string field_of(const std::string& line, const std::string& name) {
    const std::string k = "\"" + name + "\":\"";
    const std::size_t p = line.find(k);
    if (p == std::string::npos) return "";
    const std::size_t b = p + k.size(), e = line.find('"', b);
    return e == std::string::npos ? "" : line.substr(b, e - b);
}
std::string submit_req(std::uint32_t id, const std::string& jid, std::uint32_t nonce) {
    char n[16];
    std::snprintf(n, sizeof n, "%08x", nonce);
    return R"({"id":)" + std::to_string(id) + R"(,"jsonrpc":"2.0","method":"submit","params":{"id":"1","job_id":")" + jid +
           R"(","nonce":")" + n + R"(","result":")" + std::string(64, '0') + R"("}})";
}
bool reply_to(const std::string& line, std::uint32_t id) { return line.find("\"id\":" + std::to_string(id) + ",") != std::string::npos; }
bool is_error(const std::string& line) { return line.find("\"error\":{") != std::string::npos; }

struct Rig {
    Templates tpl; Verifier ver; Sink sink;
    o2::StratumListener L;
    std::atomic<long long> off_us{0};
    Clock::time_point base;
    explicit Rig(o2::StratumListenerOptions o) : L(tpl, ver, sink, o) {
        base = Clock::now();
        L.set_now_fn([this] { return base + std::chrono::microseconds(off_us.load()); });
    }
    bool up() {
        if (!L.bind().empty()) return false;
        L.notify_new_template();
        return L.start();
    }
    std::string login(int& fd, const char* src) {
        fd = dial_from(src, L.bound_port());
        if (fd < 0) return "";
        send_line(fd, login_req(""));
        return field_of(read_line(fd, 3000), "job_id");
    }
};
o2::StratumListenerOptions opts() {
    o2::StratumListenerOptions o;
    o.bind_host = "127.0.0.1"; o.bind_port = 0;
    o.poll_timeout_ms = 50;
    return o;
}
bool near(double a, double b) { return std::fabs(a - b) <= 1e-6 * (1.0 + std::fabs(b)); }

} // namespace

int main() {
    int fails = 0, n = 0;
    auto check = [&](const char* name, bool ok, const std::string& detail = {}) {
        ++n; if (!ok) ++fails;
        std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
        std::fflush(stdout);
    };
    std::printf("== v37_xmr_stratum_vardiff_kat ==\n");

    // ── VD1 budget values follow the lane constants ─────────────────────────
    {
        check("VD1 upper bound 2 x S_t = 2 x 2^k x n* / (COVERAGE x 120) = 1.60/s; floor 2 x 2^k / T = 12.8/s",
              near(kStMax, 0.80) && near(kBudgetMax, 1.60) && near(kFloorRate, 12.8) && near(kWindowS, 240.0),
              "St_max=" + std::to_string(kStMax) + " budget_max=" + std::to_string(kBudgetMax) +
                  " floor=" + std::to_string(kFloorRate) + " t_W=" + std::to_string(kWindowS));
        const o2::StratumListenerOptions d;
        check("VD1 default: vardiff on, n* = kXmrVardiffSharesPerWindow, floor submit_rate = 12.8/s",
              d.submit_vardiff && d.vardiff_shares_per_window == xc::kXmrVardiffSharesPerWindow && near(d.submit_rate, kFloorRate),
              "vardiff=" + std::to_string(d.submit_vardiff) + " n*=" + std::to_string(d.vardiff_shares_per_window));
    }

    // ── VD2 s = 100 %: upper-bound budget, floor miner never throttled ──────
    {
        Rig R(opts());
        R.tpl.set_share(1.0);
        check("VD2 listener up (s = 100 %, test clock)", R.up());
        int fd = -1;
        const std::string jid = R.login(fd, "127.0.0.70");
        const double rate = R.L.submit_rate_effective();
        check("VD2 the budget tracked the window to the upper bound 2 x S_t = 1.60/s",
              !jid.empty() && near(rate, kBudgetMax), "effective=" + std::to_string(rate));
        // the payout-floor connection: submit floor-shares at S_t for one window
        std::mt19937_64 rng(1932);
        std::exponential_distribution<double> gap(kStMax);   // S_t = 0.80/s
        double t = 0;
        std::uint32_t sent = 0, ok = 0;
        bool dropped = false;
        while (t < kWindowS) {
            t += gap(rng);
            R.off_us = static_cast<long long>(t * 1e6);
            const std::uint32_t id = 1000 + sent;
            send_line(fd, submit_req(id, jid, 50000 + sent));
            const std::string l = read_line(fd, 3000);
            ++sent;
            if (l.empty() || l == "<EOF>") { dropped = true; break; }
            if (reply_to(l, id) && !is_error(l)) ++ok;
        }
        const bool open = !dropped && !closed_within(fd, 200);
        ::close(fd);
        auto s = R.L.stats();
        check("VD2 the payout-floor connection (S_t = 0.80 floor-shares/s for one window ~ 3 full-difficulty shares) is never throttled",
              open && ok == sent && sent >= 150 && s.submits_over_budget == 0 && s.bans == 0,
              "sent=" + std::to_string(sent) + " ok=" + std::to_string(ok) +
                  " full-shares~" + std::to_string(double(sent) / kTwoK) + " over=" + std::to_string(s.submits_over_budget));
        // a connection far above the budget is still closed + banned
        int f2 = -1;
        const std::string j2 = R.login(f2, "127.0.0.71");
        const double step = 1.0 / (2.0 * kBudgetMax);   // 2 x the refill: 3.2 submits/s
        double u = t;
        std::uint32_t sent2 = 0; bool closed2 = false;
        for (std::uint32_t i = 0; i < 200; ++i) {
            u += step;
            R.off_us = static_cast<long long>(u * 1e6);
            send_line(f2, submit_req(3000 + i, j2, 80000 + i));
            const std::string l = read_line(f2, 3000);
            ++sent2;
            if (l.empty() || l == "<EOF>") { closed2 = true; break; }
        }
        ::close(f2);
        auto s2 = R.L.stats();
        check("VD2 a connection at 2 x the budget (3.2/s) is closed for over-budget within 60 submits",
              !j2.empty() && closed2 && sent2 <= 60 && s2.submits_over_budget == 1 && s2.bans == 1,
              "sent=" + std::to_string(sent2) + " over=" + std::to_string(s2.submits_over_budget));
        R.L.stop();
    }

    // ── VD3 s = 50 %: the budget halves with the window ─────────────────────
    {
        Rig R(opts());
        R.tpl.set_share(0.5);
        check("VD3 listener up (s = 50 %, test clock)", R.up());
        int fd = -1;
        const std::string jid = R.login(fd, "127.0.0.80");
        const double rate = R.L.submit_rate_effective();
        const double St_half = kStMax * 0.5;        // 0.40/s
        const double budget_half = 2.0 * St_half;   // 0.80/s
        check("VD3 the budget halved with s: refill = 2 x S_t = 0.80/s",
              !jid.empty() && near(rate, budget_half), "effective=" + std::to_string(rate));
        std::mt19937_64 rng(733);
        std::exponential_distribution<double> gap(St_half);   // floor rate at s = 50 %
        double t = 0;
        std::uint32_t sent = 0, ok = 0; bool dropped = false;
        while (t < 2.0 * kWindowS) {          // t_W doubles at s = 50 %
            t += gap(rng);
            R.off_us = static_cast<long long>(t * 1e6);
            const std::uint32_t id = 1000 + sent;
            send_line(fd, submit_req(id, jid, 50000 + sent));
            const std::string l = read_line(fd, 3000);
            ++sent;
            if (l.empty() || l == "<EOF>") { dropped = true; break; }
            if (reply_to(l, id) && !is_error(l)) ++ok;
        }
        const bool open = !dropped && !closed_within(fd, 200);
        ::close(fd);
        auto s = R.L.stats();
        check("VD3 the payout-floor connection at s = 50 % (S_t = 0.40/s for its window) is never throttled",
              open && ok == sent && sent >= 150 && s.submits_over_budget == 0 && s.bans == 0,
              "sent=" + std::to_string(sent) + " over=" + std::to_string(s.submits_over_budget));
        int f2 = -1;
        const std::string j2 = R.login(f2, "127.0.0.81");
        const double step = 1.0 / (2.0 * budget_half);   // 1.6/s = 2 x the s=50 % budget
        double u = t;
        std::uint32_t sent2 = 0; bool closed2 = false;
        for (std::uint32_t i = 0; i < 200; ++i) {
            u += step;
            R.off_us = static_cast<long long>(u * 1e6);
            send_line(f2, submit_req(3000 + i, j2, 80000 + i));
            const std::string l = read_line(f2, 3000);
            ++sent2;
            if (l.empty() || l == "<EOF>") { closed2 = true; break; }
        }
        ::close(f2);
        check("VD3 a connection at 2 x the s = 50 % budget (1.6/s) is closed within 60 submits",
              !j2.empty() && closed2 && sent2 <= 60, "sent=" + std::to_string(sent2));
        R.L.stop();
    }

    // ── VD4 s unknown: fall back to the honest-safe floor (SD7/SD8) ─────────
    {
        Rig R(opts());
        R.tpl.set_unknown();   // no Monero tip
        check("VD4 listener up (s unknown, test clock)", R.up());
        int fd = -1;
        const std::string jid = R.login(fd, "127.0.0.90");
        const double rate = R.L.submit_rate_effective();
        check("VD4 s unknown: the refill falls back to the honest-safe floor 12.8/s",
              !jid.empty() && near(rate, kFloorRate), "effective=" + std::to_string(rate));
        // SD7 behaviour: 2^k / T = 6.4/s never closed
        const double honest = kTwoK / double(xc::kXmrTargetIntervalS);   // 6.4/s
        std::mt19937_64 rng(1932);
        std::exponential_distribution<double> gap(honest);
        double t = 0;
        std::uint32_t sent = 0, ok = 0; bool dropped = false;
        while (t < 120.0) {
            t += gap(rng);
            R.off_us = static_cast<long long>(t * 1e6);
            const std::uint32_t id = 1000 + sent;
            send_line(fd, submit_req(id, jid, 50000 + sent));
            const std::string l = read_line(fd, 3000);
            ++sent;
            if (l.empty() || l == "<EOF>") { dropped = true; break; }
            if (reply_to(l, id) && !is_error(l)) ++ok;
        }
        const bool open = !dropped && !closed_within(fd, 200);
        ::close(fd);
        auto s = R.L.stats();
        check("VD4 at the floor, 2^k / T = 6.4 submits/s for 120 s is never closed (SD7)",
              open && ok == sent && sent >= 700 && s.submits_over_budget == 0 && s.bans == 0,
              "sent=" + std::to_string(sent) + " over=" + std::to_string(s.submits_over_budget));
        int f2 = -1;
        const std::string j2 = R.login(f2, "127.0.0.91");
        const double step = 1.0 / (2.0 * kFloorRate);   // 25.6/s = 2 x the floor
        double u = t;
        std::uint32_t sent2 = 0; bool closed2 = false;
        for (std::uint32_t i = 0; i < 200; ++i) {
            u += step;
            R.off_us = static_cast<long long>(u * 1e6);
            send_line(f2, submit_req(3000 + i, j2, 80000 + i));
            const std::string l = read_line(f2, 3000);
            ++sent2;
            if (l.empty() || l == "<EOF>") { closed2 = true; break; }
        }
        ::close(f2);
        check("VD4 at the floor, 2 x the floor (25.6/s) is closed within 60 submits (SD8)",
              !j2.empty() && closed2 && sent2 <= 60, "sent=" + std::to_string(sent2));
        R.L.stop();
    }

    std::printf("== v37_xmr_stratum_vardiff_kat: %s (%d/%d passed) ==\n", fails ? "FAIL" : "OK", n - fails, n);
    return fails ? 1 : 0;
}
