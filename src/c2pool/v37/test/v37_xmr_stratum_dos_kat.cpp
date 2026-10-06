// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_stratum_dos_kat.cpp   (NET-DOS, stratum)
//
// The XMR stratum listener's DoS policy, over real loopback sockets with a
// stub template source and a counting stub verifier (no RandomX, no monerod).
// Clients dial from 127.0.0.x source addresses so bans by address apply.
//   SD1  the default policy values (and the default bind 127.0.0.1)
//   SD2  minimum difficulty: "+1" is raised to the floor, a "+diff" above the
//        floor is kept, no "+diff" = the lane target, and a lane target easier
//        than the floor is not made harder
//   SD3  submit budget: the submit over the burst is dropped unverified, the
//        connection is closed and its address banned (redial refused at accept)
//   SD4  a repeated (job id, nonce) is refused unverified; three bad shares
//        (score -9) ban the connection; an accepted share never lifts the
//        score above 0
//   SD5  bounded queue: one connection's submits are queued (bound 8, the
//        rest answered busy) and verified one per pass, so another miner's
//        login is answered before that queue drains
//   SD6  login deadline (test clock): no login after 4.9 s = open, after 5.1 s
//        = closed + address banned (redial refused); a logged-in miner and an
//        address-less 127.0.0.1 client are not address-banned
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
#include <string>
#include <thread>

#include "c2pool/v37/xmr/xmr_stratum_listener.hpp"

namespace strat = ::v37::xmr::stratum;
namespace o2 = ::c2pool::v37n::xmr::o2;
using Clock = std::chrono::steady_clock;

namespace {

constexpr std::uint64_t kMax = 0xFFFFFFFFFFFFFFFFULL;

struct Templates final : strat::ITemplateSource {
    std::atomic<std::uint64_t> lane_target{kMax / 1000000};   // lane difficulty 1,000,000
    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
        out.blob.assign(76, 0);
        out.blob[0] = 16;
        out.blob[70] = static_cast<std::uint8_t>(extra_nonce);
        out.template_id = 1;
        out.height = 100;
        out.mainchain_target = 1;               // no network blocks
        out.lane_target = lane_target.load();
        out.monero_major_version = 16;
        return true;
    }
    bool rebuild_blob(std::uint32_t, std::uint32_t en, strat::TemplateJob& out) override { return get_job(en, out); }
    std::uint32_t max_extra_nonces() const override { return 1u << 20; }
};
struct Verifier final : strat::IPowVerifier {
    std::atomic<int> hashes{0};
    std::atomic<int> sleep_ms{0};
    std::atomic<bool> good{true};
    bool randomx_hash(const std::uint8_t*, std::size_t, std::uint64_t, const std::array<std::uint8_t, strat::HASH_SIZE>&,
                      std::array<std::uint8_t, strat::HASH_SIZE>& out, bool) override {
        ++hashes;
        if (const int ms = sleep_ms.load()) std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        out.fill(0);
        return true;
    }
    bool meets_target(const std::array<std::uint8_t, strat::HASH_SIZE>&, std::uint64_t) const override { return good.load(); }
};
struct Sink final : strat::IShareSink {
    std::atomic<int> shares{0};
    void on_accepted_share(const strat::AcceptedShare&) override { ++shares; }
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
// One line: "" on timeout, "<EOF>" on close.
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
    explicit Rig(o2::StratumListenerOptions o) : L(tpl, ver, sink, o) {}
    bool up() {
        if (!L.bind().empty()) return false;
        L.notify_new_template();
        return L.start();
    }
    // Connect from `src`, log in with `suffix`; the job id ("" on failure).
    std::string login(int& fd, const char* src, const std::string& suffix, std::string* reply = nullptr) {
        fd = dial_from(src, L.bound_port());
        if (fd < 0) return "";
        send_line(fd, login_req(suffix));
        const std::string r = read_line(fd, 3000);
        if (reply) *reply = r;
        return field_of(r, "job_id");
    }
};
o2::StratumListenerOptions opts() {
    o2::StratumListenerOptions o;
    o.bind_host = "127.0.0.1"; o.bind_port = 0;
    o.poll_timeout_ms = 50;
    return o;
}

} // namespace

int main() {
    int fails = 0, n = 0;
    auto check = [&](const char* name, bool ok, const std::string& detail = {}) {
        ++n; if (!ok) ++fails;
        std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
        std::fflush(stdout);
    };
    std::printf("== v37_xmr_stratum_dos_kat ==\n");

    // ── SD1 defaults ────────────────────────────────────────────────────────
    {
        const o2::StratumListenerOptions d;
        check("SD1 defaults: bind 127.0.0.1, min difficulty 16000, 24 burst + 1.6/s submits (2 x 0.8/s), 24 queued, "
              "login 5 s, ban 15 s (= burst / rate), score -3/+1 ban at -9 (cap 0), 256 (job id, nonce) pairs remembered",
              d.bind_host == "127.0.0.1" && d.min_difficulty == 16000 && d.submit_burst == 24.0 && d.submit_rate == 2 * 0.8 &&
              d.max_pending_submits == 24 && d.login_timeout_ms == 5000 && d.ban_seconds == 15 &&
              std::abs(d.ban_seconds * d.submit_rate - d.submit_burst) < 1e-9 && d.bad_share_points == -3 &&
              d.good_share_points == 1 && d.ban_score == -9 && d.max_score == 0 && d.max_seen_submits == 256);
    }

    // ── SD2 minimum difficulty ──────────────────────────────────────────────
    {
        Rig R(opts());
        check("SD2 listener up", R.up());
        auto target_of = [&](const char* src, const std::string& suffix) {
            int fd = -1; std::string r;
            R.login(fd, src, suffix, &r);
            if (fd >= 0) ::close(fd);
            return field_of(r, "target");
        };
        const std::string t_floor = strat::StratumDialect::encode_target(kMax / 16000);
        const std::string t1 = target_of("127.0.0.20", "+1");
        const std::string t2 = target_of("127.0.0.21", "+100000");
        const std::string t3 = target_of("127.0.0.22", "");
        check("SD2 '+1' is raised to the floor (16000)", !t1.empty() && t1 == t_floor, t1 + " vs " + t_floor);
        check("SD2 '+100000' (above the floor) is kept", t2 == strat::StratumDialect::encode_target(kMax / 100000), t2);
        check("SD2 no '+diff': the lane target (1,000,000)", t3 == strat::StratumDialect::encode_target(kMax / 1000000), t3);
        R.tpl.lane_target = kMax / 1000;   // a lane easier than the floor
        const std::string t4 = target_of("127.0.0.23", "");
        const std::string t5 = target_of("127.0.0.24", "+1");
        check("SD2 a lane target easier than the floor (1000) is not made harder; '+1' then gets the lane target",
              t4 == strat::StratumDialect::encode_target(kMax / 1000) && t5 == t4, t4 + " / " + t5);
        R.L.stop();
    }

    // ── SD3 submit budget ───────────────────────────────────────────────────
    {
        auto o = opts(); o.submit_burst = 4; o.submit_rate = 0;
        Rig R(o);
        check("SD3 listener up (budget 4, no refill)", R.up());
        int fd = -1;
        const std::string jid = R.login(fd, "127.0.0.30", "");
        int oks = 0;
        for (std::uint32_t i = 0; i < 4; ++i) {
            send_line(fd, submit_req(10 + i, jid, i + 1));
            const std::string l = read_line(fd, 3000);
            if (reply_to(l, 10 + i) && !is_error(l)) ++oks;
        }
        send_line(fd, submit_req(14, jid, 5));
        const bool closed = closed_within(fd, 3000);
        ::close(fd);
        const auto s = R.L.stats();
        check("SD3 4 submits verified + accepted; the 5th (over budget) dropped UNVERIFIED and the connection closed",
              !jid.empty() && oks == 4 && closed && R.ver.hashes.load() == 4 && s.submits_over_budget == 1 && s.bans == 1,
              "oks=" + std::to_string(oks) + " hashes=" + std::to_string(R.ver.hashes.load()) +
                  " over=" + std::to_string(s.submits_over_budget));
        const int again = dial_from("127.0.0.30", R.L.bound_port());
        const bool refused = again >= 0 && closed_within(again, 3000);
        if (again >= 0) ::close(again);
        check("SD3 the address is banned: a redial is refused at accept", refused && R.L.stats().refused_banned == 1);
        int fd2 = -1;
        check("SD3 another address still logs in", !R.login(fd2, "127.0.0.31", "").empty());
        if (fd2 >= 0) ::close(fd2);
        R.L.stop();
    }

    // ── SD4 duplicate + score ban ───────────────────────────────────────────
    {
        Rig R(opts());
        check("SD4 listener up", R.up());
        int fd = -1;
        const std::string jid = R.login(fd, "127.0.0.40", "");
        send_line(fd, submit_req(20, jid, 7));
        const std::string a = read_line(fd, 3000);
        send_line(fd, submit_req(21, jid, 7));
        const std::string b = read_line(fd, 3000);
        check("SD4 a repeated (job id, nonce) is refused 'Duplicate share' without a second verification",
              reply_to(a, 20) && !is_error(a) && reply_to(b, 21) && b.find("Duplicate share") != std::string::npos &&
              R.ver.hashes.load() == 1 && R.L.stats().submits_duplicate == 1,
              "a='" + a.substr(0, 60) + "' b='" + b.substr(0, 80) + "'");
        // accepted (+1, capped at 0), duplicate -3; two low-difficulty shares: -6, -9 -> banned on the third bad share
        R.ver.good = false;
        int lows = 0;
        send_line(fd, submit_req(30, jid, 100));
        if (read_line(fd, 3000).find("Low diff share") != std::string::npos) ++lows;
        const bool open_after_two_bad = !closed_within(fd, 200);
        send_line(fd, submit_req(31, jid, 101));
        if (read_line(fd, 3000).find("Low diff share") != std::string::npos) ++lows;
        const bool closed = closed_within(fd, 3000);
        ::close(fd);
        check("SD4 bad shares cost 3 points each, an accepted share lifts the score to 0 at most: open after two bad "
              "shares (-6), banned (closed) on the third (-9)",
              lows == 2 && open_after_two_bad && closed && R.L.stats().bans == 1, "lows=" + std::to_string(lows));
        const int again = dial_from("127.0.0.40", R.L.bound_port());
        const bool refused = again >= 0 && closed_within(again, 3000);
        if (again >= 0) ::close(again);
        check("SD4 the banned address is refused at accept", refused);
        R.L.stop();
    }

    // ── SD5 bounded queue, one verification per pass ────────────────────────
    {
        auto o = opts(); o.max_pending_submits = 8;
        Rig R(o);
        check("SD5 listener up (queue bound 8)", R.up());
        int fa = -1;
        const std::string jid = R.login(fa, "127.0.0.50", "");
        R.ver.sleep_ms = 100;   // 100 ms per verification
        std::string flood;
        for (std::uint32_t i = 0; i < 12; ++i) flood += submit_req(100 + i, jid, 1000 + i) + "\n";
        (void)!::write(fa, flood.data(), flood.size());
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        const auto t0 = Clock::now();
        int fb = dial_from("127.0.0.51", R.L.bound_port());
        send_line(fb, login_req(""));
        const std::string rb = read_line(fb, 3000);
        const long b_ms = static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count());
        const int verified_when_b_answered = R.ver.hashes.load();
        int answered = 0, busy = 0, ok = 0;
        for (int i = 0; i < 12; ++i) {
            const std::string l = read_line(fa, 3000);
            if (l.empty() || l == "<EOF>") break;
            ++answered;
            if (l.find("Busy") != std::string::npos) ++busy; else if (!is_error(l)) ++ok;
        }
        const auto s = R.L.stats();
        check("SD5 12 submits at once: 8 queued + verified, 4 answered busy (queue bound 8), none closed the connection",
              answered == 12 && busy == 4 && ok == 8 && s.submits_busy == 4 && s.pending_max == 8 && s.bans == 0,
              "answered=" + std::to_string(answered) + " busy=" + std::to_string(busy) + " ok=" + std::to_string(ok) +
                  " pending_max=" + std::to_string(s.pending_max));
        check("SD5 another miner's login is answered while the queue drains (one 100 ms verification per pass)",
              field_of(rb, "job_id").size() > 0 && verified_when_b_answered < 8 && b_ms < 600,
              "login after " + std::to_string(b_ms) + " ms with " + std::to_string(verified_when_b_answered) + "/8 verified");
        ::close(fa); ::close(fb);
        R.L.stop();
    }

    // ── SD6 login deadline (test clock) ─────────────────────────────────────
    {
        auto o = opts();
        Rig R(o);
        std::atomic<long long> off_ms{0};
        const auto base = Clock::now();
        R.L.set_now_fn([&] { return base + std::chrono::milliseconds(off_ms.load()); });
        check("SD6 listener up (test clock)", R.up());
        const int silent = dial_from("127.0.0.60", R.L.bound_port());
        const int local = dial_from("127.0.0.1", R.L.bound_port());
        int miner = -1;
        const std::string jid = R.login(miner, "127.0.0.61", "");
        off_ms = 4900;
        const bool open_at_4_9 = !closed_within(silent, 300);
        off_ms = 5100;
        const bool closed_at_5_1 = closed_within(silent, 3000);
        const bool local_closed = closed_within(local, 3000);
        const bool miner_open = !closed_within(miner, 300);
        ::close(silent); ::close(local);
        const auto s = R.L.stats();
        check("SD6 no login: open at +4.9 s, closed at +5.1 s; the logged-in miner stays open",
              silent >= 0 && open_at_4_9 && closed_at_5_1 && local_closed && miner_open && s.login_timeouts == 2 && !jid.empty(),
              "timeouts=" + std::to_string(s.login_timeouts));
        const int again = dial_from("127.0.0.60", R.L.bound_port());
        const bool refused = again >= 0 && closed_within(again, 3000);
        if (again >= 0) ::close(again);
        const int local2 = dial_from("127.0.0.1", R.L.bound_port());
        const bool local_ok = local2 >= 0 && !closed_within(local2, 300);
        if (local2 >= 0) ::close(local2);
        check("SD6 the silent address is banned (redial refused); 127.0.0.1 is not address-banned", refused && local_ok);
        ::close(miner);
        R.L.stop();
    }

    std::printf("== v37_xmr_stratum_dos_kat: %s (%d/%d passed) ==\n", fails ? "FAIL" : "OK", n - fails, n);
    return fails ? 1 : 0;
}
