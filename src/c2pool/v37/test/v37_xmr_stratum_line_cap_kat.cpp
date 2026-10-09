// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_stratum_line_cap_kat.cpp
//
// The XMR stratum listener's request-line bounds, over real loopback sockets
// with a stub template source / verifier / sink (no RandomX, no monerod).
//   LC1  line_over_cap : a newline-terminated line past max_line_bytes closes
//        the connection before dispatch (no reply is produced).
//   LC2  empty_line_run : a run of blank lines past the cap closes the
//        connection before a later login is served.
//   LC3  submit_log_fields_clipped : a 60000-byte job_id on the rejected and
//        on the duplicate submit path, and a 60000-byte nonce on the rejected
//        path, each give a log line under 1 KiB.
//   LC4  line_cap_crlf : a line of exactly max_line_bytes is served with a
//        "\r\n" terminator, also when the '\r' and the '\n' arrive in separate
//        reads; max_line_bytes + 1 with "\r\n" is closed.
//   LC5  split_reads : requests whose bytes and newlines arrive over several
//        reads are each answered once, in order.
// Nonzero exit on any failure.
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "c2pool/v37/xmr/xmr_stratum_listener.hpp"

namespace strat = ::v37::xmr::stratum;
namespace o2 = ::c2pool::v37n::xmr::o2;
using Clock = std::chrono::steady_clock;

namespace {

constexpr std::uint64_t kMax = 0xFFFFFFFFFFFFFFFFULL;

struct Templates final : strat::ITemplateSource {
    bool get_job(std::uint32_t en, strat::TemplateJob& out) override {
        out.blob.assign(76, 0); out.blob[0] = 16; out.blob[70] = static_cast<std::uint8_t>(en);
        out.template_id = 1; out.height = 100; out.mainchain_target = 0;
        out.lane_target = kMax / 1000000; out.monero_major_version = 16;
        return true;
    }
    bool rebuild_blob(std::uint32_t, std::uint32_t en, strat::TemplateJob& out) override { return get_job(en, out); }
    std::uint32_t max_extra_nonces() const override { return 1u << 20; }
};
struct Verifier final : strat::IPowVerifier {
    bool randomx_hash(const std::uint8_t*, std::size_t, std::uint64_t,
                      const std::array<std::uint8_t, strat::HASH_SIZE>&,
                      std::array<std::uint8_t, strat::HASH_SIZE>& out, bool) override { out.fill(0); return true; }
    bool meets_target(const std::array<std::uint8_t, strat::HASH_SIZE>&, std::uint64_t) const override { return true; }
};
struct Sink final : strat::IShareSink {
    void on_accepted_share(const strat::AcceptedShare&) override {}
    void submit_network_block(std::uint32_t, std::uint32_t, std::uint32_t) override {}
};

int dial(std::uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in d{}; d.sin_family = AF_INET; d.sin_port = htons(port); d.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&d), sizeof d) != 0) { ::close(fd); return -1; }
    return fd;
}
void send_raw(int fd, const std::string& s) { (void)!::write(fd, s.data(), s.size()); }
std::string read_line(int fd, int timeout_ms) {
    std::string buf;
    const auto until = Clock::now() + std::chrono::milliseconds(timeout_ms);
    while (Clock::now() < until) {
        pollfd p{fd, POLLIN, 0};
        if (::poll(&p, 1, 20) <= 0) continue;
        char c;
        const ssize_t n = ::read(fd, &c, 1);
        if (n <= 0) return buf.empty() ? std::string("<EOF>") : buf;
        if (c == '\n') return buf;
        buf.push_back(c);
    }
    return buf;
}

struct Rig {
    Templates tpl; Verifier ver; Sink sink;
    o2::StratumListener L;
    explicit Rig(o2::StratumListenerOptions o) : L(tpl, ver, sink, o) {}
    bool up() { if (!L.bind().empty()) return false; L.notify_new_template(); return L.start(); }
};
o2::StratumListenerOptions opts() {
    o2::StratumListenerOptions o; o.bind_host = "127.0.0.1"; o.bind_port = 0; o.poll_timeout_ms = 50; return o;
}

// A keepalived request of exactly `total` bytes (no terminator).
std::string keepalived_exact(std::uint32_t id, std::size_t total) {
    const std::string head = "{\"id\":" + std::to_string(id) + R"(,"jsonrpc":"2.0","method":"keepalived","params":{"pad":")";
    const std::string tail = "\"}}";
    return head + std::string(total - head.size() - tail.size(), 'A') + tail;
}
std::string keepalived(std::uint32_t id) {
    return "{\"id\":" + std::to_string(id) + R"(,"jsonrpc":"2.0","method":"keepalived","params":{}})";
}
std::string submit_line(std::uint32_t id, const std::string& job_id, const std::string& nonce) {
    return "{\"id\":" + std::to_string(id) + R"(,"jsonrpc":"2.0","method":"submit","params":{"id":"1","job_id":")" +
           job_id + R"(","nonce":")" + nonce + R"(","result":")" + std::string(64, '0') + "\"}}\n";
}
bool status_ok(const std::string& r, std::uint32_t id) {
    return r.find("\"id\":" + std::to_string(id) + ",") != std::string::npos &&
           r.find("\"status\":\"OK\"") != std::string::npos;
}
void pause_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

} // namespace

int main() {
    int fails = 0;
    auto check = [&](const char* name, bool ok, const std::string& d = {}) {
        if (!ok) ++fails;
        std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, d.empty() ? "" : "  -- ", d.c_str());
        std::fflush(stdout);
    };
    std::printf("== v37_xmr_stratum_line_cap_kat ==\n");

    // ── LC1 line_over_cap ───────────────────────────────────────────────────
    {
        Rig R(opts());
        check("LC1 listener up", R.up());
        const int fd = dial(R.L.bound_port());
        check("LC1 dial", fd >= 0);
        // A well-formed, shallow keepalived request padded past the 64 KiB line
        // cap (but under the 4x recv backlog, so it reaches the drain).
        // keepalived needs no login, so before the cap it draws a status reply.
        std::string pad(64u * 1024u + 256u, 'A');
        std::string line = R"({"id":7,"jsonrpc":"2.0","method":"keepalived","params":{"pad":")" + pad + R"("}})" + "\n";
        send_raw(fd, line);
        const std::string r = read_line(fd, 2000);
        check("LC1 an over-cap line is closed before dispatch (no reply)", r == "<EOF>", "reply='" + r + "'");
        if (fd >= 0) ::close(fd);
        R.L.stop();
    }

    // ── LC2 empty_line_run ──────────────────────────────────────────────────
    {
        Rig R(opts());
        check("LC2 listener up", R.up());
        const int fd = dial(R.L.bound_port());
        check("LC2 dial", fd >= 0);
        std::string blanks(72, '\n');   // past the 64-line run cap
        const std::string login =
            R"({"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"4TESTADDRESS.w1","pass":"x","agent":"x"}})";
        send_raw(fd, blanks + login + "\n");
        const std::string r = read_line(fd, 2000);
        check("LC2 a blank-line run past the cap closes before the login is served", r == "<EOF>", "reply='" + r + "'");
        if (fd >= 0) ::close(fd);
        R.L.stop();
    }

    const std::string login =
        R"({"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"4TESTADDRESS.w1","pass":"x","agent":"x"}})";

    // ── LC3 submit_log_fields_clipped ───────────────────────────────────────
    {
        Rig R(opts());
        check("LC3 listener up", R.up());
        const int fd = dial(R.L.bound_port());
        check("LC3 dial", fd >= 0);
        send_raw(fd, login + "\n");
        const std::string rl = read_line(fd, 3000);
        check("LC3 login served", rl.find("\"job_id\"") != std::string::npos, "reply='" + rl.substr(0, 60) + "'");
        const std::string long_hex(60000, 'f');   // a hex job_id that names no job
        const std::string long_nonce(60000, 'n');
        std::vector<std::string> logs;
        auto collect = [&] { for (auto& l : R.L.drain_log()) logs.push_back(std::move(l)); };
        auto count = [&](const char* needle) {
            return std::count_if(logs.begin(), logs.end(),
                                 [&](const std::string& l) { return l.find(needle) != std::string::npos; });
        };
        auto wait_for = [&](const char* needle, long want) {
            for (int i = 0; i < 100 && count(needle) < want; ++i) { pause_ms(10); collect(); }
            return count(needle) >= want;
        };
        // rejected path, long job_id
        send_raw(fd, submit_line(2, long_hex, "00000001"));
        const std::string r2 = read_line(fd, 3000);
        check("LC3 long job_id answered 'Invalid job id'", r2.find("Invalid job id") != std::string::npos, "reply='" + r2.substr(0, 80) + "'");
        // duplicate path, the same (job_id, nonce)
        send_raw(fd, submit_line(3, long_hex, "00000001"));
        const std::string r3 = read_line(fd, 3000);
        check("LC3 repeated long job_id answered 'Duplicate share'", r3.find("Duplicate share") != std::string::npos, "reply='" + r3.substr(0, 80) + "'");
        // rejected path, long nonce
        send_raw(fd, submit_line(4, "0", long_nonce));
        const std::string r4 = read_line(fd, 3000);
        check("LC3 long nonce answered 'Invalid job id'", r4.find("Invalid job id") != std::string::npos, "reply='" + r4.substr(0, 80) + "'");
        check("LC3 rejected-path log lines present", wait_for("submit REJECTED: Invalid job id", 2));
        check("LC3 duplicate-path log line present", wait_for("submit REJECTED: duplicate", 1));
        std::size_t longest = 0;
        for (const auto& l : logs) longest = std::max(longest, l.size());
        check("LC3 every log line under 1 KiB", longest < 1024, "longest=" + std::to_string(longest));
        if (fd >= 0) ::close(fd);
        R.L.stop();
    }

    const std::size_t cap = opts().max_line_bytes;

    // ── LC4 line_cap_crlf ───────────────────────────────────────────────────
    {
        Rig R(opts());
        check("LC4 listener up", R.up());
        const int fd = dial(R.L.bound_port());
        send_raw(fd, keepalived_exact(41, cap) + "\r\n");
        const std::string r = read_line(fd, 2000);
        check("LC4 a line of exactly the cap with CRLF is served", status_ok(r, 41), "reply='" + r.substr(0, 60) + "'");
        send_raw(fd, keepalived_exact(42, cap) + "\r");
        pause_ms(50);
        send_raw(fd, "\n");
        const std::string r2 = read_line(fd, 2000);
        check("LC4 the same with '\\r' and '\\n' in separate reads is served", status_ok(r2, 42), "reply='" + r2.substr(0, 60) + "'");
        if (fd >= 0) ::close(fd);
        const int fd2 = dial(R.L.bound_port());
        send_raw(fd2, keepalived_exact(43, cap + 1) + "\r\n");
        const std::string r3 = read_line(fd2, 2000);
        check("LC4 a line of the cap + 1 with CRLF is closed", r3 == "<EOF>", "reply='" + r3.substr(0, 60) + "'");
        if (fd2 >= 0) ::close(fd2);
        R.L.stop();
    }

    // ── LC5 split_reads ─────────────────────────────────────────────────────
    {
        Rig R(opts());
        check("LC5 listener up", R.up());
        const int fd = dial(R.L.bound_port());
        const std::string a = keepalived(51), b = keepalived(52), c = keepalived(53);
        send_raw(fd, a + "\n" + b.substr(0, 10));
        pause_ms(30);
        send_raw(fd, b.substr(10, 15));
        pause_ms(30);
        send_raw(fd, b.substr(25));
        pause_ms(30);
        send_raw(fd, "\n" + c.substr(0, 5));
        pause_ms(30);
        send_raw(fd, c.substr(5) + "\n");
        const std::string r1 = read_line(fd, 2000), r2 = read_line(fd, 2000), r3 = read_line(fd, 2000);
        check("LC5 first request answered", status_ok(r1, 51), "reply='" + r1.substr(0, 60) + "'");
        check("LC5 second request answered", status_ok(r2, 52), "reply='" + r2.substr(0, 60) + "'");
        check("LC5 third request answered", status_ok(r3, 53), "reply='" + r3.substr(0, 60) + "'");
        if (fd >= 0) ::close(fd);
        R.L.stop();
    }

    std::printf("%s: %d failures\n", fails ? "FAILED" : "OK", fails);
    return fails ? 1 : 0;
}
