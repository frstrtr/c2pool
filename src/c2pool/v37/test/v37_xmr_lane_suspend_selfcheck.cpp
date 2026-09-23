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
// Stub template source + stub verifier (no RandomX). Port 5771 (loopback;
// falls back to an ephemeral port if taken).
// Nonzero exit on any failure.
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
    std::printf("== %s (%d/%d passed) ==\n", fails ? "FAIL" : "OK", n - fails, n);
    return fails ? 1 : 0;
}
