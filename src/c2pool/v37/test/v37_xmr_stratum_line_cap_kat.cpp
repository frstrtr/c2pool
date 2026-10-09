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
// Nonzero exit on any failure.
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdio>
#include <string>

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

    std::printf("%s: %d failures\n", fails ? "FAILED" : "OK", fails);
    return fails ? 1 : 0;
}
