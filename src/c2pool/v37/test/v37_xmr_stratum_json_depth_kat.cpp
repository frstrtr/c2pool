// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_stratum_json_depth_kat.cpp
//
// The XMR stratum listener's JSON nesting limit and \u-escape check, over a
// loopback socket, before login. The exchange runs in a child process; the
// test passes when the child exits 0 and fails on any other exit status or
// signal.
//   JD1  nested_depth_over_limit : a request line nested past max_json_depth,
//        whose string holds a malformed \u escape, is refused and its
//        connection closed; a later login on a new connection is served.
// ===========================================================================
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <unistd.h>

#include <atomic>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>

#include "c2pool/v37/xmr/xmr_stratum_listener.hpp"

namespace strat = ::v37::xmr::stratum;
namespace o2 = ::c2pool::v37n::xmr::o2;
using Clock = std::chrono::steady_clock;

namespace {

constexpr std::uint64_t kMax = 0xFFFFFFFFFFFFFFFFULL;

struct Templates final : strat::ITemplateSource {
    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
        out.blob.assign(76, 0);
        out.blob[0] = 16;
        out.blob[70] = static_cast<std::uint8_t>(extra_nonce);
        out.template_id = 1;
        out.height = 100;
        out.mainchain_target = 0;
        out.lane_target = kMax / 1000000;
        out.monero_major_version = 16;
        return true;
    }
    bool rebuild_blob(std::uint32_t, std::uint32_t en, strat::TemplateJob& out) override { return get_job(en, out); }
    std::uint32_t max_extra_nonces() const override { return 1u << 20; }
};
struct Verifier final : strat::IPowVerifier {
    bool randomx_hash(const std::uint8_t*, std::size_t, std::uint64_t,
                      const std::array<std::uint8_t, strat::HASH_SIZE>&,
                      std::array<std::uint8_t, strat::HASH_SIZE>& out, bool) override {
        out.fill(0);
        return true;
    }
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
void send_line(int fd, const std::string& s) { const std::string l = s + "\n"; (void)!::write(fd, l.data(), l.size()); }
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

// Child: send the JD1 line, then log in on a new connection.
// Exit 0 when both steps behave as asserted, non-zero otherwise.
int child_body() {
    ::alarm(30);   // a child still running after 30 s fails the test
    o2::StratumListenerOptions o;
    o.bind_host = "127.0.0.1"; o.bind_port = 0; o.poll_timeout_ms = 50;
    Templates tpl; Verifier ver; Sink sink;
    o2::StratumListener L(tpl, ver, sink, o);
    if (!L.bind().empty()) return 2;
    L.notify_new_template();
    if (!L.start()) return 3;
    const std::uint16_t port = L.bound_port();

    // JD1 line: a string with a malformed \u escape, then 63000 '[' (under the
    // 64 KiB line cap).
    int fd = dial(port);
    if (fd < 0) { L.stop(); return 4; }
    std::string line = "[\"\\uabc\\\",";
    line.append(63000, '[');
    send_line(fd, line);
    // Expected: the line is refused (no reply, or a "Malformed request" error)
    // and the connection is closed.
    std::string r1 = read_line(fd, 2000);
    if (r1.find("Malformed") != std::string::npos) r1 = read_line(fd, 2000);
    ::close(fd);
    if (r1 != "<EOF>") { L.stop(); return 7; }

    // Expected: a login on a new connection gets a job.
    int fd2 = dial(port);
    if (fd2 < 0) { L.stop(); return 5; }
    send_line(fd2,
        R"({"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"4TESTADDRESS.w1","pass":"x","agent":"XMRig/6.22.2"}})");
    const std::string r = read_line(fd2, 3000);
    ::close(fd2);
    L.stop();
    const bool alive = r.find("\"job_id\"") != std::string::npos ||
                       r.find("\"result\"") != std::string::npos;
    return alive ? 0 : 6;
}

} // namespace

int main() {
    std::printf("== v37_xmr_stratum_json_depth_kat ==\n");
    std::fflush(stdout);
    const pid_t pid = ::fork();
    if (pid < 0) { std::printf("  [FAIL] JD1 fork() failed\n"); return 1; }
    if (pid == 0) { std::_Exit(child_body()); }

    int status = 0;
    ::waitpid(pid, &status, 0);
    bool pass = false; std::string why;
    if (WIFSIGNALED(status)) {
        why = std::string("child ended by signal ") + std::to_string(WTERMSIG(status));
    } else if (WIFEXITED(status)) {
        const int code = WEXITSTATUS(status);
        if (code == 0) pass = true;
        else why = "child exited " + std::to_string(code);
    } else {
        why = "child did not exit normally";
    }
    std::printf("  [%s] JD1 nested_depth_over_limit%s%s\n", pass ? "PASS" : "FAIL",
                why.empty() ? "" : "  -- ", why.c_str());
    std::printf("%s\n", pass ? "OK" : "FAILED");
    return pass ? 0 : 1;
}
