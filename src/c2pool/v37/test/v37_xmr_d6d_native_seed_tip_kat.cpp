// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_d6d_native_seed_tip_kat.cpp
//
// D6d: UNDER p2p-first THE NATIVE NODE IS THE TIP, THE SEED AND THE HEIGHT, AND
// NOTHING POLLS MONEROD FOR THEM.
//
// After D6a (booking) and D6b (relay chain-view feed) the only monerod traffic a
// p2p-first + native-template node still made was a trio, once per status tick
// for the life of the process: get_miner_data (the C6 parity judge's shadow
// arm), get_info and get_last_block_header (its tip observation). Everything
// that trio reads -- tip, RandomX seed hash/height, difficulty/height -- the
// embedded node already answers from its own RandomX-verified chain index, and
// under p2p-first nothing on the find path ever read the daemon's answer. The
// judge only COMPARED. So under p2p-first the daemon endpoint is now withheld
// from the embedded node unless --native-parity-monerod asks for the judge back
// as an explicit, compare-only oracle. Daemon-first is unchanged.
//
//   A  THE FORWARD. native_template_config_of() -- the one derivation main runs
//      -- hands the embedded node NO monerod endpoint under p2p-first by
//      default; still hands it one under daemon-first; hands it one under
//      p2p-first only when --native-parity-monerod was parsed (by the pool
//      binary's own flag function); and --no-daemon-rpc / --native-solo still
//      win over the flag.
//   B  THE WIRE. A real NativeTemplateBackend is started on each derived
//      config against a fake monerod that counts connections per JSON-RPC
//      method, and the status cadence main runs (poll_shadow() +
//      parity_sample()) is driven for several ticks. p2p-first: ZERO requests,
//      no daemon arm, and the oracle still exists (native side observed).
//      Controls in the same file: daemon-first and p2p-first +
//      --native-parity-monerod both reach the fake with the exact trio, so a
//      zero cannot come from a harness that sees nothing.
//   C  THE SEED EPOCH the native index keys its answer on: rx_seedheight()
//      switches at 2048*k + 64 + 1 (the first block after the lag window) and
//      nowhere else, and the next-seed prefetch opens exactly 64 blocks early.
//
// No RandomX hashing, no real daemon, no peers (the one pinned peer is a closed
// port). Listed in both build.yml --target lists (the #1539 lesson).
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "c2pool/v37/xmr/xmr_native_template_backend.hpp"
#include "c2pool/v37/xmr/xmr_node_config.hpp"
#include "impl/xmr/coin/xmr_seedheight.hpp"

namespace cfgns = c2pool::v37n::xmr;
namespace o2    = c2pool::v37n::xmr::o2;

using cfgns::ArmOrderMode;
using cfgns::CoinbaseMode;
using cfgns::MoneroNetwork;
using cfgns::TemplateSourceMode;
using cfgns::XmrNodeConfig;

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; std::printf("  ok   %s\n", what.c_str()); return; }
    ++g_fail;
    std::printf("  FAIL %s\n", what.c_str());
}

// The pool binary's own flag function over a whole argv, as main's loop runs it.
// Returns the number of tokens it consumed.
int parse_native_flags(XmrNodeConfig& c, const std::vector<std::string>& args) {
    std::vector<const char*> argv;
    for (const auto& a : args) argv.push_back(a.c_str());
    const int argc = static_cast<int>(argv.size());
    int consumed = 0;
    for (int i = 0; i < argc; ++i) {
        std::string err;
        const int used = cfgns::apply_native_node_flag(c, argc, argv.data(), i, err);
        if (used <= 0) continue;
        consumed += used;
        i += used - 1;
    }
    return consumed;
}

// ---------------------------------------------------------------------------
// A fake monerod: accepts on 127.0.0.1:<ephemeral>, records the JSON-RPC
// "method" (or the direct endpoint path) of every request, answers 200 "{}" and
// closes. Its counts are the wire, exactly as the rig's RPC proxies count it.
// ---------------------------------------------------------------------------
class FakeMonerod {
public:
    bool start() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port   = 0;
        ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
        if (::listen(fd_, 16) != 0) return false;
        socklen_t len = sizeof(a);
        if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &len) != 0) return false;
        port_ = ntohs(a.sin_port);
        th_ = std::thread([this] { loop_(); });
        return true;
    }
    void stop() {
        if (stop_.exchange(true)) return;
        {   // wake a blocked accept() with one throwaway connection
            const int w = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_port   = htons(port_);
            ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
            if (w >= 0) { (void)::connect(w, reinterpret_cast<sockaddr*>(&a), sizeof(a)); ::close(w); }
        }
        ::shutdown(fd_, SHUT_RDWR);
        ::close(fd_);
        if (th_.joinable()) th_.join();
    }
    ~FakeMonerod() { stop(); }

    std::uint16_t port() const { return port_; }
    std::map<std::string, int> counts() {
        std::lock_guard<std::mutex> lk(mu_);
        return counts_;
    }
    int total() {
        int n = 0;
        for (const auto& kv : counts()) n += kv.second;
        return n;
    }
    void reset() { std::lock_guard<std::mutex> lk(mu_); counts_.clear(); }

private:
    void loop_() {
        while (!stop_.load()) {
            const int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) { if (stop_.load()) return; continue; }
            if (stop_.load()) { ::close(c); return; }
            timeval tv{2, 0};
            ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            std::string raw;
            char buf[4096];
            for (;;) {   // read the header, then Content-Length bytes of body
                const ssize_t n = ::recv(c, buf, sizeof(buf), 0);
                if (n <= 0) break;
                raw.append(buf, static_cast<std::size_t>(n));
                const auto he = raw.find("\r\n\r\n");
                if (he == std::string::npos) continue;
                std::size_t cl = 0;
                const auto p = raw.find("Content-Length:");
                if (p != std::string::npos && p < he) cl = std::strtoul(raw.c_str() + p + 15, nullptr, 10);
                if (raw.size() >= he + 4 + cl) break;
            }
            std::string method = "?";
            const auto m = raw.find("\"method\"");
            if (m != std::string::npos) {
                const auto q1 = raw.find('"', raw.find(':', m) + 1);
                const auto q2 = (q1 == std::string::npos) ? q1 : raw.find('"', q1 + 1);
                if (q2 != std::string::npos) method = raw.substr(q1 + 1, q2 - q1 - 1);
            } else if (raw.rfind("POST /", 0) == 0) {
                method = raw.substr(6, raw.find(' ', 6) - 6);
            }
            { std::lock_guard<std::mutex> lk(mu_); ++counts_[method]; }
            const std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                     "Content-Length: 2\r\nConnection: close\r\n\r\n{}";
            (void)::send(c, resp.data(), resp.size(), MSG_NOSIGNAL);
            ::close(c);
        }
    }

    int                        fd_ = -1;
    std::uint16_t              port_ = 0;
    std::atomic<bool>          stop_{false};
    std::thread                th_;
    std::mutex                 mu_;
    std::map<std::string, int> counts_;
};

XmrNodeConfig base_cfg(ArmOrderMode order, std::uint16_t rpc_port) {
    XmrNodeConfig c;
    c.network         = MoneroNetwork::Regtest;
    c.coinbase        = CoinbaseMode::V37Settlement;
    c.template_source = TemplateSourceMode::Native;
    c.arm_order       = order;
    c.monerod.rpc_host = "127.0.0.1";
    c.monerod.rpc_port = rpc_port;
    c.native_connect  = {"127.0.0.1:1"};   // a closed port: the node dials nobody real
    c.native_force_synced = true;
    return c;
}

std::string counts_str(const std::map<std::string, int>& m) {
    std::string s = "{";
    for (const auto& kv : m) s += (s.size() > 1 ? ", " : "") + kv.first + "=" + std::to_string(kv.second);
    return s + "}";
}

// ---------------------------------------------------------------------------
// A: the forward
// ---------------------------------------------------------------------------
void section_a() {
    std::printf("A  the forward: which configurations hand the embedded node a monerod endpoint\n");

    {
        const auto n = o2::native_template_config_of(base_cfg(ArmOrderMode::P2PFirst, 58081));
        check(n.monerod_rpc_host.empty() && n.monerod_rpc_port == 0,
              "A1 p2p-first (default): NO monerod endpoint reaches the embedded node -- the "
              "native index is tip, seed and height, and the parity trio is not polled");
    }
    {
        const auto n = o2::native_template_config_of(base_cfg(ArmOrderMode::DaemonFirst, 58081));
        check(n.monerod_rpc_host == "127.0.0.1" && n.monerod_rpc_port == 58081,
              "A2 daemon-first: the endpoint is still forwarded (parity judge + submit arm), unchanged");
    }
    {
        XmrNodeConfig c = base_cfg(ArmOrderMode::P2PFirst, 58081);
        const int used = parse_native_flags(c, {"--native-parity-monerod"});
        check(used == 1, "A3 --native-parity-monerod is a native-node flag the pool binary parses "
                         "(consumed " + std::to_string(used) + " token)");
        const auto n = o2::native_template_config_of(c);
        check(n.monerod_rpc_host == "127.0.0.1" && n.monerod_rpc_port == 58081,
              "A4 p2p-first + --native-parity-monerod: the compare-only judge gets its endpoint");
        XmrNodeConfig d = c;
        d.no_daemon_rpc = true;
        const auto nd = o2::native_template_config_of(d);
        check(nd.monerod_rpc_host.empty() && nd.monerod_rpc_port == 0,
              "A5 --no-daemon-rpc still wins over --native-parity-monerod");
    }
    {
        XmrNodeConfig c = base_cfg(ArmOrderMode::P2PFirst, 58081);
        c.native_connect.clear();
        c.native_solo = true;
        (void)parse_native_flags(c, {"--native-parity-monerod"});
        const auto n = o2::native_template_config_of(c);
        check(n.monerod_rpc_host.empty() && n.monerod_rpc_port == 0,
              "A6 --native-solo still has no daemon, flag or not");
    }
    {
        // Everything else about the p2p-first forward is untouched: the fallback
        // stays pinned off and the relay order is P2pOnly.
        const auto n = o2::native_template_config_of(base_cfg(ArmOrderMode::P2PFirst, 58081));
        check(!n.fallback && n.relay_order == c2pool::xmr::native::ArmOrder::P2pOnly,
              "A7 p2p-first keeps fallback OFF and relay order P2pOnly (no other forward moved)");
    }
}

// ---------------------------------------------------------------------------
// B: the wire, through a real embedded node
// ---------------------------------------------------------------------------
struct WireRun {
    bool                       started = false;
    std::string                why;
    std::map<std::string, int> counts;
    bool                       has_daemon_arm = false;
    bool                       has_oracle     = false;
};

WireRun run_wire(const XmrNodeConfig& cfg, FakeMonerod& fake, int ticks, const char* tag) {
    WireRun r;
    o2::NativeTemplateConfig ncfg = o2::native_template_config_of(cfg);
    ncfg.allow_unverified_pow = true;   // no hashing happens here either way
    ncfg.ready_timeout_s      = 1;
    const auto dir = std::filesystem::temp_directory_path() /
                     ("d6d_kat_" + std::to_string(::getpid()) + "_" +
                      tag);
    std::filesystem::create_directories(dir);
    ncfg.parity_ledger_path = (dir / "parity.json").string();

    fake.reset();
    {
        o2::NativeTemplateBackend b(ncfg);
        r.started = b.start(r.why);
        if (r.started) {
            r.has_daemon_arm = (b.node()->monerod_source() != nullptr);
            r.has_oracle     = (b.oracle() != nullptr);
            // The status cadence exactly as main's status_extra drives it.
            for (int t = 0; t < ticks; ++t) {
                std::string pw;
                (void)b.poll_shadow(&pw);
                (void)b.node()->parity_sample();
                std::this_thread::sleep_for(std::chrono::milliseconds(20));
            }
        }
        b.stop();
    }
    r.counts = fake.counts();
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    return r;
}

void section_b() {
    std::printf("B  the wire: a started embedded node, the status cadence, a counting fake monerod\n");
    FakeMonerod fake;
    if (!fake.start()) { check(false, "B0 the fake monerod listens"); return; }
    constexpr int kTicks = 4;

    {
        const WireRun r = run_wire(base_cfg(ArmOrderMode::P2PFirst, fake.port()), fake, kTicks, "p2p");
        check(r.started, "B1 p2p-first: the embedded node starts (" + r.why + ")");
        int total = 0;
        for (const auto& kv : r.counts) total += kv.second;
        check(total == 0, "B2 p2p-first: " + std::to_string(kTicks) + " status ticks put ZERO "
                          "requests on the daemon socket " + counts_str(r.counts));
        check(!r.has_daemon_arm, "B3 p2p-first: the node built no daemon (get_miner_data) arm");
        check(r.has_oracle, "B4 p2p-first: the parity oracle still exists (native side observed)");
    }
    {
        const WireRun r = run_wire(base_cfg(ArmOrderMode::DaemonFirst, fake.port()), fake, kTicks, "daemon");
        check(r.started, "B5 daemon-first control: the embedded node starts (" + r.why + ")");
        const auto get = [&](const char* m) { auto it = r.counts.find(m); return it == r.counts.end() ? 0 : it->second; };
        check(get("get_miner_data") >= kTicks && get("get_info") >= kTicks &&
                  get("get_last_block_header") >= kTicks,
              "B6 daemon-first control: the SAME harness sees the trio every tick " + counts_str(r.counts));
    }
    {
        XmrNodeConfig c = base_cfg(ArmOrderMode::P2PFirst, fake.port());
        (void)parse_native_flags(c, {"--native-parity-monerod"});
        const WireRun r = run_wire(c, fake, kTicks, "judge");
        check(r.started, "B7 p2p-first + --native-parity-monerod: the node starts (" + r.why + ")");
        const auto get = [&](const char* m) { auto it = r.counts.find(m); return it == r.counts.end() ? 0 : it->second; };
        check(r.has_daemon_arm && get("get_miner_data") >= kTicks && get("get_info") >= kTicks &&
                  get("get_last_block_header") >= kTicks,
              "B8 the explicit compare-only judge is reachable and makes exactly the trio " +
                  counts_str(r.counts));
    }
    fake.stop();
}

// ---------------------------------------------------------------------------
// C: the seed epoch the native index answers on
// ---------------------------------------------------------------------------
void section_c() {
    std::printf("C  the RandomX seed epoch (2048 blocks, 64-block lag)\n");
    using ::xmr::coin::rx_seedheight;
    using ::xmr::coin::rx_seedheights;
    check(rx_seedheight(0) == 0 && rx_seedheight(2112) == 0,
          "C1 heights 0..2112 use the genesis seed (the lag window holds epoch 0 past 2048)");
    check(rx_seedheight(2113) == 2048 && rx_seedheight(4160) == 2048,
          "C2 the seed switches to block 2048 at height 2113 and holds through 4160");
    check(rx_seedheight(4161) == 4096, "C3 and to block 4096 at height 4161");
    bool one_step = true;
    std::uint64_t switches = 0;
    for (std::uint64_t h = 1; h <= 3 * 2048 + 200; ++h) {
        const std::uint64_t a = rx_seedheight(h - 1), b = rx_seedheight(h);
        if (a != b) {
            ++switches;
            if (b != a + 2048 || (h - 64 - 1) % 2048 != 0) one_step = false;
        }
    }
    check(one_step && switches == 3,
          "C4 over 0..6344 the seed moves exactly three times, one epoch at a time, each at 2048k+65");
    std::uint64_t s = 0, nx = 0;
    rx_seedheights(2048 + 1, s, nx);
    check(s == 0 && nx == 2048, "C5 the next-seed prefetch opens 64 blocks early (h=2049: next=2048)");
    rx_seedheights(2048, s, nx);
    check(s == 0 && nx == 0, "C6 and not a block earlier (h=2048: next still 0)");
}

}  // namespace

int main() {
    std::printf("v37_xmr_d6d_native_seed_tip_kat -- p2p-first: tip/seed/height from the native "
                "node, no monerod poll trio\n");
    section_a();
    section_b();
    section_c();
    std::printf("\n%d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
