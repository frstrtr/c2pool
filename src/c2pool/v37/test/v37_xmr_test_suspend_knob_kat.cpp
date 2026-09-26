// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_test_suspend_knob_kat.cpp   (FAULT-KNOB)
//
// The TEST-ONLY lane-suspend fault knob (--test-suspend-lane-seconds S, fired
// by SIGUSR2; xmr/xmr_test_suspend_knob.hpp). Proves:
//   FK1  OFF by default: seconds 0 -> not armed, a fire request is a no-op, the
//        lane never gets the test cause (no behaviour change);
//   FK2  mainnet refusal: --network mainnet with S > 0 is refused with a clear
//        message; S = 0 on mainnet and S > 0 on regtest/testnet/stagenet are not;
//   FK3  arm -> fire -> release: the fire edge forces LaneSuspendState into a
//        suspension whose ONLY cause is `test`; it holds for S s and releases
//        exactly once at the deadline with a resume edge;
//   FK4  a second fire while active is ignored (never extends) and counted;
//        the knob re-fires after a release;
//   FK5  the knob composes with the real causes: a release while LAG still
//        holds clears `test` but does NOT resume the lane;
//   FK6  end to end through the SAME StratumListener::set_lane_suspended()
//        path the daemon uses: the fire edge drops a mining session, a login
//        during the forced suspension is parked (no error), and the release
//        edge hands BOTH miners a login result + job;
//   FK7  RESUME-FRESH (xmr/xmr_lane_resume_fresh.hpp): the chain advances
//        while the lane is suspended (the daemon does not refresh its template
//        then); the FIRST job the parked login gets after the release is at the
//        CURRENT tip, never the cached pre-suspension template -- asserted
//        before the rest of the loop pass runs, i.e. from what the listener
//        serves the moment its gate opens (RC2 smoke 09-25: h=187 at tip 190);
//   FK8  a resume whose template rebuild fails is HELD: the gate stays closed
//        and the parked login gets nothing until a template on the current tip
//        is built on a later pass; that is its first job.
// Stub template source + verifier over loopback: no RandomX, no monerod.
// Nonzero exit on any failure.
// ===========================================================================
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <string>
#include <thread>
#include <tuple>
#include <utility>

#include "c2pool/v37/xmr/xmr_lane_resume_fresh.hpp"
#include "c2pool/v37/xmr/xmr_lane_suspend_state.hpp"
#include "c2pool/v37/xmr/xmr_stratum_listener.hpp"
#include "c2pool/v37/xmr/xmr_test_suspend_knob.hpp"

namespace strat = ::v37::xmr::stratum;
using c2pool::v37n::xmr::LaneSuspendState;
using c2pool::v37n::xmr::TestSuspendKnob;
using Clock = std::chrono::steady_clock;

namespace {

struct Templates final : strat::ITemplateSource {
    std::atomic<std::uint32_t> tid{1};
    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
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
// FK7/FK8: the daemon's template cache over an advancing chain. refresh() (main
// thread) re-keys on the tip like the settlement provider: a new template id only
// when the tip moved or the cache was invalidated. The listener thread reads one
// packed (template_id << 32 | height) word, so a job is never torn.
struct TipTemplates final : strat::ITemplateSource {
    std::atomic<std::uint64_t> tip{186};        // chain tip height; the next block is tip + 1
    std::atomic<std::uint64_t> cur{0};          // (template_id << 32) | template height; 0 = none
    std::atomic<bool> fail{false};              // FK8: the rebuild fails
    bool valid = false;
    std::uint32_t next_id = 0;
    void invalidate() { valid = false; }
    bool refresh() {
        if (fail.load()) return false;
        const std::uint64_t h = tip.load() + 1;
        if (valid && (cur.load() & 0xffffffffULL) == h) return true;
        cur.store((static_cast<std::uint64_t>(++next_id) << 32) | h);
        valid = true;
        return true;
    }
    std::uint32_t template_id() const { return static_cast<std::uint32_t>(cur.load() >> 32); }
    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
        const std::uint64_t c = cur.load();
        if (c == 0) return false;
        out.blob.assign(76, 0);
        out.blob[0] = 16;
        out.blob[70] = static_cast<std::uint8_t>(extra_nonce);
        out.template_id = static_cast<std::uint32_t>(c >> 32);
        out.height = c & 0xffffffffULL;
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
std::string read_line(int fd, int timeout_ms) {   // "" on timeout, "<EOF>" on close
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
std::string read_all(int fd, int window_ms) {
    std::string got;
    const auto until = Clock::now() + std::chrono::milliseconds(window_ms);
    while (Clock::now() < until) {
        const int left = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now()).count());
        const std::string l = read_line(fd, left > 0 ? left : 1);
        if (l == "<EOF>") { got += "<EOF>"; break; }
        if (!l.empty()) got += l + "\n";
    }
    return got;
}
const char* kLogin = R"({"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"4TESTADDRESS.w1","pass":"x","agent":"XMRig/6.22.2"}})";
bool is_login_result(const std::string& l) {
    return l.find("\"id\":1") != std::string::npos && l.find("\"result\"") != std::string::npos &&
           l.find("\"job\"") != std::string::npos && l.find("\"error\":{") == std::string::npos;
}
std::string first_line(const std::string& s) { return s.substr(0, std::min<std::size_t>(s.find('\n'), 80)); }
long job_height(const std::string& l) {   // the "height" of the job in a login result / job push; -1 if none
    const auto p = l.find("\"height\":");
    if (p == std::string::npos) return -1;
    return std::strtol(l.c_str() + p + 9, nullptr, 10);
}

} // namespace

int main() {
    int fails = 0, n = 0;
    auto check = [&](const char* name, bool ok, const std::string& detail = {}) {
        ++n; if (!ok) ++fails;
        std::printf("  [%s] %s%s%s\n", ok ? "PASS" : "FAIL", name, detail.empty() ? "" : "  -- ", detail.c_str());
    };
    std::printf("== v37_xmr_test_suspend_knob_kat ==\n");
    constexpr std::uint64_t kLagOk = 0;   // lag well inside the resume band

    // ── FK1: off by default ────────────────────────────────────────────────
    {
        TestSuspendKnob k;                       // default = --test-suspend-lane-seconds absent
        LaneSuspendState ls(3);
        bool any_force = false, any_edge = false;
        for (std::uint64_t t = 0; t < 10000; t += 400) {
            const auto s = k.step(true, t, ls);  // even a (spurious) fire request every pass
            const auto e = ls.update(kLagOk, false, false, false);
            any_force |= s.fired || s.released || ls.test_forced;
            any_edge |= e.suspend_edge || e.resume_edge;
        }
        check("FK1 OFF by default: not armed, a fire request is a no-op, no test cause, no suspend/resume edge",
              !k.armed() && !any_force && !any_edge && k.n_fired == 0 && !ls.suspended() && ls.n_test == 0);
    }

    // ── FK2: mainnet refusal ───────────────────────────────────────────────
    {
        const std::string m = TestSuspendKnob::refusal(true, 60);
        check("FK2 mainnet + knob is REFUSED with a clear message; mainnet without it, and regtest/stagenet with it, are not",
              !m.empty() && m.find("mainnet") != std::string::npos && m.find("--test-suspend-lane-seconds") != std::string::npos &&
                  TestSuspendKnob::refusal(true, 0).empty() && TestSuspendKnob::refusal(false, 60).empty(),
              "'" + m.substr(0, 70) + "...'");
    }

    // ── FK3: arm -> fire -> release through LaneSuspendState ──────────────
    {
        TestSuspendKnob k(60);
        LaneSuspendState ls(3);
        auto s0 = k.step(false, 1000, ls);
        auto e0 = ls.update(kLagOk, false, false, false);
        const bool armed_idle = k.armed() && !k.active() && !s0.fired && !e0.suspend_edge && !ls.suspended();
        auto s1 = k.step(true, 2000, ls);
        auto e1 = ls.update(kLagOk, false, false, false);
        const bool fire_ok = s1.fired && e1.suspend_edge && e1.causes == LaneSuspendState::kTest &&
                             LaneSuspendState::names(e1.causes) == "test" && ls.n_test == 1;
        bool held = true;
        for (std::uint64_t t = 2400; t < 62000; t += 400) {
            const auto s = k.step(false, t, ls);
            const auto e = ls.update(kLagOk, false, false, false);
            held &= !s.released && ls.suspended() && !e.resume_edge;
        }
        auto s2 = k.step(false, 62000, ls);
        auto e2 = ls.update(kLagOk, false, false, false);
        auto s3 = k.step(false, 62400, ls);
        auto e3 = ls.update(kLagOk, false, false, false);
        check("FK3 armed: the fire edge suspends with cause=test only; held for S s; released ONCE at the deadline with a resume edge",
              armed_idle && fire_ok && held && s2.released && e2.resume_edge && !ls.suspended() && !s3.released && !e3.resume_edge &&
                  k.n_fired == 1 && k.n_released == 1 && ls.n_suspend == 1 && ls.n_resume == 1,
              "fired=" + std::to_string(k.n_fired) + " released=" + std::to_string(k.n_released) +
                  " edges=" + std::to_string(ls.n_suspend) + "/" + std::to_string(ls.n_resume));
    }

    // ── FK4: fire while active never extends; re-fire after release ───────
    {
        TestSuspendKnob k(10);
        LaneSuspendState ls(3);
        k.step(true, 0, ls); ls.update(kLagOk, false, false, false);
        const auto s = k.step(true, 5000, ls); ls.update(kLagOk, false, false, false);
        const auto r = k.step(false, 10000, ls); const auto e = ls.update(kLagOk, false, false, false);
        const auto f2 = k.step(true, 11000, ls); const auto e2 = ls.update(kLagOk, false, false, false);
        check("FK4 a fire while ACTIVE is ignored (release stays at the first deadline); the knob re-fires after a release",
              !s.fired && s.ignored && k.n_ignored == 1 && r.released && e.resume_edge && f2.fired && e2.suspend_edge && k.n_fired == 2);
    }

    // ── FK5: composes with a real cause ────────────────────────────────────
    {
        TestSuspendKnob k(10);
        LaneSuspendState ls(3);
        k.step(true, 0, ls); ls.update(kLagOk, false, false, false);
        k.step(false, 1000, ls); const auto eL = ls.update(7, false, false, false);   // lag 7 > 2*D_conf: LAG rises
        const auto r = k.step(false, 10000, ls); const auto e = ls.update(7, false, false, false);
        k.step(false, 11000, ls); const auto e3 = ls.update(1, false, false, false);   // lag back <= D_conf
        check("FK5 release while LAG still holds clears `test` but does NOT resume; the lane resumes when LAG clears",
              (eL.added & LaneSuspendState::kLag) && r.released && !e.resume_edge && (e.cleared & LaneSuspendState::kTest) &&
                  ls.n_suspend == 1 && e3.resume_edge);
    }

    // ── FK6: end to end through StratumListener::set_lane_suspended() ─────
    {
        Templates tpl; StubVerifier ver; NullSink sink;
        c2pool::v37n::xmr::o2::StratumListenerOptions lo;
        lo.bind_host = "127.0.0.1"; lo.bind_port = 0;
        c2pool::v37n::xmr::o2::StratumListener L(tpl, ver, sink, lo);
        if (std::string e = L.bind(); !e.empty()) { std::printf("  [FAIL] bind: %s\n", e.c_str()); return 1; }
        L.start();
        TestSuspendKnob k(2);
        LaneSuspendState ls(3);
        const auto t_origin = Clock::now();
        auto now_ms = [&] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t_origin).count()); };
        // The daemon's per-pass order: knob step, lane_state.update, listener.set_lane_suspended(lane_state.suspended()).
        auto pass = [&](bool fire_req) {
            const auto s = k.step(fire_req, now_ms(), ls);
            const auto e = ls.update(kLagOk, false, false, false);
            L.set_lane_suspended(ls.suspended());
            return std::make_pair(s, e);
        };
        const int a = connect_to(L.bound_port());
        send_line(a, kLogin);
        const std::string loginA = read_line(a, 3000);
        const auto [sf, ef] = pass(true);                  // SIGUSR2
        const std::string dropA = read_all(a, 800);
        ::close(a);
        const int a2 = connect_to(L.bound_port());         // the dropped miner reconnects
        const int b  = connect_to(L.bound_port());         // a second miner logs in during the forced suspension
        send_line(a2, kLogin);
        send_line(b, kLogin);
        const std::string waitA2 = read_all(a2, 600);
        const std::string waitB  = read_all(b, 600);
        bool released = false; Clock::time_point t_rel{};
        while (!released && now_ms() < 6000) {
            const auto [s, e] = pass(false);
            if (s.released && e.resume_edge) { released = true; t_rel = Clock::now(); }
            else std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const std::string gotA2 = read_line(a2, 3000);
        const long dA2 = static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t_rel).count());
        const std::string gotB = read_line(b, 3000);
        const long dB = static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t_rel).count());
        check("FK6 live listener: fire drops the mining session, a login during the forced suspension is parked (no error), "
              "the release hands BOTH miners a login result + job",
              is_login_result(loginA) && sf.fired && ef.suspend_edge && dropA.find("<EOF>") != std::string::npos &&
                  waitA2.empty() && waitB.empty() && released && is_login_result(gotA2) && is_login_result(gotB),
              "drop='" + first_line(dropA) + "' parked a2='" + first_line(waitA2) + "' b='" + first_line(waitB) +
                  "' | after release a2 " + std::to_string(dA2) + " ms, b " + std::to_string(dB) + " ms");
        ::close(a2); ::close(b);
        L.stop();
    }

    // ── FK7 + FK8: RESUME-FRESH -- the first job after a release is at the current tip ──
    {
        TipTemplates tpl; StubVerifier ver; NullSink sink;
        c2pool::v37n::xmr::o2::StratumListenerOptions lo;
        lo.bind_host = "127.0.0.1"; lo.bind_port = 0;
        c2pool::v37n::xmr::o2::StratumListener L(tpl, ver, sink, lo);
        if (std::string e = L.bind(); !e.empty()) { std::printf("  [FAIL] bind: %s\n", e.c_str()); return 1; }
        tpl.refresh();
        std::uint32_t last_tid = tpl.template_id();
        L.notify_new_template();
        L.start();
        TestSuspendKnob k(1);
        LaneSuspendState ls(3);
        const auto t_origin = Clock::now();
        auto now_ms = [&] { return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t_origin).count()); };
        // The daemon's per-pass order (main_v37_xmr.cpp serve_and_run): knob step, lane_state.update,
        // the stratum gate (apply_lane_gate: on the resume edge the template is rebuilt BEFORE the gate
        // opens), then -- later in the pass -- the loop's own refresh + new-template notify, skipped while
        // the gate is closed. `mid_pass` runs between the two: what the listener hands out the moment the
        // gate opens is observed there, before the loop's refresh could mask a stale job.
        auto pass = [&](bool fire_req, const std::function<void()>& mid_pass) {
            const auto s = k.step(fire_req, now_ms(), ls);
            const auto e = ls.update(kLagOk, false, false, false);
            const bool gate_closed = c2pool::v37n::xmr::apply_lane_gate(L, ls.suspended(), [&] { tpl.invalidate(); return tpl.refresh(); });
            if (mid_pass) mid_pass();
            if (!gate_closed && tpl.refresh() && tpl.template_id() != last_tid) { last_tid = tpl.template_id(); L.notify_new_template(); }
            return std::make_tuple(s, e, gate_closed);
        };
        const int a = connect_to(L.bound_port());
        send_line(a, kLogin);
        const std::string loginA = read_line(a, 3000);
        const long h_before = job_height(loginA);
        pass(true, {});                                    // SIGUSR2: suspend, the session is dropped
        const std::string dropA = read_all(a, 800);
        ::close(a);
        const int a2 = connect_to(L.bound_port());         // the dropped miner reconnects: parked
        send_line(a2, kLogin);
        const std::string waitA2 = read_all(a2, 400);
        tpl.tip.store(190);                                // three blocks + ours arrive while suspended; no refresh
        std::string first; long first_ms = -1; bool released = false;
        while (!released && now_ms() < 8000) {
            Clock::time_point t_rel{};
            const auto [s, e, gate] = pass(false, [&] {
                if (!L.lane_suspended()) { t_rel = Clock::now(); first = read_line(a2, 1500);
                    first_ms = static_cast<long>(std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t_rel).count()); }
            });
            if (s.released) released = true;
            else std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const std::string more = read_all(a2, 300);       // anything else pushed in the rest of that pass
        const long h_first = job_height(first);
        const long h_tip_next = static_cast<long>(tpl.tip.load() + 1);
        check("FK7 RESUME-FRESH: the chain advanced under the suspension; the FIRST job the parked login gets after the "
              "release is at the current tip (never the cached pre-suspension template)",
              is_login_result(loginA) && h_before == 187 && dropA.find("<EOF>") != std::string::npos && waitA2.empty() &&
                  released && is_login_result(first) && h_first == h_tip_next && more.find("\"height\":187") == std::string::npos,
              "before=" + std::to_string(h_before) + " tip+1=" + std::to_string(h_tip_next) + " first job h=" +
                  std::to_string(h_first) + " after " + std::to_string(first_ms) + " ms");

        // FK8: a resume whose rebuild fails is HELD (gate closed), served at the tip once the rebuild succeeds.
        pass(true, {});                                    // the knob re-fires
        const std::string drop2 = read_all(a2, 800);
        ::close(a2);
        const int a3 = connect_to(L.bound_port());
        send_line(a3, kLogin);
        const std::string wait3 = read_all(a3, 400);
        tpl.tip.store(193);
        tpl.fail.store(true);
        bool rel2 = false, held_closed = false; std::string during_hold;
        while (!rel2 && now_ms() < 16000) {
            const auto [s, e, gate] = pass(false, {});
            if (s.released) { rel2 = true; held_closed = gate && L.lane_suspended() && e.resume_edge; }
            else std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        const auto [s2, e2, gate2] = pass(false, [&] { during_hold = read_all(a3, 500); });   // still failing: still held
        tpl.tip.store(194);
        tpl.fail.store(false);
        std::string first3;
        const auto [s3, e3, gate3] = pass(false, [&] { first3 = read_line(a3, 1500); });
        check("FK8 a resume whose rebuild fails is HELD (gate closed, the parked login gets nothing); the next pass that "
              "builds a template on the current tip opens the gate and that is the first job",
              drop2.find("<EOF>") != std::string::npos && wait3.find("\"height\"") == std::string::npos && rel2 && held_closed &&
                  gate2 && during_hold.find("\"height\"") == std::string::npos && !gate3 && is_login_result(first3) &&
                  job_height(first3) == 195,
              "held=" + std::to_string(held_closed) + " during_hold='" + first_line(during_hold) + "' first job h=" +
                  std::to_string(job_height(first3)) + " (tip+1=195)");
        ::close(a3);
        L.stop();
    }

    std::printf("== %s (%d/%d passed) ==\n", fails ? "FAIL" : "OK", n - fails, n);
    return fails ? 1 : 0;
}
