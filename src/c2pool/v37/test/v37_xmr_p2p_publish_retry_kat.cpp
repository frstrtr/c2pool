// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_p2p_publish_retry_kat.cpp
//
// THE DAEMONLESS PUBLISH ARM WHEN THE FIRST PUSH REACHES NOBODY.
//
// P2pBlockPublisher's success condition is a peer receipt. Until this branch a
// found block whose 2008 reached no peer (every monerod restarting, every link
// just re-dialled) was counted and DROPPED: it sat on our own index, nobody
// was ever told about it, and no FoundBlockEvent was pushed. Now it is parked
// and re-announced on a bounded backoff. Pinned here, with an injected clock:
//
//   R1  zero peers -> parked, NOT booked, NOT silently dropped; failed() still
//       counts the first push exactly as before.
//   R2  a peer appears -> the next due tick re-announces, and THE one
//       FoundBlockEvent is pushed; later ticks send nothing and push nothing,
//       and a repeated submit of the same block is not a second event.
//   R3  peers never appear -> bounded: at most max_attempts re-announce frames,
//       nothing past the window, ABANDONED at ERROR, nothing booked -- and the
//       line says whether the block is on our own best chain.
//   R4  our own best chain no longer carries the block -> dropped on the first
//       due tick without another frame (re-announcing a lost height helps no
//       one).
//   R5  what did NOT change: solo keeps its own rule, a refused block is never
//       parked, and a block that reached a peer first time is booked at once.
//
// No sockets, no daemon, no RandomX, no threads. Links xmr_node + xmr_coin.
//
// HOLLOW-GREEN GUARD: listed in BOTH build.yml `--target` lists (Linux x86_64
// and ASan+UBSan), or ctest reports it "***Not Run" (the #1539 lesson).
// ===========================================================================
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_p2p_block_publisher.hpp"
#include "impl/xmr/native/contracts/fakes/fakes.hpp"
#include "impl/xmr/native/relay/xmr_block_relay.hpp"

#include "xmr_c2a_golden.hpp"

using namespace c2pool::v37n::xmr;
namespace native = ::c2pool::xmr::native;
namespace submit = ::c2pool::v37n::xmr::submit;

static int g_pass = 0, g_fail = 0;

static void check(bool ok, const std::string& what, const std::string& detail = {}) {
    if (ok) {
        ++g_pass;
        std::printf("  [ok]   %s\n", what.c_str());
        return;
    }
    ++g_fail;
    std::printf("  [FAIL] %s%s%s\n", what.c_str(), detail.empty() ? "" : " -- ", detail.c_str());
}

static std::vector<std::uint8_t> bytes_from_hex(const std::string& h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2) {
        const int hi = nib(h[i]), lo = nib(h[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return out;
}

namespace {

struct BlockFixture {
    std::vector<std::uint8_t> blob;
    std::vector<std::uint8_t> hashing_blob;
    native::Hash              id{};
    std::uint64_t             height = 0;
    std::uint32_t             nonce  = 0;
    std::size_t               nonce_offset = 0;
};

bool load_fixture(BlockFixture& f) {
    f.blob   = bytes_from_hex(native::golden_c2a::BLOCKS[0].blob_hex);
    f.height = native::golden_c2a::BLOCKS[0].height;
    native::ParsedBlock   pb;
    native::BlockIdentity ident;
    if (native::parse_and_identify(f.blob, pb, ident) != native::BlockParseStatus::Ok)
        return false;
    if (pb.header_size < 4) return false;
    f.id           = ident.id;
    f.hashing_blob = ident.hashing_blob;
    f.nonce        = pb.header.nonce;
    f.nonce_offset = pb.header_size - 4;
    return true;
}

// One publisher over the C5 relay, fakes all round, and a hand-cranked clock.
struct Rig {
    const BlockFixture&                f;
    native::fakes::FakeBroadcastPort   port;      // state_normal_peers = 0
    native::fakes::FakeMinerDataSource bodies;
    native::fakes::FakeChain           chain;     // accepts our own block
    native::relay::LevinBlockRelay     relay;
    submit::FoundBlockQueue            found;
    o2::P2pBlockPublisher              pub;
    std::uint64_t                      now = 1'000'000;
    std::vector<std::string>           errors;    // the ERROR log lines
    bool                               corrupt_id = false;   // hashing blob != full blob

    static native::relay::RelayConfig relay_cfg() {
        native::relay::RelayConfig c;
        c.policy.order                 = native::ArmOrder::P2pOnly;
        c.policy.include_all_tx_bodies = true;
        return c;
    }

    explicit Rig(const BlockFixture& fx, bool on_best_chain = true)
        : f(fx),
          relay(port, native::relay::DaemonSubmitSink{}, &bodies, &chain, relay_cfg()),
          pub(relay, found, [this](std::uint32_t, std::uint32_t, submit::BlockCandidate& out) {
              out.template_id     = 1;
              out.height          = f.height;
              out.full_blob       = f.blob;
              out.hashing_blob    = f.hashing_blob;
              if (corrupt_id && !out.hashing_blob.empty()) out.hashing_blob.back() ^= 0x01;
              out.nonce_offset    = f.nonce_offset;
              out.expected_reward = 600000000000ull;
              return true;
          }) {
        pub.enable_network_relay(true);
        pub.set_clock([this] { return now; });
        pub.set_log([this](bool err, const std::string& l) {
            if (err) errors.push_back(l);
        });
        if (on_best_chain) {
            // Our own index took the block and it is its tip: the state a real
            // ChainIndex is in right after submit_own_block() connected it.
            native::node::ChainMainBlock row{};
            row.height = f.height;
            row.id     = f.id;
            chain.rows.push_back(row);
        }
    }

    std::size_t frames() const { return port.broadcasts.size(); }
    bool logged(const char* needle) const {
        for (const std::string& l : errors)
            if (l.find(needle) != std::string::npos) return true;
        return false;
    }
};

} // namespace

static void suite_r(const BlockFixture& f) {
    // --- R1 + R2: parked, then delivered once --------------------------------
    {
        std::printf("R1/R2: zero peers parks the block; the first peer gets it, once\n");
        Rig r(f);
        r.pub.submit_network_block(1, f.nonce, 0);
        check(r.found.pushed() == 0, "R1a zero peers -> no FOUND event yet", r.pub.last_error());
        check(r.pub.failed() == 1 && r.pub.relayed() == 0,
              "R1b the first push is still counted as reached-nobody (failed()=1)");
        check(r.pub.parked() == 1 && r.pub.parked_total() == 1,
              "R1c ... and the block is PARKED, not dropped");
        check(r.pub.last_error().find("PARKED") != std::string::npos && r.logged("PARKED"),
              "R1d the status line and the ERROR log both say so", r.pub.last_error());
        check(r.frames() == 1, "R1e exactly one frame so far (the first push)");

        r.now += 1'000;
        r.pub.tick();
        check(r.frames() == 1, "R1f nothing is re-sent before the first backoff (2 s)");

        r.now += 1'000;                       // t0 + 2 s: attempt 1, still no peer
        r.pub.tick();
        check(r.frames() == 2 && r.pub.parked() == 1 && r.found.pushed() == 0,
              "R1g a due tick re-announces once; still nobody -> still parked, still unbooked");

        r.port.state_normal_peers = 2;        // the network comes back
        r.now += 3'000;                       // t0 + 5 s: not yet due (next at t0 + 6 s)
        r.pub.tick();
        check(r.frames() == 2, "R2a the backoff doubles (4 s) and is honoured");
        r.now += 1'000;                       // t0 + 6 s
        r.pub.tick();
        check(r.frames() == 3, "R2b the due tick re-announces from the retained book");
        check(r.found.pushed() == 1, "R2c ... and THE FoundBlockEvent is pushed", r.pub.last_error());
        check(r.pub.late_reached() == 1 && r.pub.relayed() == 1 && r.pub.parked() == 0,
              "R2d counted late_reached=1 relayed=1, nothing left parked");
        check(r.pub.peers() == 2, "R2e the late receipt's peers are counted");
        submit::FoundBlockEvent ev;
        const bool got = r.found.pop(ev);
        check(got && ev.block_id == f.id && ev.height == f.height,
              "R2f the event is OUR block (id off the relayed bytes, the template height)");
        check(got && ev.header_check == submit::HeaderCheck::NotRun &&
                  ev.id_source == submit::IdSource::Local && ev.rpc_ms == 0.0,
              "R2g with the same honesty fields as a first-time relay");

        for (int i = 0; i < 20; ++i) { r.now += 30'000; r.pub.tick(); }
        check(r.frames() == 3 && r.found.pushed() == 1,
              "R2h later ticks send nothing and push nothing");

        // The same block submitted again (a duplicate share) reaches peers now,
        // but it is the same block: no second event.
        r.pub.submit_network_block(1, f.nonce, 0);
        check(r.found.pushed() == 1 && r.pub.duplicate_found() == 1,
              "R2i a re-submit of a delivered block is NOT a second FoundBlockEvent");
    }

    // --- R3: bounded, then abandoned loudly ------------------------------------
    {
        std::printf("R3: peers never appear -> bounded re-announce, then ABANDONED\n");
        Rig r(f);
        const o2::P2pBlockPublisher::RetryPolicy pol{};
        r.pub.submit_network_block(1, f.nonce, 0);
        const std::uint64_t t0 = r.now;
        for (int i = 0; i < 400; ++i) { r.now += 1'000; r.pub.tick(); }   // 400 s
        check(r.found.pushed() == 0, "R3a nothing is ever booked for a block nobody received");
        check(r.pub.abandoned() == 1 && r.pub.parked() == 0, "R3b the block is ABANDONED, once");
        check(r.frames() <= 1u + pol.max_attempts,
              "R3c at most max_attempts re-announce frames (" + std::to_string(r.frames()) +
                  " frames incl. the first push)");
        check(r.frames() >= 3, "R3d ... and it did actually keep trying");
        check(r.logged("RELAY ABANDONED") && r.logged("IS on our own best chain"),
              "R3e ERROR line names the abandonment and that our own chain carries it",
              r.pub.last_error());
        check(r.pub.last_error().find("ABANDONED") != std::string::npos,
              "R3f the status line keeps the abandonment");
        (void)t0;
        // The last frame went out no later than the window edge.
        Rig q(f);
        q.pub.submit_network_block(1, f.nonce, 0);
        std::uint64_t last_frame_at = q.now;
        std::size_t   seen = q.frames();
        const std::uint64_t q0 = q.now;
        for (int i = 0; i < 400; ++i) {
            q.now += 1'000;
            q.pub.tick();
            if (q.frames() != seen) { seen = q.frames(); last_frame_at = q.now; }
        }
        check(last_frame_at - q0 <= pol.window_ms,
              "R3g no frame after the window (last re-announce at +" +
                  std::to_string((last_frame_at - q0) / 1000) + " s)");
    }

    // --- R4: lost the height -> dropped without another frame -----------------
    {
        std::printf("R4: our own best chain does not carry it -> dropped, no frame\n");
        Rig r(f, /*on_best_chain=*/false);
        r.pub.submit_network_block(1, f.nonce, 0);
        check(r.pub.parked() == 1, "R4a parked like any other unreached block");
        r.port.state_normal_peers = 3;   // peers would take it -- and must not be sent it
        r.now += 2'000;
        r.pub.tick();
        check(r.pub.orphaned_unreached() == 1 && r.pub.parked() == 0,
              "R4b the first due tick drops it as orphaned_unreached");
        check(r.frames() == 1 && r.found.pushed() == 0,
              "R4c no re-announce frame and nothing booked");
        check(r.logged("RELAY DROPPED"), "R4d at ERROR");
    }

    // --- R5: what did not change -----------------------------------------------
    {
        std::printf("R5: the unchanged paths\n");
        {
            Rig r(f);
            r.port.state_normal_peers = 1;
            r.pub.submit_network_block(1, f.nonce, 0);
            check(r.found.pushed() == 1 && r.pub.relayed() == 1 && r.pub.parked() == 0 &&
                      r.pub.failed() == 0,
                  "R5a a first push that reached a peer is booked at once, never parked");
        }
        {
            Rig r(f);
            r.pub.enable_solo_own_index(true);
            r.pub.submit_network_block(1, f.nonce, 0);
            check(r.found.pushed() == 1 && r.pub.solo_landed() == 1 && r.pub.parked() == 0,
                  "R5b SOLO still books on our own index at once and parks nothing");
        }
        {
            Rig r(f);
            r.pub.enable_solo_own_index(true);
            r.chain.accept_own_block = false;
            r.pub.submit_network_block(1, f.nonce, 0);
            check(r.found.pushed() == 0 && r.pub.failed() == 1 && r.pub.parked() == 0,
                  "R5c SOLO with an index that said no: nothing booked, nothing parked");
        }
        {
            // A refused block never reaches the retained book, so there is
            // nothing valid to re-announce and it must not be parked.
            Rig r(f);
            r.corrupt_id = true;   // the id the gate "verified" is not this blob's
            r.pub.submit_network_block(1, f.nonce, 0);
            check(r.pub.parked() == 0 && r.found.pushed() == 0,
                  "R5d a block the relay REFUSED is never parked", r.pub.last_error());
            r.port.state_normal_peers = 2;
            for (int i = 0; i < 10; ++i) { r.now += 5'000; r.pub.tick(); }
            check(r.found.pushed() == 0 && r.pub.late_reached() == 0,
                  "R5e ... and never delivered later");
        }
        {
            Rig r(f);
            r.pub.enable_network_relay(false);
            r.pub.submit_network_block(1, f.nonce, 0);
            check(r.pub.refused() == 1 && r.pub.parked() == 0 && r.frames() == 0,
                  "R5f the fail-closed RandomX gate still refuses before anything is parked");
        }
    }
}

int main() {
    std::printf("== v37_xmr_p2p_publish_retry_kat: reached-nobody is parked, never dropped ==\n");
    BlockFixture f;
    if (!load_fixture(f)) {
        check(false, "R0 the captured block fixture parses and re-identifies");
    } else {
        check(true, "R0 the captured block fixture parses and re-identifies");
        suite_r(f);
    }
    std::printf("== %s: %d passed, %d failed ==\n", g_fail ? "FAIL" : "OK", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
