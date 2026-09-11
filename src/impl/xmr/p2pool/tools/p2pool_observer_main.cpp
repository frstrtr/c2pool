// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/p2pool/tools/p2pool_observer_main.cpp
//
// `xmr_p2pool_observer` -- run the read-only P2Pool sidechain observer against
// the live network and print what it saw.
//
// It is a HARNESS, the same way xmr_native_node is one: CI BUILDS it so it
// cannot bit-rot and never RUNS it, because running it means dialling a public
// network. Its whole job is to make "we can read P2Pool's sidechain" a fact
// with block ids attached rather than a design claim.
//
//   xmr_p2pool_observer --chain mini --seconds 300
//   xmr_p2pool_observer --chain main --peer 65.21.227.114:37889 --seconds 120
//   xmr_p2pool_observer --chain mini --capture-golden /tmp/frame.bin
//
// The last form is how test/p2pool_golden_frames.hpp was produced: the first
// Full sidechain blob of a live session, written out byte-for-byte with nothing
// stripped, so the KAT parses exactly what the network sent.
//
// `--monero-prev HEIGHT:HASH` is the cross-check against a public Monero
// source. Every sidechain block templated on Monero height H carries the id of
// height H-1 as its prev_id, so supplying (H-1, id-of-H-1) from any independent
// source -- a block explorer, a daemon, p2pool.observer's own network stats --
// turns "we parsed some bytes" into "we parsed the Monero chain everyone else
// sees". It is checked, counted and reported; a mismatch is a loud failure.
//
// SCOPE FENCE: everything under src/impl/xmr/. UNIX only.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/p2pool/p2pool_observer.hpp"

namespace p2p = c2pool::xmr::p2pool;

namespace {

p2p::Sidechain parse_chain(const std::string& s) {
    if (s == "mini") return p2p::Sidechain::Mini;
    if (s == "nano") return p2p::Sidechain::Nano;
    return p2p::Sidechain::Main;
}

bool parse_hex32(const std::string& s, p2p::Hash& out) {
    if (s.size() != 64) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = nib(s[2 * i]), lo = nib(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

void usage() {
    std::cout <<
        "xmr_p2pool_observer -- strictly read-only P2Pool sidechain observer\n"
        "  --chain main|mini|nano   sidechain to observe (default mini)\n"
        "  --peer HOST:PORT         dial this peer first; seeds follow (repeatable)\n"
        "  --no-seeds               do not append the DNS seeds\n"
        "  --peers N                concurrent connections (default 4)\n"
        "  --seconds N              observation window (default 300)\n"
        "  --seed N                 deterministic rng seed\n"
        "  --capture-golden PATH    write the first full sidechain FRAME to PATH\n"
        "  --capture-mm PATH        write the first frame with >=2 merge-mining ids to PATH\n"
        "  --dump-failed DIR        write any blob that failed to parse into DIR\n"
        "  --monero-prev H:HASH     cross-check: block templated on H+1 must carry HASH\n"
        "  --verbose                per-frame logging\n";
}

} // namespace

int main(int argc, char** argv) {
    p2p::ObserverConfig cfg;
    cfg.chain   = p2p::Sidechain::Mini;
    cfg.run_ms  = 300000;
    std::vector<std::pair<std::string, std::uint16_t>> explicit_peers;
    std::string capture_path;
    std::string capture_mm_path;
    std::uint64_t xcheck_height = 0;
    p2p::Hash     xcheck_hash{};
    bool          xcheck_set = false;
    bool          no_seeds = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* what) -> std::string {
            if (i + 1 >= argc) { std::cerr << "missing value for " << what << "\n"; std::exit(2); }
            return argv[++i];
        };
        if (a == "--chain")            cfg.chain = parse_chain(next("--chain"));
        else if (a == "--peers")       cfg.max_peers = static_cast<std::size_t>(std::stoul(next("--peers")));
        else if (a == "--seconds")     cfg.run_ms = std::stoull(next("--seconds")) * 1000ull;
        else if (a == "--seed")        cfg.seed = std::stoull(next("--seed"));
        else if (a == "--verbose")     cfg.verbose = true;
        else if (a == "--no-seeds")    no_seeds = true;
        else if (a == "--dump-failed") cfg.dump_failed_dir = next("--dump-failed");
        else if (a == "--capture-golden") capture_path = next("--capture-golden");
        else if (a == "--capture-mm") capture_mm_path = next("--capture-mm");
        else if (a == "--peer") {
            const std::string hp = next("--peer");
            const std::size_t c = hp.rfind(':');
            if (c == std::string::npos) { std::cerr << "bad --peer " << hp << "\n"; return 2; }
            explicit_peers.emplace_back(hp.substr(0, c),
                                        static_cast<std::uint16_t>(std::stoul(hp.substr(c + 1))));
        } else if (a == "--monero-prev") {
            const std::string v = next("--monero-prev");
            const std::size_t c = v.find(':');
            if (c == std::string::npos || !parse_hex32(v.substr(c + 1), xcheck_hash)) {
                std::cerr << "bad --monero-prev " << v << "\n"; return 2;
            }
            xcheck_height = std::stoull(v.substr(0, c));
            xcheck_set = true;
        } else if (a == "--help" || a == "-h") { usage(); return 0; }
        else { std::cerr << "unknown argument " << a << "\n"; usage(); return 2; }
    }

    p2p::Observer obs(cfg);
    const bool verbose = cfg.verbose;
    obs.set_log([verbose](const std::string& m) {
        if (verbose) std::cout << "  . " << m << "\n" << std::flush;
    });

    std::size_t captured = 0, captured_mm = 0;
    std::size_t xcheck_hits = 0, xcheck_misses = 0;
    std::size_t repeat_sightings = 0;
    std::set<p2p::Hash> printed;
    obs.set_block_sink([&](const p2p::PoolBlock& pb, const std::vector<std::uint8_t>& body,
                           p2p::MessageId wire_id, const std::string& from) {
        // The golden is the COMPLETE WIRE FRAME: the message-id byte, the
        // little-endian u32 body length and the body exactly as received. The
        // KAT re-splits it with frame_size() before parsing, so the capture
        // exercises the framing as well as the parser.
        if (!capture_path.empty() && captured == 0 && pb.shape == p2p::BlobShape::Full) {
            FILE* f = std::fopen(capture_path.c_str(), "wb");
            if (f) {
                const std::uint32_t len = static_cast<std::uint32_t>(body.size());
                std::uint8_t hdr[5];
                hdr[0] = static_cast<std::uint8_t>(wire_id);
                hdr[1] = static_cast<std::uint8_t>(len & 0xFFu);
                hdr[2] = static_cast<std::uint8_t>((len >> 8) & 0xFFu);
                hdr[3] = static_cast<std::uint8_t>((len >> 16) & 0xFFu);
                hdr[4] = static_cast<std::uint8_t>((len >> 24) & 0xFFu);
                std::fwrite(hdr, 1, sizeof(hdr), f);
                std::fwrite(body.data(), 1, body.size(), f);
                std::fclose(f);
                std::cout << "captured golden frame " << (body.size() + 5) << " bytes -> "
                          << capture_path << "\n";
                ++captured;
            }
        }
        if (!capture_mm_path.empty() && captured_mm == 0 && pb.shape == p2p::BlobShape::Full
            && pb.merge_mining_extra.size() >= 2) {
            if (FILE* f = std::fopen(capture_mm_path.c_str(), "wb")) {
                const std::uint32_t len = static_cast<std::uint32_t>(body.size());
                const std::uint8_t hdr[5] = {
                    static_cast<std::uint8_t>(wire_id),
                    static_cast<std::uint8_t>(len & 0xFFu),
                    static_cast<std::uint8_t>((len >> 8) & 0xFFu),
                    static_cast<std::uint8_t>((len >> 16) & 0xFFu),
                    static_cast<std::uint8_t>((len >> 24) & 0xFFu)};
                std::fwrite(hdr, 1, sizeof(hdr), f);
                std::fwrite(body.data(), 1, body.size(), f);
                std::fclose(f);
                std::cout << "captured merge-mining frame " << (body.size() + 5)
                          << " bytes (" << pb.merge_mining_extra.size() << " chain ids) -> "
                          << capture_mm_path << "\n";
                ++captured_mm;
            }
        }
        if (xcheck_set && pb.txin_gen_height == xcheck_height + 1) {
            if (pb.prev_id == xcheck_hash) ++xcheck_hits; else ++xcheck_misses;
        }
        // A tip poll against N peers returns the same block N times; printing
        // every copy buries the chain under its own echo.
        if (!printed.insert(pb.sidechain_id).second) { ++repeat_sightings; return; }
        std::cout << "block " << p2p::hex(pb.sidechain_id).substr(0, 16)
                  << " h=" << pb.sidechain_height
                  << " diff=" << pb.difficulty.to_string()
                  << " cum=" << pb.cumulative_difficulty.to_string()
                  << " xmr_h=" << pb.txin_gen_height
                  << " shares=" << pb.outputs.size()
                  << " uncles=" << pb.uncles.size()
                  << " txs=" << pb.tx_hashes.size()
                  << " reward=" << pb.total_reward
                  << " shape=" << p2p::to_string(pb.shape)
                  << " id_verified=" << (pb.sidechain_id_verified ? 1 : 0)
                  << " parent=" << p2p::hex(pb.parent).substr(0, 16)
                  << " xmr_prev=" << p2p::hex(pb.prev_id).substr(0, 16)
                  << " from=" << from
                  << "\n" << std::flush;
    });

    // Explicit peers are dialled FIRST and the DNS seeds are appended behind
    // them, because a seed is often at its incoming-connection limit: with
    // either/or, one full seed is an empty run. Peer-list gossip widens the
    // queue from whichever of them answers.
    for (const auto& p : explicit_peers) obs.add_seed(p.first, p.second);
    if (!no_seeds) obs.add_default_seeds();

    std::cout << "observing p2pool " << p2p::to_string(cfg.chain)
              << " sidechain, read-only, for " << (cfg.run_ms / 1000) << " s\n" << std::flush;

    // STEADY: this is the length of one run, start to finish, inside one
    // process -- a duration, and the one clock an NTP step must not perturb.
    const std::uint64_t t0 = p2p::steady_ms();
    const std::uint64_t iters = obs.run();
    const std::uint64_t elapsed = p2p::steady_ms() - t0;

    std::cout << "\n" << obs.model().status(elapsed);
    std::cout << "  outbound     : " << obs.ledger().to_string() << "\n";
    std::cout << "  poll_iters   : " << iters
              << "  repeat_sightings=" << repeat_sightings << "\n";

    // The read-only assertion, stated as an audit of what was actually sent
    // rather than as a claim. There are four outbound buckets because there are
    // four encoders; a publish would have had nowhere to be counted.
    std::cout << "  READ-ONLY    : no LISTEN_PORT, no BLOCK_RESPONSE, no BLOCK_BROADCAST,\n"
                 "                 no BLOCK_NOTIFY, no AUX_JOB_DONATION, no MONERO_BLOCK_BROADCAST\n"
                 "                 emitted -- this tree contains no encoder for any of them.\n";

    for (const p2p::HeightContest& c : obs.model().contests()) {
        std::cout << "  contested h=" << c.height << " blocks=" << c.ids.size()
                  << " spread_ms=" << c.spread_ms() << "\n";
        for (const p2p::Hash& id : c.ids) std::cout << "      " << p2p::hex(id) << "\n";
    }

    if (xcheck_set) {
        std::cout << "  monero xcheck: height=" << (xcheck_height + 1)
                  << " hits=" << xcheck_hits << " misses=" << xcheck_misses << "\n";
        if (xcheck_misses) { std::cerr << "MONERO CROSS-CHECK FAILED\n"; return 1; }
    }

    // Non-vacuity: a run that connected but parsed nothing is a failed run.
    if (obs.model().distinct_blocks() == 0) {
        std::cerr << "no sidechain blocks parsed\n";
        return 1;
    }
    return 0;
}
