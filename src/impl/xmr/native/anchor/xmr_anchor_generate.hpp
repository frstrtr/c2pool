// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/anchor/xmr_anchor_generate.hpp
//
// generate_anchor(): mint an AnchorBundle at a chosen height from a synced
// monerod. Plan section 4.10 pins the name and the parameter list; this file
// authors the RULES -- which heights, which windows, which consistency checks a
// capture must survive -- and nothing else.
//
// WHY THE TRANSPORT IS NOT HERE. `MoneroDaemonRpc` below is an ABSTRACT
// read-only view of the daemon: four queries, all of them value types this
// family already owns. The HTTP client and the JSON parser that back it live
// outside (WF-C6a wires the real one; tools/xmr-anchor-gen/xmr_anchor_gen.py is
// the release-time capture path that speaks the same four queries over
// monerod's JSON-RPC). Keeping the port abstract is what lets these rules be
// tested by a KAT against a deterministic model daemon -- including the
// dishonest-daemon cases, which a live capture can never stage on purpose.
//
// THE GENERATOR RUNS THE LOADER'S OWN JUDGEMENT ON WHAT IT BUILT. The last act
// of generate_anchor is anchor_self_check(). A generator bug therefore fails at
// the tool, in front of the person minting the bundle, instead of at some
// operator's boot three weeks later. That is the whole reason contracts/ hosts
// the self-check rather than the loader.
//
// WHAT IT REFUSES, AND WHY EACH ONE MATTERS
//   * an anchor less than ANCHOR_MIN_BURY deep -- a bundle pinned to a block
//     that can still be reorged away is a trust root with an expiry date;
//   * a chain of headers that is not contiguous, not prev-linked, or whose
//     cumulative difficulty goes backwards -- the daemon (or the transport)
//     handed us something that is not a chain, and a trust root minted from it
//     would be wrong in a way no later check catches;
//   * coins arithmetic that underflows or that disagrees with the block above
//     it -- already_generated_coins drives every future coinbase check, so it
//     is exact or it is nothing;
//   * a seed height that is not inside the fetched window -- the bundle would
//     ship a seed id we never actually read from a block.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"

namespace c2pool::xmr::native {

// How far below the daemon's tip an anchor must sit before we are willing to
// pin it. 60 blocks is the D_conf burial depth the v37 settlement side already
// uses, so the anchor is never shallower than the thing it underwrites.
inline constexpr std::uint64_t ANCHOR_MIN_BURY = 60;

// monerod's own cap on get_block_headers_range under a restricted RPC. Staying
// at it means the same generator works against a public restricted daemon.
inline constexpr std::uint64_t ANCHOR_RPC_CHUNK = 1000;

// --- what one header contributes --------------------------------------------
// Exactly the block_header_response fields the bundle is built from, normalised
// to this family's types. `reward` is monerod's coinbase amount for the block
// (base emission plus fees) -- the quantity monerod itself adds into
// already_generated_coins, which is why it can be subtracted back off.
struct AnchorRpcHeader {
    std::uint64_t height = 0;
    Hash          id{};
    Hash          prev_id{};
    std::uint64_t timestamp = 0;
    std::uint8_t  major_version = 0;
    std::uint64_t reward = 0;
    std::uint64_t block_weight = 0;
    std::uint64_t long_term_weight = 0;
    U128          cumulative_difficulty{};
};

// --- the read-only daemon port ----------------------------------------------
// Every method is a QUERY. There is deliberately no way to reach a submit, a
// wallet or the peer list through this interface: an anchor tool that can only
// read is one fewer thing to review before pointing it at a production daemon.
struct MoneroDaemonRpc {
    virtual ~MoneroDaemonRpc() = default;

    // /get_info -> nettype and the height of the current tip BLOCK (not the
    // "height" field, which is one past it).
    virtual bool net_and_tip(std::string& network, std::uint64_t& tip_height,
                             std::string& why) = 0;

    // get_block_headers_range, inclusive, oldest first, exactly (to - from + 1)
    // rows or a failure.
    virtual bool headers_range(std::uint64_t from, std::uint64_t to,
                               std::vector<AnchorRpcHeader>& out, std::string& why) = 0;

    // get_miner_data -> already_generated_coins as of `tip_height`.
    virtual bool coins_at_tip(std::uint64_t& tip_height, std::uint64_t& coins,
                              std::string& why) = 0;

    // monerod publishes no RPC for its compiled-in checkpoints, so this is a
    // release-time input rather than a query in the real implementation. It is
    // on the port anyway: the generator must not know where they came from, and
    // a build with none returns an empty vector and succeeds.
    virtual bool checkpoints_at_or_above(std::uint64_t height,
                                         std::vector<std::pair<std::uint64_t, Hash>>& out,
                                         std::string& why) = 0;
};

namespace anchor_gen_detail {

inline bool net_from_string(const std::string& s, XmrNet& out) noexcept {
    if (s == "mainnet")  { out = XmrNet::Mainnet;  return true; }
    if (s == "testnet")  { out = XmrNet::Testnet;  return true; }
    if (s == "stagenet") { out = XmrNet::Stagenet; return true; }
    if (s == "regtest")  { out = XmrNet::Regtest;  return true; }
    return false;
}

// Chunked fetch with the chain checks applied ACROSS chunk boundaries, which is
// where a lazy implementation stops looking and where a truncated or reordered
// response would otherwise slip through.
inline bool fetch_span(MoneroDaemonRpc& rpc, std::uint64_t from, std::uint64_t to,
                       std::vector<AnchorRpcHeader>& out, std::string& why) {
    out.clear();
    if (to < from) { why = "empty header span requested"; return false; }
    out.reserve(static_cast<std::size_t>(to - from + 1));
    std::uint64_t at = from;
    while (at <= to) {
        const std::uint64_t end = (to - at + 1 > ANCHOR_RPC_CHUNK) ? at + ANCHOR_RPC_CHUNK - 1 : to;
        std::vector<AnchorRpcHeader> chunk;
        if (!rpc.headers_range(at, end, chunk, why)) return false;
        if (chunk.size() != static_cast<std::size_t>(end - at + 1)) {
            why = "daemon returned " + std::to_string(chunk.size()) + " headers for "
                + std::to_string(at) + ".." + std::to_string(end);
            return false;
        }
        for (std::size_t i = 0; i < chunk.size(); ++i) {
            const AnchorRpcHeader& h = chunk[i];
            const std::uint64_t want = at + i;
            if (h.height != want) {
                why = "header out of order: expected height " + std::to_string(want)
                    + ", daemon says " + std::to_string(h.height);
                return false;
            }
            if (!out.empty()) {
                const AnchorRpcHeader& p = out.back();
                if (h.prev_id != p.id) {
                    why = "header chain breaks at height " + std::to_string(h.height)
                        + ": prev_id does not match the block below it";
                    return false;
                }
                if (u128_less(h.cumulative_difficulty, p.cumulative_difficulty)) {
                    why = "cumulative difficulty goes backwards at height "
                        + std::to_string(h.height);
                    return false;
                }
            }
            out.push_back(h);
        }
        at = end + 1;
    }
    return true;
}

}  // namespace anchor_gen_detail

// --- the generator -----------------------------------------------------------
// `height` is H_a. On false, `out` is left empty and `why` carries one line an
// operator can act on.
inline bool generate_anchor(MoneroDaemonRpc& rpc, std::uint64_t height,
                            AnchorBundle& out, std::string& why) {
    using namespace anchor_gen_detail;
    out = AnchorBundle{};
    why.clear();

    // --- the daemon we are talking to ---------------------------------------
    std::string network;
    std::uint64_t tip = 0;
    if (!rpc.net_and_tip(network, tip, why)) return false;
    XmrNet net{};
    if (!net_from_string(network, net)) {
        why = "daemon reports unknown network '" + network + "'";
        return false;
    }
    if (height > tip || tip - height < ANCHOR_MIN_BURY) {
        why = "anchor height " + std::to_string(height) + " is only "
            + std::to_string(height > tip ? 0 : tip - height) + " blocks below the tip "
            + std::to_string(tip) + "; at least " + std::to_string(ANCHOR_MIN_BURY)
            + " required";
        return false;
    }
    if (height + 1 < ANCHOR_LONG_TERM_WEIGHTS) {
        why = "anchor height " + std::to_string(height) + " is below the "
            + std::to_string(ANCHOR_LONG_TERM_WEIGHTS) + "-block long-term window";
        return false;
    }

    // --- the window ---------------------------------------------------------
    const std::uint64_t lo = height - (ANCHOR_LONG_TERM_WEIGHTS - 1);
    std::vector<AnchorRpcHeader> win;
    if (!fetch_span(rpc, lo, height, win, why)) return false;
    const AnchorRpcHeader& at = win.back();

    // Built into a LOCAL bundle and published to `out` only on success: see the
    // assignment at the end of the function.
    AnchorBundle b;
    b.network       = network;
    b.height        = height;
    b.id            = at.id;
    b.prev_id       = at.prev_id;
    b.timestamp     = at.timestamp;
    b.major_version = at.major_version;
    b.cumulative_difficulty = at.cumulative_difficulty;

    b.difficulty_window.reserve(ANCHOR_DIFFICULTY_WINDOW);
    for (std::size_t i = win.size() - ANCHOR_DIFFICULTY_WINDOW; i < win.size(); ++i)
        b.difficulty_window.emplace_back(win[i].timestamp, win[i].cumulative_difficulty);

    b.short_term_weights.reserve(ANCHOR_SHORT_TERM_WEIGHTS);
    for (std::size_t i = win.size() - ANCHOR_SHORT_TERM_WEIGHTS; i < win.size(); ++i)
        b.short_term_weights.push_back(win[i].block_weight);

    b.long_term_weights.reserve(ANCHOR_LONG_TERM_WEIGHTS);
    for (const AnchorRpcHeader& h : win) b.long_term_weights.push_back(h.long_term_weight);

    // --- already_generated_coins --------------------------------------------
    // The daemon publishes it only for its own tip, so we walk it back down: the
    // coinbase of every block above H_a is subtracted off, one exact integer at
    // a time. Any underflow means the two sources disagree, and a trust root
    // built on a disagreement is worse than no trust root.
    std::uint64_t coins_tip_height = 0, coins = 0;
    if (!rpc.coins_at_tip(coins_tip_height, coins, why)) return false;
    if (coins_tip_height < height) {
        why = "daemon reports already_generated_coins at height "
            + std::to_string(coins_tip_height) + ", below the anchor height "
            + std::to_string(height);
        return false;
    }
    if (coins_tip_height > height) {
        std::vector<AnchorRpcHeader> above;
        if (!fetch_span(rpc, height + 1, coins_tip_height, above, why)) return false;
        if (above.front().prev_id != at.id) {
            why = "the block above the anchor does not link to it; the daemon "
                  "switched chains during the capture";
            return false;
        }
        for (const AnchorRpcHeader& h : above) {
            if (coins < h.reward) {
                why = "already_generated_coins underflows subtracting the coinbase of "
                      "block " + std::to_string(h.height);
                return false;
            }
            coins -= h.reward;
        }
    }
    if (coins == 0) {
        why = "already_generated_coins came out zero at height " + std::to_string(height);
        return false;
    }
    b.already_generated_coins = coins;

    // --- the RandomX seeds the first post-anchor blocks need ------------------
    // The seed for H_a+1 and, when the lag window straddles the anchor, the one
    // for H_a+1+LAG. Both are read out of blocks we actually fetched.
    const std::uint64_t s0 = rx_seedheight(height + 1);
    const std::uint64_t s1 = rx_seedheight(height + 1 + SEEDHASH_EPOCH_LAG);
    for (std::uint64_t sh : {s0, s1}) {
        bool already = false;
        for (const auto& s : b.seed_ids) already = already || (s.first == sh);
        if (already) continue;
        if (sh < lo || sh > height) {
            why = "seed height " + std::to_string(sh) + " is outside the fetched window "
                + std::to_string(lo) + ".." + std::to_string(height);
            return false;
        }
        b.seed_ids.emplace_back(sh, win[static_cast<std::size_t>(sh - lo)].id);
    }

    // --- monerod's own checkpoints at or above H_a ---------------------------
    if (!rpc.checkpoints_at_or_above(height, b.monerod_checkpoints, why)) return false;

    // --- the loader's judgement, applied to what we just built ---------------
    std::string sc_why;
    const AnchorStatus st = anchor_self_check(b, net, sc_why);
    if (st != AnchorStatus::Ok) {
        why = std::string("generated bundle fails its own self-check (") + to_string(st)
            + "): " + sc_why;
        return false;
    }

    b.digest = anchor_digest(b);

    // Only now does the caller get anything. Every refusal above leaves `out`
    // exactly as it was found -- empty -- so a caller that ignores the bool
    // cannot mistake a half-built window for a bundle.
    out = b;
    return true;
}

// The signature plan section 4.10 pins, for callers that only need the bit.
inline bool generate_anchor(MoneroDaemonRpc& rpc, std::uint64_t height, AnchorBundle& out) {
    std::string why;
    return generate_anchor(rpc, height, out, why);
}

}  // namespace c2pool::xmr::native
