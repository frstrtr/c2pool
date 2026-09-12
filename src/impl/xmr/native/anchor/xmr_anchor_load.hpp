// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/anchor/xmr_anchor_load.hpp
//
// The DEFINITION of load_anchor(), whose signature contracts/anchor.hpp pins.
// This is the node's first consensus-relevant act at boot, so the whole file is
// written for one property: there is no input for which it returns true and a
// bundle the node should not have trusted.
//
// THE FOUR GATES, in order, each one refusing rather than repairing:
//
//   1. SOURCE. An empty path means the release-embedded bundle for the network
//      we are running; anything else is a file. A file is read whole, with a
//      size cap, so a wrong path cannot become an allocation.
//   2. FORM (xmr_anchor_codec.hpp). Every line understood, every window exactly
//      the pinned length, `digest` last, body hashes to it.
//   3. MEANING (contracts/anchor.hpp anchor_self_check). Right network,
//      epoch-aligned seeds, monotone cumulative difficulty, a major version the
//      hard-fork table agrees with at this height and that this build is not
//      fenced out of, no checkpoint below the anchor.
//   4. The caller's remaining duty, which this function CANNOT discharge and
//      says so: C2's boot must fetch the block at `height` from peers and
//      refuse to start unless it hashes to `id`. Gates 2 and 3 make a corrupted
//      bundle reject the TRUE chain, which is loud; gate 4 is the only defence
//      against a bundle that is internally perfect and names the wrong block.
//      anchor_boot_duty() below exists to be quoted in that code review.
//
// WHY THE STATUS IS RETURNED AS WELL AS THE BOOL. The pinned signature returns
// bool because that is all a caller must handle. But "damaged file" and "right
// file, wrong network" want different operator messages, so the richer entry
// point sits beside it and the bool one is a thin wrapper over it. Neither can
// succeed where the other would fail.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <fstream>
#include <ios>
#include <string>

#include "impl/xmr/native/contracts/anchor.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_embedded.hpp"

namespace c2pool::xmr::native {

// A bundle is a few tens of kilobytes with the long-term window run-encoded,
// and a few hundred without. 16 MiB is far above any honest file and far below
// anything that hurts, so a mistyped path fails fast instead of reading a disk
// image into memory.
inline constexpr std::size_t ANCHOR_INC_MAX_BYTES = 16u * 1024u * 1024u;

// What happened, in enough detail for one operator-facing line.
struct AnchorLoadResult {
    bool         ok = false;
    AnchorParse  parse  = AnchorParse::Ok;      // meaningful when the form gate failed
    AnchorStatus status = AnchorStatus::Ok;     // meaningful when the meaning gate failed
    std::string  why;                           // always set when !ok
    std::string  source;                        // "embedded" or the path, for the log
};

namespace anchor_detail {

inline bool read_file(const std::string& path, std::string& out, std::string& why) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { why = "cannot open anchor bundle '" + path + "'"; return false; }
    f.seekg(0, std::ios::end);
    const std::streamoff size = f.tellg();
    if (size < 0) { why = "cannot size anchor bundle '" + path + "'"; return false; }
    if (static_cast<std::uintmax_t>(size) > ANCHOR_INC_MAX_BYTES) {
        why = "anchor bundle '" + path + "' is " + std::to_string(static_cast<std::uintmax_t>(size))
            + " bytes, above the " + std::to_string(ANCHOR_INC_MAX_BYTES) + " byte cap";
        return false;
    }
    f.seekg(0, std::ios::beg);
    out.assign(static_cast<std::size_t>(size), '\0');
    if (size > 0) f.read(&out[0], size);
    if (f.bad()) { why = "read error on anchor bundle '" + path + "'"; return false; }
    return true;
}

}  // namespace anchor_detail

// The full-detail entry point. `path_or_embedded` empty => the release bundle
// compiled into this binary for `net`.
inline AnchorLoadResult load_anchor_detailed(const std::string& path_or_embedded, XmrNet net,
                                             AnchorBundle& out) {
    AnchorLoadResult r;
    out = AnchorBundle{};

    // --- gate 1: source -----------------------------------------------------
    std::string text;
    if (path_or_embedded.empty()) {
        r.source = "embedded";
        const char* embedded = anchor_embedded_text(net);
        if (embedded == nullptr) {
            r.why = std::string("this build carries no embedded anchor bundle for network '")
                  + to_string(net) + "'; pass an explicit anchor path";
            return r;
        }
        text.assign(embedded);
    } else {
        r.source = path_or_embedded;
        if (!anchor_detail::read_file(path_or_embedded, text, r.why)) return r;
    }

    // --- gate 2: form -------------------------------------------------------
    r.parse = parse_anchor_inc(text, out, r.why);
    if (r.parse != AnchorParse::Ok) {
        r.why = "anchor bundle from " + r.source + " is malformed (" + to_string(r.parse)
              + "): " + r.why;
        out = AnchorBundle{};
        return r;
    }

    // --- gate 3: meaning ----------------------------------------------------
    std::string sc_why;
    r.status = anchor_self_check(out, net, sc_why);
    if (r.status != AnchorStatus::Ok) {
        r.why = "anchor bundle from " + r.source + " is rejected (" + to_string(r.status)
              + "): " + sc_why;
        out = AnchorBundle{};
        return r;
    }

    r.ok = true;
    r.why.clear();
    return r;
}

// The signature contracts/anchor.hpp pins. Same gates, one bit of answer.
inline bool load_anchor(const std::string& path_or_embedded, XmrNet net,
                        AnchorBundle& out, std::string& why) {
    const AnchorLoadResult r = load_anchor_detailed(path_or_embedded, net, out);
    why = r.why;
    return r.ok;
}

// Gate 4, written down so it cannot be forgotten by the code that owes it.
// C2's boot calls this AFTER load_anchor and BEFORE it trusts a single window:
// `id_from_network` is the hash of the block blob peers served at
// bundle.height, computed by the blob reader, never taken from a peer's word.
inline bool anchor_confirmed_by_network(const AnchorBundle& bundle, const Hash& id_from_network,
                                        std::string& why) {
    if (id_from_network != bundle.id) {
        why = "anchor block at height " + std::to_string(bundle.height)
            + " hashes to " + anchor_codec::to_hex(id_from_network)
            + " on this network, but the bundle pins "
            + anchor_codec::to_hex(bundle.id) + "; refusing to start";
        return false;
    }
    why.clear();
    return true;
}

// One line for a boot log / review checklist. Quoted by C2a so the duty above is
// visible where the node decides it is ready.
inline const char* anchor_boot_duty() noexcept {
    return "load_anchor() proves the bundle is well-formed and self-consistent; the caller "
           "MUST still fetch the block at bundle.height from peers and refuse to start "
           "unless it hashes to bundle.id (anchor_confirmed_by_network).";
}

}  // namespace c2pool::xmr::native
