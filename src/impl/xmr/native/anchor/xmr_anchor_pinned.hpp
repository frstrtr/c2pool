// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/anchor/xmr_anchor_pinned.hpp
//
// THE PINNED SNAPSHOT: the bootstrap a release ships, per network.
//
// A cold node needs two things to start above genesis: the format-2 anchor
// bundle (xmr_chain_anchor_<net>_f2.inc, compiled in, see
// xmr_anchor_embedded.hpp) and the output-set snapshot that anchor commits to
// (a ChainOutputSet::serialize() file, far too large to compile in). This
// file pins BOTH by sha256, so a release names exactly one anchor and exactly
// one snapshot per network, and anyone with their own synced monerod can
// re-mint them with tools/xmr-anchor-gen/xmr_anchor_gen.py and compare
// (docs/xmr-lane/PINNED-SNAPSHOTS.md has the procedure).
//
// WHY THE SNAPSHOT IS HASHED AND NOT ONLY ROOT-CHECKED. The loader
// (chain/xmr_output_set.hpp seed_bytes_) re-derives the output/spent MMR
// roots from the per-block LEAF hashes the file carries and compares them to
// the anchor. The output rows and key-image rows those leaves summarise are
// not re-hashed at load, so a file whose leaves are intact but whose rows are
// damaged passes the root check. Against the pinned anchor the node therefore
// also compares the whole file's size and sha256 with the pin below, before
// it maps a single row. An explicit --native-anchor keeps the root-only check
// (there is no pin to compare against).
//
// NOT CONSENSUS. Nothing here changes which blocks are valid; it only decides
// which bootstrap bytes a node is willing to start from.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <ios>
#include <string>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_embedded.hpp"
#include "impl/xmr/native/anchor/xmr_anchor_sha256.hpp"
#include "impl/xmr/native/contracts/anchor.hpp"

namespace c2pool::xmr::native {

struct PinnedSnapshot {
    XmrNet        net;
    std::uint64_t height;               // H_a
    const char*   block_id;             // hex id of the block at H_a
    const char*   anchor_inc_file;      // the committed .inc, repo-relative
    const char*   anchor_inc_sha256;    // sha256 of that file's bytes
    const char*   output_set_file;      // the snapshot's release file name
    const char*   output_set_sha256;    // sha256 of the snapshot file
    std::uint64_t output_set_bytes;     // its exact size
    const char*   release_url;          // where a release publishes it
};

// The values below are the ones docs/xmr-lane/PINNED-SNAPSHOTS.md lists;
// v37_xmr_pinned_snapshot_kat checks the two against each other and against
// the compiled-in bundles.
inline constexpr PinnedSnapshot PINNED_SNAPSHOT_STAGENET{
    XmrNet::Stagenet,
    2213803ull,
    "571f97ae8e7cd7816065c08260a3b65d0192b85d57e9961fa93e102629e6d3ee",
    "src/impl/xmr/native/anchor/xmr_chain_anchor_stagenet_f2.inc",
    "7e39e1a206c4f18776f6f6d83b518fd7146cdd66eacd6d28752446168e88a4a5",
    "xmr_stagenet_output_set.bin",
    "186b23c3b43cbc61e6132a9b4927e4eeb3666f153d2f2c5f9d52814d670dcb7d",
    1170058729ull,
    "https://github.com/frstrtr/c2pool/releases/download/<release-tag>/xmr_stagenet_output_set.bin",
};

inline constexpr PinnedSnapshot PINNED_SNAPSHOT_MAINNET{
    XmrNet::Mainnet,
    3765865ull,
    "ff732eb5bd91e3d7a5188841a04af3146360ffa6f5acbc20ff93797f5351fe33",
    "src/impl/xmr/native/anchor/xmr_chain_anchor_mainnet_f2.inc",
    "616407ba7d2ab2d304532ba1a10aa174c945c28109436ab2eac7d255061782e2",
    "xmr_mainnet_output_set.bin",
    "506aa2480fcab4ec6d4514f68898ca638065548675de9740e56a1b80b571390d",
    18320778025ull,
    "https://github.com/frstrtr/c2pool/releases/download/<release-tag>/xmr_mainnet_output_set.bin",
};

// nullptr: this build pins no snapshot for `net` (testnet, regtest).
inline const PinnedSnapshot* pinned_snapshot(XmrNet net) noexcept {
    switch (net) {
        case XmrNet::Stagenet: return &PINNED_SNAPSHOT_STAGENET;
        case XmrNet::Mainnet:  return &PINNED_SNAPSHOT_MAINNET;
        case XmrNet::Testnet:
        case XmrNet::Regtest:  return nullptr;
    }
    return nullptr;
}

// The exact bytes of the committed .inc, rebuilt from the compiled-in text:
// the file is the raw-string frame around the text plus one newline, so this
// is the same byte string sha256sum reads from the repo.
inline std::string embedded_anchor_file_bytes(XmrNet net) {
    const char* text = anchor_embedded_text(net);
    if (text == nullptr) return {};
    return std::string("R\"ANCHOR(") + text + ")ANCHOR\"\n";
}

inline std::string embedded_anchor_file_sha256(XmrNet net) {
    const std::string bytes = embedded_anchor_file_bytes(net);
    if (bytes.empty()) return {};
    return anchor_codec::to_hex(anchor_hash::sha256(bytes));
}

// The compiled-in bundle IS the pinned one: same file hash, same height, same
// block id. A false here is a build defect (the table and the .inc drifted),
// and the node refuses rather than boot from an anchor nobody pinned.
inline bool pinned_anchor_matches(const PinnedSnapshot& pin, const AnchorBundle& b,
                                  std::string& why) {
    const std::string file_sha = embedded_anchor_file_sha256(pin.net);
    if (file_sha != pin.anchor_inc_sha256) {
        why = std::string("the compiled-in ") + to_string(pin.net) + " anchor hashes to "
            + (file_sha.empty() ? std::string("<none>") : file_sha) + ", but the release pins "
            + pin.anchor_inc_sha256 + " (" + pin.anchor_inc_file + ")";
        return false;
    }
    if (b.height != pin.height || anchor_codec::to_hex(b.id) != pin.block_id) {
        why = std::string("the compiled-in ") + to_string(pin.net) + " anchor sits at height "
            + std::to_string(b.height) + " id " + anchor_codec::to_hex(b.id)
            + ", but the release pins height " + std::to_string(pin.height) + " id "
            + pin.block_id;
        return false;
    }
    if (!b.has_output_set()) {
        why = std::string("the compiled-in ") + to_string(pin.net)
            + " anchor is not a format-2 bundle; a pinned snapshot needs committed roots";
        return false;
    }
    why.clear();
    return true;
}

// One boot-log line naming what this node starts from and what it expects.
inline std::string pinned_boot_line(const PinnedSnapshot& pin) {
    return std::string("[pinned] booting from the compiled-in ") + to_string(pin.net)
         + " anchor: height " + std::to_string(pin.height) + " id " + pin.block_id
         + " (anchor .inc sha256 " + pin.anchor_inc_sha256 + "); expected output-set sha256 "
         + pin.output_set_sha256 + " (" + std::to_string(pin.output_set_bytes) + " bytes, "
         + pin.output_set_file + ")";
}

enum class PinnedSetCheck { Ok, CannotOpen, WrongSize, WrongHash };

inline const char* to_string(PinnedSetCheck c) noexcept {
    switch (c) {
        case PinnedSetCheck::Ok:         return "ok";
        case PinnedSetCheck::CannotOpen: return "cannot-open";
        case PinnedSetCheck::WrongSize:  return "wrong-size";
        case PinnedSetCheck::WrongHash:  return "wrong-sha256";
    }
    return "?";
}

namespace pinned_detail {
inline std::string refusal(const std::string& path, const PinnedSnapshot& pin,
                           const std::string& got) {
    return "output-set snapshot '" + path + "' is not the pinned " + to_string(pin.net)
         + " snapshot: expected sha256 " + pin.output_set_sha256 + " ("
         + std::to_string(pin.output_set_bytes) + " bytes) for the compiled-in anchor at height "
         + std::to_string(pin.height) + " (block " + pin.block_id + "), got " + got
         + "; refusing to start. Download " + pin.output_set_file
         + " from the release or re-mint it from your own monerod "
           "(docs/xmr-lane/PINNED-SNAPSHOTS.md)";
}
}  // namespace pinned_detail

// Size first (a truncated download refuses without reading it), then one
// sequential sha256 pass over the whole file. `got_sha256` receives the hex
// digest when the file was hashed.
inline PinnedSetCheck check_output_set_against_pin(const std::string& path,
                                                   const PinnedSnapshot& pin,
                                                   std::string& why,
                                                   std::string* got_sha256 = nullptr) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        why = pinned_detail::refusal(path, pin, "a file that cannot be opened");
        return PinnedSetCheck::CannotOpen;
    }
    f.seekg(0, std::ios::end);
    const std::streamoff size = f.tellg();
    if (size < 0 || static_cast<std::uint64_t>(size) != pin.output_set_bytes) {
        why = pinned_detail::refusal(path, pin, std::to_string(size < 0 ? 0 : size) + " bytes");
        return PinnedSetCheck::WrongSize;
    }
    f.seekg(0, std::ios::beg);
    anchor_hash::Sha256 h;
    std::vector<char> buf(std::size_t{4} << 20);
    std::uint64_t seen = 0;
    while (f) {
        f.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        const std::streamsize n = f.gcount();
        if (n <= 0) break;
        h.update(reinterpret_cast<const std::uint8_t*>(buf.data()), static_cast<std::size_t>(n));
        seen += static_cast<std::uint64_t>(n);
    }
    if (f.bad() || seen != pin.output_set_bytes) {
        why = pinned_detail::refusal(path, pin, "a read error after " + std::to_string(seen) + " bytes");
        return PinnedSetCheck::CannotOpen;
    }
    const std::string got = anchor_codec::to_hex(h.finish());
    if (got_sha256) *got_sha256 = got;
    if (got != pin.output_set_sha256) {
        why = pinned_detail::refusal(path, pin, "sha256 " + got);
        return PinnedSetCheck::WrongHash;
    }
    why.clear();
    return PinnedSetCheck::Ok;
}

}  // namespace c2pool::xmr::native
