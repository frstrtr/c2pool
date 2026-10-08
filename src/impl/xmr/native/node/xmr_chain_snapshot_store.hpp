// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/node/xmr_chain_snapshot_store.hpp
//
// THE RESUME FILE, and the one thing it is not allowed to become.
//
// chain/xmr_chain_index.hpp has carried save_snapshot()/load_snapshot() since
// C2: a self-describing, digest-checked image of the index taken
// `snapshot_depth` blocks below the tip, with the bodies above it so a resume
// lands with a rollback horizon rather than a frozen one. Nothing ever wrote
// one to disk, so every restart re-walked the chain from the anchor -- cheap
// on a fresh anchor, and an hour of somebody else's bandwidth on a pool that
// has been up for a month.
//
// This file is the disk half, and it exists as a SEPARATE ENVELOPE rather than
// as a path argument on the codec because of what a snapshot is: a trust root
// that did not come off the wire. The index's own image says which network it
// is for and carries the anchor height/id it was built over, but it is checked
// against those fields only loosely, and a file on disk is exactly the thing an
// operator's backup script, a shared volume, or a stale copy from another
// network can substitute. So the envelope BINDS the image to the anchor the
// running node just had confirmed:
//
//   magic "C2XSNAP1" | version | net | anchor_height | anchor_id | len | image
//   | sha256(everything above)
//
// and load() refuses on any of: a short file, a digest mismatch, a wrong magic
// or version, a different network, or an anchor identity that is not the one
// this node is booting on. Every refusal is the SAME refusal -- fall back to
// the anchor boot and sync -- which is why none of them is fatal and all of
// them are logged.
//
// WHAT THIS DOES NOT DO, deliberately and load-bearingly: it does not bypass
// gate 4. NativeNode loads a snapshot only AFTER the anchor confirm has
// settled Confirmed against live peers, and keys the envelope on the anchor
// identity the gate just confirmed. A snapshot can therefore only ever
// fast-forward a node along a chain whose ROOT the network has just vouched
// for; a tampered or foreign snapshot is refused by the key check, and a
// tampered ANCHOR is refused by gate 4 before this file is ever opened. There
// is no flag here that turns either check off.
//
// SCOPE FENCE (standing XMR-lane rule): src/impl/xmr/ only. No consensus
// digest, no src/sharechain/v37.
//
// Header-only. STL + <filesystem>; the digest is the anchor tree's own SHA-256.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_sha256.hpp"
#include "impl/xmr/native/contracts/types.hpp"

namespace c2pool::xmr::native::rt {

// ---------------------------------------------------------------------------
// The identity a snapshot is bound to. Two nodes may only exchange snapshots
// when all three agree: same network, same anchor height, same anchor id.
//
// On a genesis boot there is no anchor bundle, and the key is {0, genesis id} --
// which is an identity in exactly the same sense (a node that booted from the
// stagenet genesis must not read an image written by a mainnet one) and keeps
// one code path instead of two.
// ---------------------------------------------------------------------------
struct SnapshotKey {
    std::uint64_t net           = 0;   // the XmrNet the index was built for
    std::uint64_t anchor_height = 0;
    Hash          anchor_id{};

    bool operator==(const SnapshotKey& o) const noexcept {
        return net == o.net && anchor_height == o.anchor_height && anchor_id == o.anchor_id;
    }
    bool operator!=(const SnapshotKey& o) const noexcept { return !(*this == o); }
};

// "C2XSNAP1", little-endian, the same trick the index's own magic uses.
inline constexpr std::uint64_t kSnapshotEnvelopeMagic   = 0x3150414E53583243ull;
inline constexpr std::uint64_t kSnapshotEnvelopeVersion = 1;

// A ceiling on what load() will read off disk before it has checked anything.
// The index's own image is bounded by row_retention * a row plus snapshot_depth
// block bodies; 512 MiB is far above any legitimate one and far below a file
// that could exhaust a pool host's memory by being pointed at.
inline constexpr std::uint64_t kSnapshotMaxBytes = 512ull * 1024 * 1024;

namespace snapshot_detail {

inline void put_u64(std::vector<std::uint8_t>& o, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) o.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xff));
}

inline std::uint64_t get_u64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(p[i]) << (8 * i);
    return v;
}

} // namespace snapshot_detail

// ---------------------------------------------------------------------------
// encode: image -> envelope. Infallible by construction (it only appends), so
// it returns the bytes rather than a bool nobody could act on.
// ---------------------------------------------------------------------------
inline std::vector<std::uint8_t> encode_snapshot_envelope(const SnapshotKey& key,
                                                          const std::vector<std::uint8_t>& image) {
    using snapshot_detail::put_u64;
    std::vector<std::uint8_t> out;
    out.reserve(image.size() + 96);
    put_u64(out, kSnapshotEnvelopeMagic);
    put_u64(out, kSnapshotEnvelopeVersion);
    put_u64(out, key.net);
    put_u64(out, key.anchor_height);
    out.insert(out.end(), key.anchor_id.begin(), key.anchor_id.end());
    put_u64(out, static_cast<std::uint64_t>(image.size()));
    out.insert(out.end(), image.begin(), image.end());

    anchor_hash::Sha256 h;
    h.update(out.data(), out.size());
    const std::array<std::uint8_t, 32> d = h.finish();
    out.insert(out.end(), d.begin(), d.end());
    return out;
}

// ---------------------------------------------------------------------------
// decode: envelope -> image, or a reason. FAIL-CLOSED in every direction; the
// caller's only correct response to `false` is to stay on the anchor boot.
//
// The digest is checked BEFORE any length inside the file is trusted, so a
// truncated or corrupt file cannot steer the reader with its own header.
// ---------------------------------------------------------------------------
inline bool decode_snapshot_envelope(const std::vector<std::uint8_t>& in,
                                     const SnapshotKey& expect,
                                     std::vector<std::uint8_t>& image,
                                     std::string& why) {
    using snapshot_detail::get_u64;
    image.clear();

    // 8 magic + 8 version + 8 net + 8 height + 32 id + 8 len + 32 digest.
    constexpr std::size_t kFixed = 8 + 8 + 8 + 8 + 32 + 8 + 32;
    if (in.size() < kFixed) { why = "snapshot file is too short to be an envelope"; return false; }

    const std::size_t body_len = in.size() - 32;
    anchor_hash::Sha256 h;
    h.update(in.data(), body_len);
    const std::array<std::uint8_t, 32> d = h.finish();
    for (std::size_t i = 0; i < 32; ++i) {
        if (d[i] != in[body_len + i]) {
            why = "snapshot envelope digest does not match its contents";
            return false;
        }
    }

    const std::uint8_t* p = in.data();
    if (get_u64(p) != kSnapshotEnvelopeMagic) {
        why = "snapshot envelope magic is wrong (not a c2pool chain snapshot)";
        return false;
    }
    if (get_u64(p + 8) != kSnapshotEnvelopeVersion) {
        why = "snapshot envelope version is not one this build writes";
        return false;
    }

    SnapshotKey got;
    got.net           = get_u64(p + 16);
    got.anchor_height = get_u64(p + 24);
    for (std::size_t i = 0; i < got.anchor_id.size(); ++i) got.anchor_id[i] = p[32 + i];

    if (got.net != expect.net) {
        why = "snapshot was written for a different Monero network";
        return false;
    }
    if (got.anchor_height != expect.anchor_height || got.anchor_id != expect.anchor_id) {
        why = "snapshot is bound to a different trust anchor than the one this node "
              "booted on (height " + std::to_string(got.anchor_height) + " vs "
            + std::to_string(expect.anchor_height) + ")";
        return false;
    }

    const std::uint64_t len = get_u64(p + 64);
    if (len > kSnapshotMaxBytes) { why = "snapshot image length is implausible"; return false; }
    if (72 + len != static_cast<std::uint64_t>(body_len)) {
        why = "snapshot image length disagrees with the file size";
        return false;
    }
    image.assign(in.begin() + 72, in.begin() + static_cast<std::ptrdiff_t>(body_len));
    return true;
}

// ---------------------------------------------------------------------------
// Disk. Reading is bounded before the bytes are taken; writing goes through a
// sibling temporary and a rename so that a crash mid-write leaves either the
// previous snapshot or none, never a half one. (A half one would be caught by
// the digest anyway -- and would still have cost the operator the good file.)
// ---------------------------------------------------------------------------
inline bool read_snapshot_file(const std::string& path,
                               std::vector<std::uint8_t>& out,
                               std::string& why) {
    out.clear();
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) { why = "no snapshot at " + path; return false; }
    const std::uintmax_t sz = std::filesystem::file_size(path, ec);
    if (ec) { why = "cannot size " + path; return false; }
    if (sz == 0 || sz > kSnapshotMaxBytes) {
        why = "snapshot file size is implausible (" + std::to_string(sz) + " bytes)";
        return false;
    }
    std::ifstream f(path, std::ios::binary);
    if (!f) { why = "cannot open " + path; return false; }
    out.resize(static_cast<std::size_t>(sz));
    f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(sz));
    if (!f) { out.clear(); why = "short read on " + path; return false; }
    return true;
}

inline bool write_snapshot_file(const std::string& path,
                                const std::vector<std::uint8_t>& bytes,
                                std::string& why) {
    std::error_code ec;
    const std::filesystem::path p(path);
    if (p.has_parent_path()) {
        std::filesystem::create_directories(p.parent_path(), ec);
        ec.clear();   // a pre-existing directory is not an error, and the open below is the test
    }
    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) { why = "cannot open " + tmp + " for writing"; return false; }
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        f.flush();
        if (!f) { why = "short write on " + tmp; return false; }
    }
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(tmp, ec);
        why = "cannot rename " + tmp + " onto " + path;
        return false;
    }
    return true;
}

} // namespace c2pool::xmr::native::rt
