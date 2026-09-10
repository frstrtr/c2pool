// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/consensus/xmr_hf_table.hpp
//
// The vendored Monero hard-fork table and the version-dependent consensus rules
// the native node reads, plus the CARROT / FCMP++ FENCE.
//
// Two things depend on getting this right, and they fail in opposite ways:
//
//   * we advertise top_version in HANDSHAKE and TIMED_SYNC. Advertise the wrong
//     one and every peer disconnects us -- a pure availability failure, loud;
//   * we decide which transaction shapes, ring size and reward rules apply at a
//     height. Get that wrong and we build an invalid block -- a safety failure,
//     quiet until our block is rejected and our identity is banned.
//
// So the table is a compile-time constant (never read from a peer, never read
// from the environment), and anything above the last version we actually
// implement is FENCED: the node halts that path and falls back to an armed
// daemon rather than guessing at a fork it was not built for. This is the
// fail-closed side of ruling R-HF, and it is the standing cost of tracking
// Monero: every hard fork needs a code change here.
//
// Heights are monero-project src/cryptonote_basic/hardfork.cpp
// (mainnet_hard_forks / testnet_hard_forks / stagenet_hard_forks) as of the
// v0.18.x series. The stagenet rows are cross-checked against the live stagenet
// daemon this wave captured its transaction golden from: blocks at height
// 1100000 report major_version 14 and blocks at 1399268 report 16, which
// brackets the v15/v16 rows below.
// ---------------------------------------------------------------------------
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace c2pool::xmr::native {

enum class XmrNet : std::uint8_t { Mainnet = 0, Testnet = 1, Stagenet = 2, Regtest = 3 };

inline const char* to_string(XmrNet n) noexcept {
    switch (n) {
        case XmrNet::Mainnet:  return "mainnet";
        case XmrNet::Testnet:  return "testnet";
        case XmrNet::Stagenet: return "stagenet";
        case XmrNet::Regtest:  return "regtest";
    }
    return "?";
}

// The highest major version this code implements. Monero's next fork introduces
// CARROT addressing and FCMP++ membership proofs, which change the transaction
// format, the weight accounting and the coinbase output shape. Until that work
// is done, version 17 and above are refused rather than approximated.
inline constexpr std::uint8_t MAX_IMPLEMENTED_HF_VERSION = 16;

struct HardForkRow {
    std::uint8_t  version;
    std::uint64_t height;
};

// --- mainnet -----------------------------------------------------------------
inline constexpr HardForkRow MAINNET_HARD_FORKS[] = {
    { 1,       1 }, { 2, 1009827 }, { 3, 1141317 }, { 4, 1220516 },
    { 5, 1288616 }, { 6, 1400000 }, { 7, 1546000 }, { 8, 1685555 },
    { 9, 1686275 }, {10, 1788000 }, {11, 1788720 }, {12, 1978433 },
    {13, 2210000 }, {14, 2210720 }, {15, 2688888 }, {16, 2689608 },
};

// --- testnet -----------------------------------------------------------------
inline constexpr HardForkRow TESTNET_HARD_FORKS[] = {
    { 1,       1 }, { 2,  624634 }, { 3,  800500 }, { 4,  801219 },
    { 5,  802660 }, { 6,  971400 }, { 7, 1057027 }, { 8, 1057058 },
    { 9, 1057778 }, {10, 1154318 }, {11, 1155038 }, {12, 1308737 },
    {13, 1543939 }, {14, 1544659 }, {15, 1982800 }, {16, 1983520 },
};

// --- stagenet ----------------------------------------------------------------
inline constexpr HardForkRow STAGENET_HARD_FORKS[] = {
    { 1,       1 }, { 2,   32000 }, { 3,   33000 }, { 4,   34000 },
    { 5,   35000 }, { 6,   36000 }, { 7,   37000 }, { 8,  176456 },
    { 9,  177176 }, {10,  269000 }, {11,  269720 }, {12,  454721 },
    {13,  675405 }, {14,  676125 }, {15, 1151000 }, {16, 1151720 },
};

// A private regtest chain starts at the newest version we implement, from
// height 1, which is what monerod --regtest --fixed-difficulty does.
inline constexpr HardForkRow REGTEST_HARD_FORKS[] = {
    { MAX_IMPLEMENTED_HF_VERSION, 1 },
};

struct HardForkTable {
    const HardForkRow* rows  = nullptr;
    std::size_t        count = 0;
};

inline constexpr HardForkTable hard_fork_table(XmrNet net) noexcept {
    switch (net) {
        case XmrNet::Mainnet:  return { MAINNET_HARD_FORKS,  sizeof(MAINNET_HARD_FORKS)  / sizeof(HardForkRow) };
        case XmrNet::Testnet:  return { TESTNET_HARD_FORKS,  sizeof(TESTNET_HARD_FORKS)  / sizeof(HardForkRow) };
        case XmrNet::Stagenet: return { STAGENET_HARD_FORKS, sizeof(STAGENET_HARD_FORKS) / sizeof(HardForkRow) };
        case XmrNet::Regtest:  return { REGTEST_HARD_FORKS,  sizeof(REGTEST_HARD_FORKS)  / sizeof(HardForkRow) };
    }
    return { MAINNET_HARD_FORKS, sizeof(MAINNET_HARD_FORKS) / sizeof(HardForkRow) };
}

// The major version consensus requires at a height. Heights below the first row
// resolve to version 1.
inline constexpr std::uint8_t hf_version_for_height(XmrNet net, std::uint64_t height) noexcept {
    const HardForkTable t = hard_fork_table(net);
    std::uint8_t v = 1;
    for (std::size_t i = 0; i < t.count; ++i) {
        if (height >= t.rows[i].height) v = t.rows[i].version;
        else break;
    }
    return v;
}

// The activation height of a version, or 0 when the version is not in the table.
inline constexpr std::uint64_t hf_height_for_version(XmrNet net, std::uint8_t version) noexcept {
    const HardForkTable t = hard_fork_table(net);
    for (std::size_t i = 0; i < t.count; ++i)
        if (t.rows[i].version == version) return t.rows[i].height;
    return 0;
}

// --- the fence ---------------------------------------------------------------
inline constexpr bool hf_is_fenced(std::uint8_t version) noexcept {
    return version > MAX_IMPLEMENTED_HF_VERSION;
}

// --- version-dependent consensus rules --------------------------------------
// RandomX from v12; before that the chain used CryptoNight variants that this
// node deliberately does not implement (nothing it will ever sync reaches back
// that far from a modern anchor).
inline constexpr bool hf_randomx_active(std::uint8_t version) noexcept { return version >= 12; }

// Ring size: 11 from v12 (mixin 10), 16 from v15 (mixin 15).
inline constexpr std::size_t hf_ring_size(std::uint8_t version) noexcept {
    if (version >= 15) return 16;
    if (version >= 12) return 11;
    if (version >= 8)  return 7;
    if (version >= 7)  return 5;
    if (version >= 6)  return 3;
    return 0;   // not pinned before v6
}

// The rct type a non-coinbase transaction must carry.
//   v13, v14 -> CLSAG (5);  v15, v16 -> BulletproofPlus (6).
// Returns 0 when the version is outside the pinned range.
inline constexpr std::uint8_t hf_required_rct_type(std::uint8_t version) noexcept {
    if (version >= 15) return 6;
    if (version >= 13) return 5;
    if (version >= 11) return 4;
    if (version >= 10) return 3;
    return 0;
}

// Tagged-key outputs (view tags) from v15.
inline constexpr bool hf_view_tags_active(std::uint8_t version) noexcept { return version >= 15; }

// --- the check every consumer calls -----------------------------------------
enum class HfStatus : std::uint8_t {
    Ok = 0,
    Fenced,          // above MAX_IMPLEMENTED_HF_VERSION: halt, fall back to a daemon
    VersionTooLow,   // below the version the table requires at this height
    MinorTooLow,     // minor_version must be at least the required major
};

inline const char* to_string(HfStatus s) noexcept {
    switch (s) {
        case HfStatus::Ok:            return "Ok";
        case HfStatus::Fenced:        return "Fenced";
        case HfStatus::VersionTooLow: return "VersionTooLow";
        case HfStatus::MinorTooLow:   return "MinorTooLow";
    }
    return "?";
}

// Checks a block header's version pair against the table. `why` receives a
// one-line reason on anything but Ok.
//
// Note the asymmetry, which is monerod's: a block may carry a major version
// ABOVE the table's (that is how a fork is voted in), so a higher version is
// not an error -- but if it is above what we implement it is FENCED, and we
// stop rather than pretend to understand it.
inline HfStatus hf_check_block_version(XmrNet net, std::uint64_t height,
                                       std::uint8_t major, std::uint8_t minor,
                                       std::string& why) {
    const std::uint8_t required = hf_version_for_height(net, height);
    if (major < required) {
        why = "block major_version " + std::to_string(major) + " below required "
            + std::to_string(required) + " at height " + std::to_string(height);
        return HfStatus::VersionTooLow;
    }
    if (hf_is_fenced(major)) {
        why = "block major_version " + std::to_string(major)
            + " is beyond the implemented fork range (max "
            + std::to_string(MAX_IMPLEMENTED_HF_VERSION)
            + "); halting this path -- the CARROT / FCMP++ fence";
        return HfStatus::Fenced;
    }
    // From v8 monerod requires minor_version >= major_version in a block header.
    if (major >= 8 && minor < major) {
        why = "block minor_version " + std::to_string(minor) + " below major "
            + std::to_string(major);
        return HfStatus::MinorTooLow;
    }
    why.clear();
    return HfStatus::Ok;
}

// The version we advertise as top_version. Same fence: if our own tip is at a
// version we do not implement, we do not advertise it, we stop.
inline HfStatus hf_top_version(XmrNet net, std::uint64_t tip_height,
                               std::uint8_t& out, std::string& why) {
    const std::uint8_t v = hf_version_for_height(net, tip_height);
    if (hf_is_fenced(v)) {
        out = 0;
        why = "network is at fork version " + std::to_string(v)
            + " which this build does not implement";
        return HfStatus::Fenced;
    }
    out = v;
    why.clear();
    return HfStatus::Ok;
}

} // namespace c2pool::xmr::native
