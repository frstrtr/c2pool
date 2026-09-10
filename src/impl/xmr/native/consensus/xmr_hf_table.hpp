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
// implement is reported as FENCED by hf_is_fenced().
//
// WHAT THIS FILE DECIDES, AND WHAT IT DOES NOT. It decides the VALUES: which
// version applies at a height, and which transaction shapes that version admits.
// It does NOT decide the unknown-fork POLICY -- whether meeting a fenced version
// halts the path and falls back to an armed daemon, or continues at risk. That
// is a wave-1 C2a ruling; this header only reports the fact and names it, and
// hf_check_block_version() returns HfStatus::Fenced as a distinct status
// precisely so the caller can act on it either way.
//
// The structure is built for VERSION-ROLLING, which is the standing cost of
// tracking Monero. Adding a fork is: one row in each net's table, one bump of
// MAX_IMPLEMENTED_HF_VERSION, and one row in each rule band below that the fork
// moves. Nothing else in the tree needs to change, and no rule is expressed as
// "the value at the newest version" so that rolling forward never silently
// reinterprets an older height.
//
// Heights are monero-project src/hardforks/hardforks.cpp
// (mainnet_hard_forks / testnet_hard_forks / stagenet_hard_forks) on the
// release-v0.18 branch. All 48 rows across the three networks were compared
// against that file row for row and match, and the KAT re-asserts every one of
// them from both sides of its activation -- a transcription slip in any row is
// a test failure, not something that shows up the first time we sync a chain.
// The stagenet rows are additionally cross-checked against the live stagenet
// daemon this wave captured its transaction golden from: blocks at height
// 1100000 report major_version 14 and blocks at 1399268 report 16, which
// brackets the v15/v16 rows below.
//
// The VERSION-DEPENDENT RULE functions below carry their own source of truth,
// which the first cut of this file did not: every threshold cites the constant
// in monero-project src/cryptonote_config.h that produces it, and the ones that
// can be observed are pinned against a synced stagenet daemon (monerod
// 0.18.5.1, read-only get_block / get_transactions over the activation bands).
// The observed values are reproduced in the KAT so a transcription slip cannot
// pass again -- the previous ring-size row was correct in its values and wrong
// in its thresholds, and the KAT only asserted the two rows that happened to
// line up.
//
// TWO OF THESE RULES ARE BANDS, NOT SCALARS. Monero introduces a new proof
// system (or ring size) as ALLOWED at one fork and only makes it REQUIRED at
// the next, so for one fork window two shapes are simultaneously valid on the
// chain. A single "the required value at version v" number cannot express that
// and will reject blocks the network accepts, so the predicates below answer
// "is this shape legal at this version" and the scalars answer only "what a
// freshly built transaction should use".
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

// --- ring size ---------------------------------------------------------------
// monerod gates the ring size on the MINIMUM MIXIN band. cryptonote_config.h:
//
//   (no constant; the pre-v6 floor)  -> mixin  2 -> ring  3
//   HF_VERSION_MIN_MIXIN_4  =  6     -> mixin  4 -> ring  5
//   HF_VERSION_MIN_MIXIN_6  =  7     -> mixin  6 -> ring  7
//   HF_VERSION_MIN_MIXIN_10 =  8     -> mixin 10 -> ring 11
//   HF_VERSION_MIN_MIXIN_15 = 15     -> mixin 15 -> ring 16
//
// Observed on stagenet (monerod 0.18.5.1, read-only): height 37000-37400 is
// major 7 with ring 7; 176481 is major 8 with ring 11; the whole major-15 band
// carries BOTH ring 11 and ring 16; the major-16 band carries ring 16 only.
//
// This function answers "what a transaction built at this version should use".
// It is NOT the admission test -- use hf_ring_size_allowed() for that.
inline constexpr std::size_t hf_ring_size(std::uint8_t version) noexcept {
    if (version >= 15) return 16;
    if (version >= 8)  return 11;
    if (version >= 7)  return 7;
    if (version >= 6)  return 5;
    return 3;   // monerod's pre-v6 floor: mixin 2
}

// The admission test. Below v15 monerod enforces the band above as a FLOOR (a
// larger ring is legal). From v15 the ring must be EXACTLY 16, with one
// documented exception: at exactly v15 -- the fork window itself -- a ring of 11
// is still accepted, which is why the major-15 stagenet band carries both. From
// v16 the exception is gone.
inline constexpr bool hf_ring_size_allowed(std::uint8_t version, std::size_t ring) noexcept {
    if (version >= 15) {
        if (ring == 16) return true;
        return version == 15 && ring == 11;   // the one-fork grace window
    }
    return ring >= hf_ring_size(version);
}

// --- rct type ----------------------------------------------------------------
// Type numbering is rct::RCTType, monero-project src/ringct/rctTypes.h:
//   0 Null (coinbase and pre-RingCT), 1 Full, 2 Simple (both Borromean),
//   3 Bulletproof, 4 Bulletproof2, 5 CLSAG, 6 BulletproofPlus.
// The in-tree spelling of those numbers is the RCT_TYPE_* constant family in
// consensus/xmr_tx_weight.hpp; this header deliberately does not re-declare it,
// so there stays exactly one place where a type number is named.
inline constexpr std::uint8_t XMR_RCT_TYPE_MAX = 6;

// The fork at which a type FIRST becomes legal for a non-coinbase transaction.
// 0 means "never legal" (an unknown type). cryptonote_config.h / blockchain.cpp
// Blockchain::check_tx_inputs:
//
//   type 1, 2  RingCT enabled at v4 (allowed; mandatory at HF_VERSION_ENFORCE_RCT = 6)
//   type 3     "Bulletproofs are not allowed before v8"          (hf_version < 8)
//   type 4     "not allowed before v10"   HF_VERSION_SMALLER_BP      = 10
//   type 5     "not allowed before v13"   HF_VERSION_CLSAG           = 13
//   type 6     "not allowed before v15"   HF_VERSION_BULLETPROOF_PLUS = 15
inline constexpr std::uint8_t hf_rct_type_allowed_from(std::uint8_t rct_type) noexcept {
    switch (rct_type) {
        case 0: return 1;    // non-RingCT; see the forbidden_from row below
        case 1:
        case 2: return 4;
        case 3: return 8;
        case 4: return 10;
        case 5: return 13;
        case 6: return 15;
        default: return 0;
    }
}

// The fork at which a type STOPS being legal. 0 means "still legal at the top of
// the implemented range". Same source; each of these is the fork AFTER the one
// that introduced its successor, which is what creates the one-fork grace band:
//
//   type 0     non-RingCT refused from HF_VERSION_ENFORCE_RCT = 6
//   type 1, 2  "Borromean range proofs are not allowed after v8"  (hf_version > 8)
//   type 3     "Ringct type 3 is not allowed from v11"            (hf_version > 10)
//   type 4     "not allowed from v14"                  (hf_version > HF_VERSION_CLSAG)
//   type 5     "Bulletproofs are not allowed from v16" (hf_version > HF_VERSION_BULLETPROOF_PLUS)
//   type 6     still current
inline constexpr std::uint8_t hf_rct_type_forbidden_from(std::uint8_t rct_type) noexcept {
    switch (rct_type) {
        case 0: return 6;
        case 1:
        case 2: return 9;
        case 3: return 11;
        case 4: return 14;
        case 5: return 16;
        case 6: return 0;
        default: return 1;
    }
}

// THE admission predicate for a non-coinbase transaction's rct type. A coinbase
// always carries type 0 and is exempt; so is a pre-v7 transaction spending an
// unmixable dust output, which this node never meets (it syncs from a modern
// anchor) and deliberately does not model.
//
// Observed on stagenet (monerod 0.18.5.1, read-only), one line per activation
// band, and every grace window is real chain data rather than a reading of the
// source:
//     major  7 -> {1, 2}     major 12 -> {4}
//     major  8 -> {3}        major 13 -> {4, 5}   <- CLSAG allowed, BP2 still legal
//     major  9 -> {3}        major 14 -> {5}
//     major 10 -> {3, 4}     major 15 -> {5, 6}   <- BP+ allowed, CLSAG still legal
//     major 11 -> {4}        major 16 -> {6}
inline constexpr bool hf_rct_type_allowed(std::uint8_t version, std::uint8_t rct_type) noexcept {
    const std::uint8_t from = hf_rct_type_allowed_from(rct_type);
    if (from == 0 || version < from) return false;
    const std::uint8_t until = hf_rct_type_forbidden_from(rct_type);
    return until == 0 || version < until;
}

// The REQUIRE edge: the lowest rct type still legal at `version`. A structural
// check that wants one number should use this as a FLOOR, never as an equality.
// Returns XMR_RCT_TYPE_MAX + 1 when no type at all is legal. Fencing is a
// separate question and hf_is_fenced() answers it.
inline constexpr std::uint8_t hf_min_rct_type(std::uint8_t version) noexcept {
    for (std::uint8_t t = 0; t <= XMR_RCT_TYPE_MAX; ++t)
        if (hf_rct_type_allowed(version, t)) return t;
    return XMR_RCT_TYPE_MAX + 1;
}

// The type a freshly built transaction should carry at `version`: the newest one
// the fork allows. Returns 0 when no type is legal.
inline constexpr std::uint8_t hf_newest_rct_type(std::uint8_t version) noexcept {
    for (std::uint8_t t = XMR_RCT_TYPE_MAX; t > 0; --t)
        if (hf_rct_type_allowed(version, t)) return t;
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
