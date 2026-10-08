// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// src/impl/xmr/pathb/pathb_header_rules.hpp
// Path B: the header fields and the size verdict of a receipt body, the
// carrier's own body included [consensus].
//
//   S2.3 #9 (every receipt) and S1.3 #7 (carriers), one rule set, STRIKE:
//     major == hf_version(h)                    (hf_version_for_height on the lane's network)
//     timestamp >= median60(P_r branch)         (pathb_branch.hpp timestamp_median_for_child;
//                                                no median below 60 blocks: the rule does not apply)
//     n_tx <= floor(2 Z(P_r) / w_min); D == floor(log2(n_tx + 1 + X(hf)))
//     body length <= RECEIPT_CAP(hf, P_r)
//   No clock input: a timestamp ahead of local time is not judged here (the
//   future bound is relay policy P-29).
//
//   S2.3 #1a / #1b and the frame (K18):
//     a body longer than the receipt I/O buffer (P-10) or a frame longer than
//     the frame I/O buffer (P-11): DROP (no verdict, no token);
//     any other codec refusal: STRIKE;
//     a frame above FRAME_CAP at the largest receipt cap among its bodies: STRIKE.
//
// Header-only. Not included by any running component.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <optional>

#include "pathb_caps.hpp"               // receipt_size_rules, within_receipt_cap
#include "pathb_receipt_admission.hpp"  // AdmitVerdict
#include "pathb_wire_v3.hpp"            // HashingBlob, ReceiptBodyV3, WireError

namespace c2pool::xmr::pathb {

enum class HeaderFault : std::uint8_t {
    None,
    MajorVersion,          // major != hf_version(h)
    TimestampBelowMedian,  // timestamp < median60(P_r branch)
    TxCount,               // n_tx above floor(2 Z(P_r) / w_min), or no miner tx
    Depth,                 // D != floor(log2(n_tx + 1 + X(hf)))
    OverCap,               // body length above RECEIPT_CAP(hf, P_r)
};

// The two header rules. `hf`: the version Monero requires at the receipt's
// height; `median60`: empty when the branch is below 60 blocks.
inline constexpr HeaderFault header_rules(const HashingBlob& b, std::uint8_t hf,
                                          std::optional<std::uint64_t> median60) noexcept {
    if (b.major != hf) return HeaderFault::MajorVersion;
    if (median60.has_value() && b.timestamp < *median60) return HeaderFault::TimestampBelowMedian;
    return HeaderFault::None;
}

// Chain data of the receipt's own P_r branch.
struct HeaderInputs {
    std::uint8_t hf = 0;                    // hf_version(h(r))
    std::optional<std::uint64_t> median60;  // timestamp_median_for_child(P_r)
    std::uint64_t z = 0;                    // Z(P_r): the n_tx rule
    std::uint64_t z_lt = 0;                 // Z_lt(P_r): RECEIPT_CAP
};

// #9 / #7: the header rules, then the size rules, then the consensus cap.
// `body_bytes` is the length of the body as received.
inline HeaderFault header_fields(const ReceiptBodyV3& r, std::uint64_t body_bytes, const HeaderInputs& in) {
    if (const HeaderFault f = header_rules(r.blob, in.hf, in.median60); f != HeaderFault::None) return f;
    switch (receipt_size_rules(in.hf, in.z, r.blob.tx_count, r.branch.size())) {
        case SizeRule::Ok: break;
        case SizeRule::TxCount: return HeaderFault::TxCount;
        case SizeRule::Depth: return HeaderFault::Depth;
    }
    if (!within_receipt_cap(in.hf, in.z_lt, body_bytes)) return HeaderFault::OverCap;
    return HeaderFault::None;
}

// The verdict of #9 / #7: none when the row passes, else STRIKE.
inline constexpr std::optional<AdmitVerdict> header_fields_verdict(HeaderFault f) noexcept {
    if (f == HeaderFault::None) return std::nullopt;
    return AdmitVerdict::Strike;
}

// #1a / #1b: the codec outcome. None when the body decoded.
inline constexpr std::optional<AdmitVerdict> wire_verdict(WireError e) noexcept {
    if (e == WireError::None) return std::nullopt;
    if (wire_drop_without_verdict(e)) return AdmitVerdict::Drop;
    return AdmitVerdict::Strike;
}

// The frame length against the frame I/O buffer (before parsing) and FRAME_CAP.
inline constexpr std::optional<AdmitVerdict> frame_size_verdict(std::uint64_t frame_bytes,
                                                                std::uint64_t frame_buffer_bytes,
                                                                std::uint64_t frame_cap_bytes) noexcept {
    if (frame_bytes > frame_buffer_bytes) return AdmitVerdict::Drop;
    if (frame_bytes > frame_cap_bytes) return AdmitVerdict::Strike;
    return std::nullopt;
}

}  // namespace c2pool::xmr::pathb
