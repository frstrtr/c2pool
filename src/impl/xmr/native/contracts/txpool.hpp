// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/contracts/txpool.hpp
//
// C3 relayed-txpool surfaces: the relay sink C1 calls, the snapshot C4 selects
// from, and the two body-access surfaces C2 and C5 need.
//
// MUST-FIX (a): the tx-relay verdict is named TxRelayVerdict here. The BLOCK
// relay verdict lives in relay.hpp as BlockRelayVerdict. The two used to share
// the name RelayVerdict, which made the C1/C3 and C5 headers unincludable in
// one translation unit; they are different shapes with different consumers and
// they now have different names.
//
// MUST-FIX (b): validation depth is an AdmissionEvidence BITMASK, not a scalar
// tier. The four kinds of evidence are ORTHOGONAL -- in particular
// DaemonConfirmed (a monerod that accepted the tx) is not "more" than
// FeePolicy, it is different evidence obtained a different way, and a scalar
// ladder could not express "daemon-confirmed but our own fee replica has not
// run yet". Config gates on a required MASK.
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <vector>

#include "types.hpp"

namespace c2pool::xmr::native {

// ---------------------------------------------------------------------------
// Admission evidence (must-fix b)
// ---------------------------------------------------------------------------
// Each flag records ONE independently obtained fact about a transaction. Flags
// are set as evidence is gathered and never cleared except on eviction.
enum class AdmissionEvidence : std::uint8_t {
    None              = 0,
    // Decoded cleanly and passed the structural check table: version, rct type
    // in the accepted set, ring sizes, extra size, unlock_time == 0, weight and
    // output-count bounds. Cheap, always available.
    Structural        = 1u << 0,
    // Our own replica of monerod's fee policy accepted the fee for the tx
    // weight at the current fee context (the T1 leg of ruling R-VAL).
    FeePolicy         = 1u << 1,
    // Non-input consensus checks passed: range proofs and commitment balance,
    // key-image domain. This is the leg that needs vendored ringct code and is
    // gated on ruling R-VAL.
    NonInputConsensus = 1u << 2,
    // An armed monerod accepted the transaction into its own pool. Free while a
    // daemon is armed, unobtainable once the daemon is demoted (M5), which is
    // exactly why it cannot be a rung on a ladder with the other three.
    DaemonConfirmed   = 1u << 3,
};

inline constexpr AdmissionEvidence operator|(AdmissionEvidence a, AdmissionEvidence b) noexcept {
    return static_cast<AdmissionEvidence>(static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b));
}
inline constexpr AdmissionEvidence operator&(AdmissionEvidence a, AdmissionEvidence b) noexcept {
    return static_cast<AdmissionEvidence>(static_cast<std::uint8_t>(a) & static_cast<std::uint8_t>(b));
}
inline constexpr AdmissionEvidence& operator|=(AdmissionEvidence& a, AdmissionEvidence b) noexcept {
    a = a | b; return a;
}
inline constexpr bool any(AdmissionEvidence e) noexcept {
    return static_cast<std::uint8_t>(e) != 0;
}
// True when `have` carries every flag in `required`.
inline constexpr bool covers(AdmissionEvidence have, AdmissionEvidence required) noexcept {
    return (static_cast<std::uint8_t>(have) & static_cast<std::uint8_t>(required))
           == static_cast<std::uint8_t>(required);
}

// The daemonless default recommended by ruling R-VAL: structural + our own fee
// replica. Key-image cleanliness and peer corroboration are separate pool-side
// conditions (they are not evidence about the transaction in isolation).
inline constexpr AdmissionEvidence EVIDENCE_DAEMONLESS_DEFAULT =
        AdmissionEvidence::Structural | AdmissionEvidence::FeePolicy;

// ---------------------------------------------------------------------------
// Relay verdict for TRANSACTIONS (must-fix a: was RelayVerdict)
// ---------------------------------------------------------------------------
struct TxRelayVerdict {
    enum class Reason : std::uint8_t {
        Accepted = 0,
        Duplicate,
        Structural,
        TooBig,
        WeightLimit,
        BadVersion,
        BadRing,
        ExtraTooBig,
        UnlockNotZero,
        KeyImageConflict,
        FeeTooLow,
        ProofFail,
        PoolFull,
        NotSynced,
    };

    Reason reason = Reason::Accepted;
    // Whether the peer that sent this should be scored down. Mirrors monerod's
    // drop-offence split: a duplicate or a full pool is not the peer's fault.
    bool   drop_offense = false;
    Hash   id{};
    // What we learned about the transaction while forming this verdict.
    AdmissionEvidence evidence = AdmissionEvidence::None;
};

inline const char* to_string(TxRelayVerdict::Reason r) noexcept {
    switch (r) {
        case TxRelayVerdict::Reason::Accepted:         return "Accepted";
        case TxRelayVerdict::Reason::Duplicate:        return "Duplicate";
        case TxRelayVerdict::Reason::Structural:       return "Structural";
        case TxRelayVerdict::Reason::TooBig:           return "TooBig";
        case TxRelayVerdict::Reason::WeightLimit:      return "WeightLimit";
        case TxRelayVerdict::Reason::BadVersion:       return "BadVersion";
        case TxRelayVerdict::Reason::BadRing:          return "BadRing";
        case TxRelayVerdict::Reason::ExtraTooBig:      return "ExtraTooBig";
        case TxRelayVerdict::Reason::UnlockNotZero:    return "UnlockNotZero";
        case TxRelayVerdict::Reason::KeyImageConflict: return "KeyImageConflict";
        case TxRelayVerdict::Reason::FeeTooLow:        return "FeeTooLow";
        case TxRelayVerdict::Reason::ProofFail:        return "ProofFail";
        case TxRelayVerdict::Reason::PoolFull:         return "PoolFull";
        case TxRelayVerdict::Reason::NotSynced:        return "NotSynced";
    }
    return "?";
}

// NOTIFY_REQUEST_GET_TXPOOL_COMPLEMENT (2010) id cap.
inline constexpr std::size_t MAX_TXPOOL_COMPLEMENT_IDS = 131072;

// ---------------------------------------------------------------------------
// C1 -> C3 (D-6): the verdict vector is what C1 needs for peer scoring.
// ---------------------------------------------------------------------------
class IRelayedTxSink {
public:
    virtual ~IRelayedTxSink() = default;

    // NOTIFY_NEW_TRANSACTIONS (2002). One verdict per input blob, in order.
    // Called on the io thread: the pool enqueues and answers from what it can
    // decide cheaply, and the verdict is advisory for peer scoring only.
    virtual std::vector<TxRelayVerdict> on_relayed(
            const PeerRef&,
            std::vector<std::vector<std::uint8_t>> blobs,
            bool                                   dandelionpp_fluff) = 0;

    // Ids we already hold, for the txpool complement exchange (2010).
    // At most MAX_TXPOOL_COMPLEMENT_IDS entries.
    virtual std::vector<Hash> complement_request_ids() const = 0;
};

// ---------------------------------------------------------------------------
// C3 -> C4 (D-7): the assembler-facing snapshot. The element type is the
// EXISTING node::TxBacklogEntry so the option-B assembler is not touched.
// ---------------------------------------------------------------------------
class ITxpoolSnapshot {
public:
    virtual ~ITxpoolSnapshot() = default;

    // Already filtered: not conflicted, evidence covers the configured mask,
    // fluffed (or stem allowed), and corroborated by at least the configured
    // number of peers. The validity classification itself stays C3-internal.
    virtual std::vector<node::TxBacklogEntry> selectable_backlog() const = 0;

    // Monotone; bumps whenever selectable_backlog() could differ.
    virtual std::uint64_t backlog_version() const = 0;
};

// ---------------------------------------------------------------------------
// C3 -> C2: body lookup for block completion. C2 re-hashes what it gets back
// and never trusts the pool's id.
// ---------------------------------------------------------------------------
class ITxSource {
public:
    virtual ~ITxSource() = default;
    virtual bool get_tx(const Hash& id, std::vector<std::uint8_t>& full_blob) = 0;
};

// ---------------------------------------------------------------------------
// C3 -> C5 (D-8): bodies for a block we are about to relay, pinned for as long
// as the template that selected them can still win.
// ---------------------------------------------------------------------------
class ITxBlobSource {
public:
    virtual ~ITxBlobSource() = default;

    virtual bool get_blobs(const std::vector<Hash>&                ids,
                           std::vector<std::vector<std::uint8_t>>& out,
                           std::vector<Hash>&                      missing) = 0;

    // Pin the bodies a template selected. C4 pins on build and unpins when the
    // template leaves the old-templates ring (plus a grace period).
    virtual void pin(const Hash& template_id, const std::vector<Hash>& ids) = 0;
    virtual void unpin(const Hash& template_id) = 0;
};

} // namespace c2pool::xmr::native
