// SPDX-License-Identifier: AGPL-3.0-or-later
//
// RULES RATCHET (operator rulings 2026-10-03): the EPOCH table of the XMR lane.
//
// A lane block names its pool and its EPOCH (V37P v2, xmr_credit_cut.hpp); the
// rules of every epoch are a Deployment descriptor, compiled per network and
// carried in the relay HELLO after the lane-rules TLV:
//
//   Deployment (61 B) = u32 epoch_no | b32 rules_digest | u8 kind | u64 start_height |
//                       u64 timeout_height | u64 fixed_height
//   kind: 0 genesis (epoch 1 only: start 0, timeout 0, fixed 0)
//         1 signal  (the ballot tally, spec sec. 6.2; timeout_height = start + TIMEOUT(network))
//         2 height  (emergency / operator-run networks: fixed_height >= start + GRACE, timeout 0)
//
// Slice R1 ships the LAYOUT and the one-entry table (epoch 1 = the node's own
// lane rules, ACTIVE from H_act = 0). The tally, lock-in, the RATCHET event's
// position and the follower HOLD are slice R3 (xmr_epoch_tally.hpp); the
// codec, the validity checks and epoch_of() below are what R3 builds on and
// what the HELLO already carries, so the wire format never moves again.
//
// Integer-only; no relay / impl deps.
#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>   // ::v37::bytes32
#include <c2pool/v37/w4_settlement.hpp>   // the ledger's epoch rows (EpochState, EpochRow, LedgerEpochTable)

namespace c2pool::v37n::xmr::epoch {

using bytes32 = ::v37::bytes32;

inline constexpr std::uint8_t  kKindGenesis = 0;
inline constexpr std::uint8_t  kKindSignal  = 1;
inline constexpr std::uint8_t  kKindHeight  = 2;
inline constexpr std::size_t   kDeploymentBytes = 4 + 32 + 1 + 8 + 8 + 8;   // 61
inline constexpr std::size_t   kMaxDeployments  = 64;                      // HELLO n_epochs bound (Q1 default)
inline constexpr std::uint32_t kGenesisEpoch    = 1;

struct Deployment {
    std::uint32_t epoch_no = kGenesisEpoch;
    bytes32       rules_digest{};      // lanerules::rules_digest(rules_of(epoch_no))
    std::uint8_t  kind = kKindGenesis;
    std::uint64_t start_height = 0;
    std::uint64_t timeout_height = 0;
    std::uint64_t fixed_height = 0;
    bool operator==(const Deployment&) const = default;
};

// The epoch-1 descriptor: the node's own lane rules, in force from H_act = 0.
inline Deployment genesis_deployment(const bytes32& rules_digest) {
    Deployment d;
    d.epoch_no = kGenesisEpoch; d.rules_digest = rules_digest; d.kind = kKindGenesis;
    d.start_height = 0; d.timeout_height = 0; d.fixed_height = 0;
    return d;
}

// ── codec (little-endian, 61 B) ─────────────────────────────────────────────
namespace detail {
inline void put32(std::vector<std::uint8_t>& b, std::uint32_t v) { for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i))); }
inline void put64(std::vector<std::uint8_t>& b, std::uint64_t v) { for (int i = 0; i < 8; ++i) b.push_back(static_cast<std::uint8_t>(v >> (8 * i))); }
inline std::uint32_t get32(const std::uint8_t* p) { std::uint32_t v = 0; for (int i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(p[i]) << (8 * i); return v; }
inline std::uint64_t get64(const std::uint8_t* p) { std::uint64_t v = 0; for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(p[i]) << (8 * i); return v; }
} // namespace detail

inline void put_deployment(std::vector<std::uint8_t>& b, const Deployment& d) {
    detail::put32(b, d.epoch_no);
    b.insert(b.end(), d.rules_digest.begin(), d.rules_digest.end());
    b.push_back(d.kind);
    detail::put64(b, d.start_height);
    detail::put64(b, d.timeout_height);
    detail::put64(b, d.fixed_height);
}
inline std::vector<std::uint8_t> encode_deployment(const Deployment& d) {
    std::vector<std::uint8_t> b; b.reserve(kDeploymentBytes); put_deployment(b, d); return b;
}
// Exactly kDeploymentBytes at `p`.
inline Deployment get_deployment(const std::uint8_t* p) {
    Deployment d;
    d.epoch_no = detail::get32(p);
    std::memcpy(d.rules_digest.data(), p + 4, 32);
    d.kind = p[36];
    d.start_height = detail::get64(p + 37);
    d.timeout_height = detail::get64(p + 45);
    d.fixed_height = detail::get64(p + 53);
    return d;
}

// ── validity of a list (spec sec. 4.1): "" = valid; else the refusal text ───
// epoch_no strictly ascending from 1; entry 1 is kind 0 with start/timeout/fixed
// 0; every other entry is kind 1 (timeout > start) or kind 2 (fixed > start,
// timeout 0); n in 1..kMaxDeployments.
inline std::string deployments_refusal(const std::vector<Deployment>& v) {
    if (v.empty()) return "epochs: the deployment list is empty (epoch 1 is mandatory)";
    if (v.size() > kMaxDeployments) return "epochs: " + std::to_string(v.size()) + " deployments, the bound is " + std::to_string(kMaxDeployments);
    for (std::size_t i = 0; i < v.size(); ++i) {
        const Deployment& d = v[i];
        if (i == 0) {
            if (d.epoch_no != kGenesisEpoch) return "epochs: the first deployment is epoch " + std::to_string(d.epoch_no) + ", epoch 1 is mandatory";
            if (d.kind != kKindGenesis || d.start_height || d.timeout_height || d.fixed_height)
                return "epochs: epoch 1 must be kind 0 (genesis) with start/timeout/fixed 0";
            continue;
        }
        if (d.epoch_no <= v[i - 1].epoch_no)
            return "epochs: epoch_no not strictly ascending at entry " + std::to_string(i) + " (" + std::to_string(d.epoch_no) + ")";
        if (d.kind == kKindSignal) {
            if (d.timeout_height <= d.start_height || d.fixed_height != 0)
                return "epochs: epoch " + std::to_string(d.epoch_no) + " (kind 1) needs timeout > start and fixed 0";
        } else if (d.kind == kKindHeight) {
            if (d.fixed_height <= d.start_height || d.timeout_height != 0)
                return "epochs: epoch " + std::to_string(d.epoch_no) + " (kind 2) needs fixed > start and timeout 0";
        } else {
            return "epochs: epoch " + std::to_string(d.epoch_no) + " has an unknown kind " + std::to_string(d.kind);
        }
    }
    return {};
}

inline const Deployment* find_deployment(const std::vector<Deployment>& v, std::uint32_t epoch_no) {
    for (const auto& d : v) if (d.epoch_no == epoch_no) return &d;
    return nullptr;
}
inline std::uint32_t epoch_max_of(const std::vector<Deployment>& v) {
    std::uint32_t m = 0;
    for (const auto& d : v) if (d.epoch_no > m) m = d.epoch_no;
    return m;
}

// ── the activation state an epoch row carries in the LEDGER (spec sec. 3.1/3.2) ──
// The row types live in the ledger (L/w4_settlement.hpp: EpochState, EpochRow,
// LedgerEpochTable), so the digest's V37Y / V37V sections and this table are
// one object. Epoch 1 is ACTIVE at H_act 0 from the genesis.
using State = ::c2pool::v37n::settle::EpochState;
using EpochRow = ::c2pool::v37n::settle::EpochRow;
using LedgerEpochTable = ::c2pool::v37n::settle::LedgerEpochTable;
using ::c2pool::v37n::settle::to_string;

// epoch_of(h) = max { e : state(e) in {LOCKED_IN, ACTIVE}, H_act(e) <= h }, with H_act(1) = 0.
inline std::uint32_t epoch_of(const std::vector<EpochRow>& rows, std::uint64_t height) {
    std::uint32_t e = 0;
    for (const auto& r : rows)
        if ((r.state == State::LockedIn || r.state == State::Active) && r.H_act <= height && r.epoch_no > e) e = r.epoch_no;
    return e == 0 ? kGenesisEpoch : e;
}

// The Deployment of a ledger row (what HELLO carries for it).
inline Deployment deployment_of(const EpochRow& r, std::uint64_t start = 0, std::uint64_t timeout = 0, std::uint64_t fixed = 0) {
    Deployment d;
    d.epoch_no = r.epoch_no; d.rules_digest = r.rules_digest; d.kind = r.kind;
    d.start_height = start; d.timeout_height = timeout; d.fixed_height = fixed;
    return d;
}

// Per-network constants of the state machine (spec sec. 6.1; CONSTITUTIONAL C2/C7).
// Carried here so R3's tally and the KATs read one table. network: 0 mainnet
// 1 testnet 2 stagenet 3 regtest (D_conf of regtest = as configured).
struct NetConsts {
    std::uint32_t K = 48;            // finalized lane blocks with a passing box, in a row
    std::uint64_t L = 17280;         // lane positions spanned by the streak (two windows)
    std::uint64_t GRACE = 1440;      // heights from h_L to H_act (>= D_conf + 1)
    std::uint64_t TIMEOUT = 43200;   // heights after start_height until FAILED (kind 1)
};
inline NetConsts net_consts(std::uint8_t network, std::uint64_t d_conf = 60) {
    NetConsts c;
    if (network == 0) { c.K = 48; c.L = 17280; c.GRACE = 1440; c.TIMEOUT = 43200; }
    else if (network == 1 || network == 2) { c.K = 8; c.L = 8640; c.GRACE = 120; c.TIMEOUT = 10080; }
    else { c.K = 2; c.L = 0; c.GRACE = 2 * d_conf; c.TIMEOUT = 1000; }
    return c;
}

} // namespace c2pool::v37n::xmr::epoch
