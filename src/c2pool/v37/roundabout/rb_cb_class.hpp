#pragma once
// S2 — per-share coinbase class (cb_class u8) -> payout byte budget.
//
// A share commits the coinbase-size class of the hardware/firmware that will
// build the coinbase if that share wins. The class maps to a byte ceiling:
//
//   class  bytes    hardware
//     0      750    stock Antminer (the FLOOR class: unknown/absent -> 0)
//     1     2250    S21 stock
//     2     6500    Whatsminer
//     3    16384    VNish / ePIC / Bitaxe
//     4    65535    open-firmware SV1 max
//     5    K_max    SV2 header-only (the template is not size-bound by the
//                   miner; the lane K_max is the only ceiling)
//
//   budget = min(class_bytes - fixed_overhead, free_space_after_txs, lane K_max)
//
// RECOMPUTABLE FROM THE BLOCK ALONE: class is committed on-chain (one byte in
// the coinbase tail), fixed_overhead and free_space_after_txs are measured from
// the block's own bytes, and lane K_max is a lane parameter — so every
// validator recomputes the identical budget and can check the coinbase's
// payout bytes against it (budget_from_block + payout_within_budget).
//
// K_fair is UNTOUCHED: the budget only sets CoinbaseBudget::max_payout_bytes;
// W5 assemble() (w5_coinbase.hpp:416-425) still fills in strict K_fair order
// (oldest first_eligible first, key ASC, h_min carry) and stops at the first
// output that would exceed it — every remaining balance carries forward.
//
// ★ HAZARD pinned here: w5 CoinbaseBudget::max_payout_bytes == 0 means
// UNBOUNDED (w5_coinbase.hpp:144). A computed budget of 0 bytes (overhead >=
// class bytes, or a full block) must NOT become "unbounded": cb_budget() returns
// at least 1, which admits no output (every output is >= 32 bytes) and carries
// every balance forward.

#include <algorithm>
#include <cstdint>
#include <optional>
#include <vector>

#include "rb_params.hpp"

namespace c2pool::v37n::rb {

enum class CbClass : std::uint8_t {
    STOCK_ANTMINER   = 0,
    S21_STOCK        = 1,
    WHATSMINER       = 2,
    OPEN_FW_16K      = 3,   // VNish / ePIC / Bitaxe
    OPEN_FW_SV1_MAX  = 4,
    SV2_HEADER_ONLY  = 5,
};

inline constexpr std::uint8_t CB_CLASS_MAX = 5;
inline constexpr u64 CB_CLASS_BYTES[5] = {750, 2250, 6500, 16384, 65535};
inline constexpr u64 CB_FLOOR_BYTES = 750;

// ON-CHAIN decode: a committed byte > 5 is INVALID (the block fails the
// recompute), never silently mapped — a validator must not guess a budget.
inline std::optional<CbClass> decode_cb_class(std::uint8_t b) {
    if (b > CB_CLASS_MAX) return std::nullopt;
    return static_cast<CbClass>(b);
}

// TEMPLATE-side selection: an unknown / unreported / out-of-range class takes
// the FLOOR class 0 (750 B). This is the only place a default is chosen.
inline CbClass template_cb_class(std::optional<std::uint8_t> reported) {
    if (!reported || *reported > CB_CLASS_MAX) return CbClass::STOCK_ANTMINER;
    return static_cast<CbClass>(*reported);
}

inline std::uint8_t encode_cb_class(CbClass c) { return static_cast<std::uint8_t>(c); }

// Class ceiling in bytes. lane_kmax == 0 is the w5 "unbounded" convention, so
// class 5 under an unbounded lane has no class ceiling (UINT64_MAX).
inline u64 class_bytes(CbClass c, u64 lane_kmax) {
    if (c == CbClass::SV2_HEADER_ONLY) return lane_kmax == 0 ? ~u64(0) : lane_kmax;
    return CB_CLASS_BYTES[static_cast<std::uint8_t>(c)];
}

// budget = min(class_bytes - fixed_overhead, free_space_after_txs, lane K_max),
// saturating at 0 then lifted to 1 (never the w5 "unbounded" 0; see HAZARD).
inline u64 cb_budget(CbClass c, u64 fixed_overhead, u64 free_space_after_txs, u64 lane_kmax) {
    const u64 cb = class_bytes(c, lane_kmax);
    u64 b = cb > fixed_overhead ? cb - fixed_overhead : 0;
    b = std::min(b, free_space_after_txs);
    if (lane_kmax != 0) b = std::min(b, lane_kmax);
    return b == 0 ? 1 : b;
}

// The facts a validator reads off the block itself.
struct BlockFacts {
    std::uint8_t cb_class_byte = 0;   // committed in the coinbase tail
    u64 coinbase_fixed_overhead = 0;  // coinbase bytes excluding payout outputs
    u64 block_limit_bytes = 0;        // coin rule (e.g. BTC 4M WU / 4 for legacy bytes)
    u64 txs_bytes = 0;                // serialized non-coinbase tx bytes
};

inline u64 free_space_after_txs(const BlockFacts& f) {
    const u64 used = f.txs_bytes + f.coinbase_fixed_overhead;
    return f.block_limit_bytes > used ? f.block_limit_bytes - used : 0;
}

// nullopt => the committed class byte is invalid (block rejects).
inline std::optional<u64> budget_from_block(const BlockFacts& f, u64 lane_kmax) {
    const auto c = decode_cb_class(f.cb_class_byte);
    if (!c) return std::nullopt;
    return cb_budget(*c, f.coinbase_fixed_overhead, free_space_after_txs(f), lane_kmax);
}

inline bool payout_within_budget(u64 payout_bytes, u64 budget) { return payout_bytes <= budget; }

}  // namespace c2pool::v37n::rb
