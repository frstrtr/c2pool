#pragma once
//
// version_gate.hpp — Cross-coin c2pool share-version activation gate (SINGLE SOURCE OF TRUTH).
//
// c2pool's sharechain format is versioned. The V36 format revision is a
// CONSENSUS boundary that is IDENTICAL across every coin c2pool mines
// (btc/ltc/bch/dgb): when a share's VERSION >= 36 the wire layout switches to
// the V36 encoding (VarInt subsidy, AbsworkV36Format, merged_addresses,
// merged_coinbase_info + merged_payout_hash, V36HashLinkType extra_data,
// message_data) and the V36 PPLNS / donation semantics engage. The activation
// number 36 carries no per-coin network state — every coin's params set
// current_share_version = 36 — so it belongs here in core/ rather than being
// re-spelled as a bare `>= 36` literal at each call site.
//
// SCOPE — what this gate does and does NOT own:
//   OWNS:   the V36 share-format / consensus-revision boundary (uniform 36).
//   NOT:    segwit activation. That version is coin-SPECIFIC
//           (BTC 33, dgb 35, ltc/bch 17) and stays in each coin's PoolConfig
//           as SEGWIT_ACTIVATION_VERSION, surfaced via the per-coin
//           is_segwit_activated() helper. Do not fold segwit into this gate.
//
// Conformance shape (BTC-first, per v36-standardize goal):
//   Every coin replaces its scattered `version >= 36` / `>= 36` literals with
//   core::version_gate::is_v36_active(version). Both compile-time
//   (`if constexpr (is_v36_active(Tmpl::version))`) and runtime
//   (`if (is_v36_active(p.share_version))`) call sites are covered because the
//   predicate is constexpr. BTC is the reference adoption; ltc/dgb/bch conform
//   by mechanical site-rewrite — no value changes, byte-for-byte identical gate.
//
// Provenance: p2pool check() gates the V36 share rev on self.VERSION >= 36
//   (jtoomim/forrestv). The number is shared across the c2pool multi-coin tree.
//

#include <cstdint>

namespace core::version_gate
{

// V36 share-format / consensus-revision activation version. Uniform cross-coin.
inline constexpr uint64_t V36_ACTIVATION_VERSION = 36;

// True iff a share of the given VERSION uses the V36 sharechain encoding and
// V36 consensus semantics. constexpr so it serves both `if constexpr` template
// gates and runtime checks.
constexpr bool is_v36_active(uint64_t version)
{
    return version >= V36_ACTIVATION_VERSION;
}

} // namespace core::version_gate
