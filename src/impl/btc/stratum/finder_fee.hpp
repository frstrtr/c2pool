// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// btc::stratum::v35_finder_fee_split — integer-exact v35 block-finder fee.
//
// The mined-block coinbase moves 0.5% of the coinbase value from the donation
// residual to the share-finder's payout output. This mirrors the p2pool
// reference (data.py generate_transaction):
//     amounts[finder] += share_data['subsidy'] // 200   # 0.5%, floor, unconditional
// where p2pool's `subsidy` is the block-template coinbasevalue (subsidy +
// fees) — so the c2pool base is coinbasevalue (matching core/web_server.cpp).
//
// The consensus share gentx already computes this integer-exactly; this SSOT
// keeps the block-coinbase money path identical: floor division, NO float, so
// there is no sub-satoshi rounding divergence on a won block.
//
// Returns the satoshis actually moved: floor(coinbasevalue / 200), capped at
// the donation available so the coinbase stays balanced (total == subsidy) and
// no output goes negative. The cap only binds in a pathological rounding edge —
// in canonical operation the donation residual (~0.5%) covers the fee (~0.5%),
// so the full fee is always applied (unconditional; never all-or-nothing
// skipped as the prior float path did when donation < fee).

#include <algorithm>
#include <cstdint>

namespace btc::stratum {

inline uint64_t v35_finder_fee_split(uint64_t coinbasevalue, uint64_t donation_sats)
{
    const uint64_t finder_fee = coinbasevalue / 200;  // integer floor == subsidy//200
    return std::min(finder_fee, donation_sats);
}

} // namespace btc::stratum
