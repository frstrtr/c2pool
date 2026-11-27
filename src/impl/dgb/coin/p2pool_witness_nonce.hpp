// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// The P2Pool witness reserved value: '[P2Pool]' four times (32 bytes). The
// P2Pool witness commitment output is SHA256d(wtxid merkle root || this value)
// (p2pool data.py generate_transaction), and a won block's coinbase witness
// carries this value. One copy: share_check.hpp and won_block_serialize.hpp.

namespace dgb {

inline constexpr unsigned char P2POOL_WITNESS_NONCE[32] = {
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
};

} // namespace dgb
