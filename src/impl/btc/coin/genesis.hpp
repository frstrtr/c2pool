// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// btc::coin genesis-hash SSOT for NodeRPC::check().
//
// check() probes getblockheader(<genesis>) to confirm the external daemon is a
// real bitcoind on the SELECTED network (a wrong-coin / wrong-net daemon does
// not answer for this hash). Historically check() hard-coded the *Litecoin*
// genesis (copied verbatim from the LTC impl and never corrected), so on BTC
// MAINNET the `is_main_chain && !has_block` gate always failed -> a permanent
// 15s reconnect loop and a degraded ARM B on the one network where a lost block
// is real money (#744/#787 B1, a #759-class cross-coin copy-paste drift).
//
// Per-net values sourced from bitcoin/src/kernel/chainparams.cpp and mirrored in
// header_chain.hpp. Kept as a per-coin ISOLATION primitive (bucket-1): pinned
// here so a standalone TU can guard against drift WITHOUT linking the beast
// transport, exactly as dgb/coin/rpc_request.hpp does for DGB.
// ---------------------------------------------------------------------------

namespace btc
{
namespace coin
{

inline constexpr const char* BTC_GENESIS_MAIN =
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
// testnet3 genesis. NodeRPC carries a single testnet bool; the check() gate only
// bites on `is_main_chain` (mainnet), so testnet3/testnet4/regtest all bypass it
// regardless (is_main_chain==false) -- the testnet value is the correct probe
// for a standard testnet3 daemon and harmless for the other test nets.
inline constexpr const char* BTC_GENESIS_TEST =
    "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";

// The genesis hash NodeRPC::check() probes for the selected network.
inline const char* btc_genesis_hash(bool testnet)
{
    return testnet ? BTC_GENESIS_TEST : BTC_GENESIS_MAIN;
}

} // namespace coin
} // namespace btc
