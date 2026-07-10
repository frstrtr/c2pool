// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// bch::coin::BCHChainParams -- genesis-hash conformance vs Bitcoin Cash Node.
//
// Pins the mainnet / testnet3 / testnet4 genesis block hashes that the embedded
// daemon's HeaderChain seeds as its chain root against the AUTHORITATIVE values
// in BCHN v29.0.0 src/chainparams.cpp (commit 89a591f). The literals below are
// transcribed verbatim from BCHN's `assert(consensus.hashGenesisBlock == ...)`
// statements -- NOT copied from header_chain.hpp -- so this is a real reference
// pin: a future edit that silently drifts a genesis constant fails here, even
// though header-internal round-trips would still pass.
//
//   mainnet  chainparams.cpp:203  uint256S("000000000019d6...8ce26f")  (== BTC)
//   testnet3 chainparams.cpp:456  uint256S("000000000933ea...7f4943")  (== BTC)
//   testnet4 chainparams.cpp:676  BlockHash::fromHex("00000000...fd9f7b") (own)
//
// mainnet/testnet3 share Bitcoin's pre-fork genesis (BCH forked at height
// 478558); testnet4 has its OWN genesis -- a BCH-specific consensus constant.
// Closes header_chain.hpp:188 TODO(M3) "verify genesis_hash vs VM300 bchn-bch
// chainparams.cpp" -- verified vs the BCHN v29.0.0 source the VM300 node runs.
//
// p2pool-merged-v36 surface: NONE. per-coin isolation: src/impl/bch/ only.
// Header-only over coin/header_chain.hpp (no peer, socket, or coin lib).
// ---------------------------------------------------------------------------

#include <cassert>
#include <iostream>
#include <string>

#include "../coin/header_chain.hpp"

using bch::coin::BCHChainParams;

int main()
{
    // BCHN v29.0.0 src/chainparams.cpp authoritative genesis constants.
    const std::string BCHN_MAINNET_GENESIS  =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const std::string BCHN_TESTNET3_GENESIS =
        "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943";
    const std::string BCHN_TESTNET4_GENESIS =
        "000000001dd410c49a788668ce26751718cc797474d3152a5fc073dd44fd9f7b";

    const auto mainnet  = BCHChainParams::mainnet();
    const auto testnet3 = BCHChainParams::testnet();
    const auto testnet4 = BCHChainParams::testnet4();

    assert(mainnet.genesis_hash.GetHex()  == BCHN_MAINNET_GENESIS);
    assert(testnet3.genesis_hash.GetHex() == BCHN_TESTNET3_GENESIS);
    assert(testnet4.genesis_hash.GetHex() == BCHN_TESTNET4_GENESIS);

    // The fast-start checkpoint root must seed AT genesis (height 0) with the
    // genesis hash -- the cold-start IBD invariant the HeaderChain relies on.
    assert(mainnet.fast_start_checkpoint.has_value());
    assert(testnet3.fast_start_checkpoint.has_value());
    assert(testnet4.fast_start_checkpoint.has_value());
    assert(mainnet.fast_start_checkpoint->height == 0);
    assert(mainnet.fast_start_checkpoint->hash   == mainnet.genesis_hash);
    assert(testnet3.fast_start_checkpoint->hash  == testnet3.genesis_hash);
    assert(testnet4.fast_start_checkpoint->hash  == testnet4.genesis_hash);

    // mainnet and testnet3 share Bitcoin's pre-fork genesis; testnet4 diverges.
    assert(testnet4.genesis_hash != mainnet.genesis_hash);
    assert(testnet4.genesis_hash != testnet3.genesis_hash);

    std::cout << "bch genesis conformance vs BCHN v29.0.0: ALL PASS\n";
    return 0;
}