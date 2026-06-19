#pragma once
#include <cstdint>

// ---------------------------------------------------------------------------
// NMC merged-mining chain-id SSOT (v37 bucket-2 standardization, note #2).
//
// Lightweight, dependency-free home for the single consensus chain-id constant
// the parent share trackers need when enumerating aux payout chains, so they
// need NOT pull the full embedded header_chain.hpp (leveldb/block/transaction)
// just to read a chain id. NMCChainParams::aux_chain_id defaults to this.
//
// Namecoin nAuxpowChainId = 0x0001 on both mainnet and testnet
// (Namecoin src/chainparams.cpp). NOT DOGE's 0x0062.
namespace nmc {
namespace coin {

inline constexpr uint32_t NMC_AUXPOW_CHAIN_ID = 0x0001;

} // namespace coin
} // namespace nmc
