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
// Namecoin nAuxpowChainId = 0x0001 across ALL nets. PINNED from canonical
// Namecoin Core @ 6697dba480 (branch auxpow), src/kernel/chainparams.cpp:
//   :179 CMainParams  :345 CTestNetParams  :620 CTestNet4Params
//   :725 CRegTestParams  -> consensus.nAuxpowChainId = 0x0001 (all four).
// Live cross-check vs .140 namecoind deferred to PE item4 soak. NOT DOGE's 0x0062.
namespace nmc {
namespace coin {

inline constexpr uint32_t NMC_AUXPOW_CHAIN_ID = 0x0001;

} // namespace coin
} // namespace nmc
