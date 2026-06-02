#pragma once
// c2pool-bch :: BCH coin parameters (V36)
// Skeleton per c2pool-bch-embedded-impl-plan.md (frstrtr/the docs/v36) §3.
// Embedded daemon forked from Bitcoin Cash Node (BCHN). SHA256d family.
//
// SCOPE NOTE (M1 §4.2): HogEx is a SmartBCH sidechain construct, NOT BCH
// mainchain. It is explicitly OUT OF SCOPE for this template/coin module.
// Do not add HogEx commitment handling here. See feedback: hogex-not-bch.
//
// CashAddr scaffolding: BCH address encoding diverges from BTC base58/bech32.
// TODO(M3): port CashAddr (prefix "bitcoincash:") encode/decode at vendoring.

namespace c2pool::bch {

struct CoinParams {
    // TODO(M3): fill from BCHN chainparams at vendoring (confirm commit/tag).
    static constexpr const char* ticker      = "BCH";
    static constexpr const char* cashaddr_hrp = "bitcoincash";
    // ASERT DAA (May 2020) anchor — see coin/header_chain.hpp insertion point.
    // CTOR (Nov 2018) canonical tx ordering — see coin/template_builder.hpp.
};

} // namespace c2pool::bch
