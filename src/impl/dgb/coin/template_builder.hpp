#pragma once
// DGB block-template builder. Mirrors src/impl/btc/coin/template_builder.hpp.
// Must emit p2pool-merged-v36-compatible templates (V36 master compat).
//
// >>> SCRYPT GBT FILTER POINT (M1 §3) <<<
// DGB multi-algo: getblocktemplate is requested with rules=["scrypt"] so the
// embedded daemon only returns Scrypt-eligible templates. The builder assembles
// and submits Scrypt blocks only in V36. (config_coin.hpp CoinParams::GBT_ALGO.)
//
// Share/PoW format is identical to LTC Scrypt; share assembly reuses the shared
// Scrypt-family path (do NOT fork LTC share logic — per-coin isolation).
// TODO(M3): TemplateBuilder emitting p2pool-merged-v36-parity Scrypt templates.
namespace c2pool::dgb { /* TODO(M3): TemplateBuilder, Scrypt GBT */ }
