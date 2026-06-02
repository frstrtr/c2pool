#pragma once
// BCH block-template builder. Mirrors src/impl/btc/coin/template_builder.hpp.
// Must emit p2pool-merged-v36-compatible templates (V36 master compat).
//
// >>> CTOR INSERTION POINT (M1 §4.3) <<<
// BCH requires CTOR: canonical (lexicographic txid) ordering of mempool txs
// in the block body, coinbase first. Net-new c2pool code (second BCH slice).
// TODO(M3): CTOR re-sort pass over selected txs before template assembly.
//
// CashTokens (May 2023) awareness: token-bearing outputs must round-trip
// intact through template assembly. TODO(M3): preserve token prefix bytes.
// HogEx: NOT applicable (see config_coin.hpp scope note).
namespace c2pool::bch { /* TODO(M3): TemplateBuilder w/ CTOR re-sort */ }
