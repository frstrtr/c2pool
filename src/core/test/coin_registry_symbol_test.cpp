// SPDX-License-Identifier: AGPL-3.0-or-later
//
// KAT: label-first node-symbol resolution (core::resolve_node_symbol).
//
// Charter — the dashboard must never fabricate a coin identity. A BCH / NMC /
// BIP110 node shares the Blockchain::BITCOIN consensus enum (SHA256d graph
// pairing) but must report its OWN symbol on every surface, not "BTC". These
// vectors lock the label-first mapping that node_symbol() and the
// /pplns_current "coin" field now resolve through. Pure function — no HTTP or
// node fixture required.
#include <gtest/gtest.h>

#include <core/coin_registry.hpp>

using core::resolve_node_symbol;

// The three label-keyed coins that ride the BITCOIN enum: the enum symbol is
// "BTC" for all of them, yet each must report its configured label's symbol.
TEST(CoinRegistrySymbol, LabelKeyedCoinsSharingBitcoinEnumReportOwnSymbol) {
    EXPECT_EQ(resolve_node_symbol("BCH",    "BTC"), "BCH");
    EXPECT_EQ(resolve_node_symbol("bch",    "BTC"), "BCH");   // case-insensitive
    EXPECT_EQ(resolve_node_symbol("NMC",    "BTC"), "NMC");
    EXPECT_EQ(resolve_node_symbol("BIP110", "BTC"), "BIP110");
}

// Consensus-enum coins are unchanged: the label agrees with the enum symbol.
TEST(CoinRegistrySymbol, EnumCoinsUnchanged) {
    EXPECT_EQ(resolve_node_symbol("ltc",  "LTC"),  "LTC");
    EXPECT_EQ(resolve_node_symbol("btc",  "BTC"),  "BTC");
    EXPECT_EQ(resolve_node_symbol("doge", "DOGE"), "DOGE");
    EXPECT_EQ(resolve_node_symbol("dash", "DASH"), "DASH");
    EXPECT_EQ(resolve_node_symbol("dgb",  "DGB"),  "DGB");
}

TEST(CoinRegistrySymbol, UnknownLabelFallsBackToEnumThenLabel) {
    // Unknown label but a known enum -> keep the enum symbol (old behaviour).
    EXPECT_EQ(resolve_node_symbol("weirdcoin", "LTC"), "LTC");
    // Unknown label and no enum symbol -> raw uppercased label, never blank
    // while something was configured.
    EXPECT_EQ(resolve_node_symbol("weirdcoin", ""), "WEIRDCOIN");
    // Truly unconfigured -> empty, so callers surface "unknown" not a wrong coin.
    EXPECT_EQ(resolve_node_symbol("", ""), "");
}
