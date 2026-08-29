// Coin display-identity registry — the C++ analog of the frontend coin
// descriptor table (web-static/sharechain-explorer/src/pplns/classify.ts).
//
// ONE table maps an uppercase coin symbol to its canonical network name and
// human display name. This is a WEB / DISPLAY layer only: it feeds /node_info,
// the dashboard header, and other identity surfaces. It NEVER feeds consensus,
// address validation, block assembly, or any reward path — those resolve coin
// behaviour through the Blockchain enum and the per-coin PoolConfig, not this
// table.
//
// Why a registry rather than another enum switch: coin identity was scattered
// across three parallel switches (rest_node_info, node_symbol, primary_chain_key)
// plus a label-keyed if-chain in rest_web_currency_info. A coin like BCH that
// deliberately shares a Blockchain enum value with BITCOIN (SHA256d graph_db
// pairing) has no enum row of its own, so an enum switch cannot name it — it
// falls through to Bitcoin's label. The runtime key that already carries the
// truth for every lane is the configured coin label; resolving identity through
// this table, keyed by that label, gives BCH (and any future label-keyed coin)
// its own honest name without adding it to the consensus enum.
#pragma once

#include <string>

namespace core {

struct CoinDescriptor {
    const char* symbol;        // uppercase ticker, e.g. "BCH"
    const char* chain_name;    // canonical lowercase network name, e.g. "bitcoincash"
    const char* display_name;  // human-readable, e.g. "Bitcoin Cash"
};

// Resolve a coin descriptor by uppercase symbol. Returns nullptr for an unknown
// symbol so the caller can fall back to the label itself — honesty rule: an
// unknown coin is never given a fabricated network name.
inline const CoinDescriptor* coin_descriptor(const std::string& symbol_uc)
{
    static constexpr CoinDescriptor kCoins[] = {
        {"LTC",  "litecoin",    "Litecoin"},
        {"BTC",  "bitcoin",     "Bitcoin"},
        {"DOGE", "dogecoin",    "Dogecoin"},
        {"DASH", "dash",        "Dash"},
        {"DGB",  "digibyte",    "DigiByte"},
        {"BCH",  "bitcoincash", "Bitcoin Cash"},
        {"NMC",  "namecoin",    "Namecoin"},
    };
    for (const auto& d : kCoins) {
        if (symbol_uc == d.symbol) return &d;
    }
    return nullptr;
}

}  // namespace core
