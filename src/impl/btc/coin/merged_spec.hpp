// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once
// ---------------------------------------------------------------------------
// btc::parse_merged_spec — parse a c2pool "--merged" SPEC string into a typed
// c2pool::merged::AuxChainConfig for the embedded merged-mined NMC backend.
//
// SPEC grammar (mirrors the DOGE-under-LTC c2pool-style spec in main_ltc.cpp):
//     SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT]
//
// PE host-wire slice 3/N. #997 (slices 1-2) added the merged_addrs seam and
// collected raw --merged strings into merged_chain_specs but consumed nothing.
// This slice turns each raw spec into a validated AuxChainConfig; slice 4 feeds
// the aux-merkle payout from these configs into merged_addrs at the
// create_local_share call site. Pure/stateless so it KATs without a daemon;
// absent --merged the BTC host path stays v35 byte-for-byte.
// ---------------------------------------------------------------------------
#include <c2pool/merged/merged_mining.hpp>

#include <cstdint>
#include <exception>
#include <sstream>
#include <string>
#include <vector>

namespace btc {

// Parse one --merged SPEC into `out`. Returns true on success. On failure,
// leaves `out` untouched and writes a human-readable reason into `err` so the
// call site can LOG_ERROR + skip that chain (an invalid aux spec must not abort
// the parent BTC pool).
inline bool parse_merged_spec(const std::string& spec,
                              c2pool::merged::AuxChainConfig& out,
                              std::string& err)
{
    std::vector<std::string> parts;
    std::string token;
    std::istringstream ss(spec);
    while (std::getline(ss, token, ':'))
        parts.push_back(token);

    // Embedded NMC has no p2pool-style flag assembly yet (that lands with the
    // backend in a later slice), so the c2pool spec must be fully qualified:
    // the 6 mandatory fields plus an optional 7th P2P port.
    if (parts.size() < 6 || parts.size() > 7) {
        err = "expected SYMBOL:CHAIN_ID:HOST:PORT:USER:PASS[:P2P_PORT], got "
              + std::to_string(parts.size()) + " field(s)";
        return false;
    }
    if (parts[0].empty()) { err = "empty SYMBOL"; return false; }
    if (parts[2].empty()) { err = "empty HOST"; return false; }

    c2pool::merged::AuxChainConfig cfg;
    cfg.symbol = parts[0];
    try {
        unsigned long cid = std::stoul(parts[1]);
        if (cid == 0 || cid > 0xffffffffUL) { err = "CHAIN_ID out of range: " + parts[1]; return false; }
        cfg.chain_id = static_cast<uint32_t>(cid);
    } catch (const std::exception&) {
        err = "non-numeric CHAIN_ID: " + parts[1];
        return false;
    }
    cfg.rpc_host = parts[2];
    try {
        unsigned long port = std::stoul(parts[3]);
        if (port == 0 || port > 0xffffUL) { err = "PORT out of range: " + parts[3]; return false; }
        cfg.rpc_port = static_cast<uint16_t>(port);
    } catch (const std::exception&) {
        err = "non-numeric PORT: " + parts[3];
        return false;
    }
    cfg.rpc_userpass = parts[4] + ":" + parts[5];
    cfg.multiaddress = true;  // V36: canonical PPLNS coinbase for merged chains

    if (parts.size() == 7 && !parts[6].empty()) {
        try {
            unsigned long p2p = std::stoul(parts[6]);
            if (p2p > 0xffffUL) { err = "P2P_PORT out of range: " + parts[6]; return false; }
            cfg.p2p_port = static_cast<uint16_t>(p2p);
        } catch (const std::exception&) {
            err = "non-numeric P2P_PORT: " + parts[6];
            return false;
        }
    }
    cfg.p2p_address = cfg.rpc_host;  // default; explicit override lands with the backend slice

    out = std::move(cfg);
    return true;
}

} // namespace btc
