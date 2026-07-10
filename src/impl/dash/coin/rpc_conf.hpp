// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// ---------------------------------------------------------------------------
// dash::coin::rpc_conf -- dash.conf credential resolution for the launcher
// slice-3 external-daemon submitblock arm (the RPC leg of the won-block
// dual-path broadcaster; the embedded-P2P relay leg is still DEFERRED).
//
// Credential rule (operator self-provision posture, STANDING RULE 2026-06-18):
// the rpcpassword NEVER reaches the process table. --coin-rpc carries only
// HOST:PORT; --coin-rpc-auth carries a FILE PATH to the conf (default
// ~/.dashcore/dash.conf); rpcuser/rpcpassword are read from that file and are
// never echoed. 1:1 mirror of src/impl/dgb/coin/rpc_conf.hpp, conformed to
// DASH (dash.conf default path + dash_rpc_* aliases), fenced in src/impl/dash/
// only -- zero shared/core touch, per-coin isolation held.
//
// Header-only and dependency-light by design (no config_pool.hpp pull): the
// net-default RPC port is supplied by the caller, so a standalone conf-parse
// guard can exercise the parser without dragging the coin config in.
// ---------------------------------------------------------------------------

#include <cstdint>
#include <fstream>
#include <string>

namespace dash
{
namespace coin
{

// Resolved external-daemon RPC endpoint + credentials. `armed()` is the single
// gate the launcher consults before constructing a NodeRPC: no creds (or no
// port) => the submit arm stays UNARMED and submit_block_hex returns false
// LOUDLY, identical to the daemon-less default build. NEVER remove the
// external-daemon RPC fallback (V36 external_fallback mandate).
struct RpcConf
{
    std::string host = "127.0.0.1";
    uint16_t    port = 0;   // 0 => caller fills the per-net default
    std::string user;
    std::string pass;

    bool armed() const { return !user.empty() && !pass.empty() && port != 0; }
    std::string userpass() const { return user + ":" + pass; }
};

namespace conf_detail
{
inline std::string trim(const std::string& s)
{
    const char* ws = " \t\r\n";
    const auto b = s.find_first_not_of(ws);
    if (b == std::string::npos) return {};
    const auto e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}
} // namespace conf_detail

// Parse rpcuser/rpcpassword/rpcport/rpcconnect from a dash.conf-style file
// (also accepts the c2pool dash_rpc_user/dash_rpc_password aliases). '#' begins
// a comment. Returns true ONLY when BOTH user and password were found; the
// password stays in-file and is never logged.
inline bool load_rpc_conf(const std::string& path, RpcConf& out)
{
    std::ifstream f(path);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        const auto h = line.find('#');
        if (h != std::string::npos) line = line.substr(0, h);
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = conf_detail::trim(line.substr(0, eq));
        const std::string val = conf_detail::trim(line.substr(eq + 1));
        if (val.empty()) continue;
        if      (key == "rpcuser"     || key == "dash_rpc_user")     out.user = val;
        else if (key == "rpcpassword" || key == "dash_rpc_password") out.pass = val;
        else if (key == "rpcport")    out.port = static_cast<uint16_t>(std::stoi(val));
        else if (key == "rpcconnect") out.host = val;
    }
    return !out.user.empty() && !out.pass.empty();
}

// Apply a "--coin-rpc HOST:PORT" endpoint override. Endpoint only -- carries no
// secret, so it is safe on the process table. A bare "HOST" leaves the port at
// whatever the conf/default supplied; an empty argument is a no-op.
inline void apply_endpoint_override(const std::string& hostport, RpcConf& out)
{
    if (hostport.empty()) return;
    const auto colon = hostport.rfind(':');
    if (colon == std::string::npos) { out.host = hostport; return; }
    out.host = hostport.substr(0, colon);
    const std::string p = hostport.substr(colon + 1);
    if (!p.empty()) out.port = static_cast<uint16_t>(std::stoi(p));
}

} // namespace coin
} // namespace dash