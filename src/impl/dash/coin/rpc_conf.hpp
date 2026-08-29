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

// ---------------------------------------------------------------------------
// DASHD-CUT arm authority (daemonless cut mode).
//
// THE DEFECT THIS CLOSES (hotel-reserve thrash, 2026-08-15):
// removing --coin-rpc was COSMETIC. conf.armed() alone (creds resolved from the
// DEFAULT ~/.dashcore/dash.conf) re-armed the dashd-fallback CoindRPC to
// 127.0.0.1:9998. When the operator then stopped dashd, the armed-but-dead RPC
// entered a hot sync_reconnect spin (~30/s) whose every failure invalidated the
// template cache and starved the working embedded arm -> 0 shares served though
// the embedded arm was producing valid templates the whole time.
//
// The fix DECOUPLES two independent axes that conf.armed() had conflated:
//   (1) OPERATOR INTENT  -- did the operator EXPLICITLY name a coin RPC?
//       (--coin-rpc / --coin-daemon endpoint, or --coin-rpc-auth creds path,
//        or a one-shot that only dashd can service, e.g. --submit-block.)
//   (2) CREDS RESOLVED   -- conf.armed() (rpcuser+rpcpassword+port present).
//
// The dashd-fallback CoindRPC is CONSTRUCTED only when BOTH hold. With NO
// explicit request the node is in DAEMONLESS CUT MODE: rpc == nullptr, the
// embedded/null arm is AUTHORITATIVE, and a stray dash.conf can no longer arm a
// hot-spinning fallback behind the operator's back. This is pure invocation-
// level policy (no I/O, no allocation), so it is unit-testable in isolation and
// cannot drift from the launcher.
//
// WITH-dashd behaviour is UNCHANGED: any invocation that names --coin-rpc /
// --coin-rpc-auth still arms exactly as before (ArmedLive). Only the accidental
// "no flag + stray dash.conf" arming is removed -- which is precisely the cut.
enum class DashdArm
{
    Disarmed,   ///< cut mode: no CoindRPC constructed; embedded/null arm authoritative
    ArmedLive,  ///< operator named a coin RPC AND creds resolved: construct NodeRPC
};

struct DashdArmDecision
{
    bool        construct_rpc = false;              ///< launcher: `if (d.construct_rpc)` build+connect NodeRPC
    DashdArm    arm           = DashdArm::Disarmed;
    const char* reason        = "";                 ///< operator-facing banner text
};

// Pure resolution. `coin_rpc_requested` = the operator EXPLICITLY asked for a
// coin RPC (endpoint override, auth-path override, or a dashd-only one-shot).
// `creds_armed` = conf.armed(). No hidden state; no ordering dependence.
inline DashdArmDecision resolve_dashd_arm(bool coin_rpc_requested, bool creds_armed)
{
    DashdArmDecision d;
    if (!coin_rpc_requested) {
        // Cut mode. Even if a stray dash.conf makes creds_armed true, the arm
        // stays OFF: the operator did not ask for dashd, so we do not spin one
        // up. This is the line that makes removing --coin-rpc actually cut.
        d.construct_rpc = false;
        d.arm           = DashdArm::Disarmed;
        d.reason        = "daemonless cut mode (no --coin-rpc/--coin-rpc-auth): "
                          "dashd-fallback arm OFF, embedded/null arm authoritative";
        return d;
    }
    if (!creds_armed) {
        // Requested but no usable creds/port: cannot arm. Fail CLOSED (unarmed),
        // loudly -- never silently spin against an endpoint with no auth.
        d.construct_rpc = false;
        d.arm           = DashdArm::Disarmed;
        d.reason        = "coin RPC requested but creds/port unresolved "
                          "(no rpcuser/rpcpassword in dash.conf) -- arm stays OFF";
        return d;
    }
    d.construct_rpc = true;
    d.arm           = DashdArm::ArmedLive;
    d.reason        = "coin RPC requested and creds resolved "
                      "(dashd-fallback arm ARMED)";
    return d;
}

} // namespace coin
} // namespace dash