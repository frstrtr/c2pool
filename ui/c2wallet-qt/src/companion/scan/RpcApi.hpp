// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — the dashd JSON-RPC transport seam.
//
// SourceDashd speaks to dashd only through this interface: one synchronous
// call per JSON-RPC method, the transport returning the raw HTTP status and
// body. SourceDashd builds the parameters and parses the JSON-RPC envelope
// ({"result": ..., "error": {"code", "message"}, "id"}) itself, so a transport
// carries no RPC knowledge: the KATs drive a scripted fake, and the real Qt
// transport (slice S-C, next to QtNodeApi) adds only the loopback-URL rule and
// the credentials read at use from a 0600 cookie / rpcauth file.
//
// Methods SourceDashd calls (all read-only):
//   getblockchaininfo, getblockcount, getbestblockhash, getblockhash,
//   getaddressutxos {"addresses":[...], "chainInfo":true}   (needs -addressindex)
//   scantxoutset "start" ["addr(A)", ...]                    (fallback)
//   gettxout txid n true                                     (per row)

#include <string>

namespace c2w::companion::scan {

struct RpcReply {
    bool transport_ok = false; // false: connect refused, timeout, socket error
    int http_status = 0;       // dashd answers 200, or 500 with a JSON-RPC error body
    std::string body;          // the JSON-RPC reply envelope
    std::string error;         // transport error text when !transport_ok
};

struct RpcApi {
    virtual ~RpcApi() = default;
    // `params_json` is the JSON array of positional parameters, e.g. "[]".
    virtual RpcReply call(const std::string& method, const std::string& params_json) = 0;
    virtual const char* name() const = 0;
};

} // namespace c2w::companion::scan
