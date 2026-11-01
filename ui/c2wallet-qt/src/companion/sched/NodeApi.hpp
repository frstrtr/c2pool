// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — the node transport seam. The core speaks to a c2pool
// node only through this interface: GET a loopback route, POST a JSON body.
// It is synchronous on purpose, so Scheduler::tick() is a plain function and
// the KATs drive it with a scripted fake. The Qt Network implementation
// (QtNodeApi, slice S2) runs each request to completion with a 15 s guard, no
// proxy, no redirects and no custom headers.
//
// Routes the core uses (all loopback-only on the node, all on master):
//   POST /api/tx-inject/submit           the inject itself (token in the body)
//   GET  /api/tx-inject-status           armed? pool and rate-limit counts
//   POST /api/config/apply               two-phase arm, only with recorded consent
//   GET  /api/explorer/getblockchaininfo tip (taken only when synced)
//   GET  /api/explorer/getrawmempool     still pooled?
//   GET  /api/explorer/getmempoolentry?txid=   time_added (the IS-hold clock)
//   GET  /api/explorer/getblock?height=H       mined? (retained bodies)
//   GET  /api/explorer/getblockhash?height=H   reorg check

#include <string>

namespace c2w::companion::sched {

struct HttpReply {
    bool transport_ok = false; // false: connect refused, timeout, socket error
    int status = 0;            // HTTP status when transport_ok
    std::string body;
    std::string error;         // transport error text when !transport_ok
};

struct NodeApi {
    virtual ~NodeApi() = default;
    virtual HttpReply get(const std::string& path) = 0;
    virtual HttpReply post_json(const std::string& path, const std::string& body) = 0;
    virtual const char* name() const = 0;
};

namespace route {
inline constexpr const char* kSubmit = "/api/tx-inject/submit";
inline constexpr const char* kStatus = "/api/tx-inject-status";
inline constexpr const char* kConfigApply = "/api/config/apply";
inline constexpr const char* kChainInfo = "/api/explorer/getblockchaininfo";
inline constexpr const char* kRawMempool = "/api/explorer/getrawmempool";
inline constexpr const char* kMempoolEntry = "/api/explorer/getmempoolentry?txid=";
inline constexpr const char* kBlockAtHeight = "/api/explorer/getblock?height=";
inline constexpr const char* kBlockHash = "/api/explorer/getblockhash?height=";
} // namespace route

} // namespace c2w::companion::sched
