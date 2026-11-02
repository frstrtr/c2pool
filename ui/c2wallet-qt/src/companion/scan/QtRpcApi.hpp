// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — the Qt Network implementation of the dashd
// JSON-RPC seam (scan::RpcApi). It lives beside QtNodeApi in
// c2wallet-companion-qtnet (Qt6::Network), which only the companion GUI and
// c2wallet-qt-schedd link; the signer never does (ci/check_no_network.sh).
//
// Same transport discipline as QtNodeApi: a loopback-only http base URL
// (validate_node_url: a remote dashd is reached with ssh -L), no proxy, no
// redirects, no HTTP/2, no cache, no cookies, a hard timeout and a reply size
// cap. The one header it adds is Authorization: Basic, built at the moment of
// each request from the 0600 credentials file (read_rpc_auth_file) and wiped
// after it; the credentials are never kept between requests, never in argv.
// Residual (as for QtNodeApi's token body): Qt's HTTP thread serialises its
// own copy of the request headers, which this code cannot reach to wipe.
//
// call_long (scantxoutset "start") polls the cancel check every 100 ms; on a
// cancel it runs the caller's on_cancel (SourceDashd sends scantxoutset
// "abort" through call(), a second request on this transport) and waits for
// the start to return, as dashd then does at once. The long timeout is a
// backstop for a dashd that never answers.
//
// A QCoreApplication must exist; one instance per thread (the GUI creates it
// inside its worker thread).

#include "RpcApi.hpp"

#include <cstdint>
#include <memory>
#include <string>

class QNetworkAccessManager;

namespace c2w::companion::scan {

class QtRpcApi : public RpcApi {
public:
    static constexpr int kDefaultTimeoutMs = 30000;
    static constexpr int kLongTimeoutMs = 30 * 60 * 1000;
    static constexpr int64_t kMaxReplyBytes = 256LL * 1024 * 1024;

    // nullptr + why when `url` is not a loopback http URL or the credentials
    // file is not usable now (it is read again at every request).
    static std::unique_ptr<QtRpcApi> create(const std::string& url, const std::string& auth_file, std::string& why,
                                            int timeout_ms = kDefaultTimeoutMs, int long_timeout_ms = kLongTimeoutMs);
    ~QtRpcApi() override;

    RpcReply call(const std::string& method, const std::string& params_json) override;
    RpcReply call_long(const std::string& method, const std::string& params_json, const CancelCheck& cancelled,
                       const std::function<void()>& on_cancel) override;
    const char* name() const override { return name_.c_str(); }

private:
    QtRpcApi(std::string base, std::string auth_file, int timeout_ms, int long_timeout_ms);
    RpcReply request(const std::string& method, const std::string& params_json, const CancelCheck* cancelled,
                     const std::function<void()>* on_cancel, int timeout_ms);

    std::string base_;
    std::string auth_file_;
    std::string name_;
    int timeout_ms_;
    int long_timeout_ms_;
    int64_t next_id_ = 1;
    std::unique_ptr<QNetworkAccessManager> nam_;
};

} // namespace c2w::companion::scan
