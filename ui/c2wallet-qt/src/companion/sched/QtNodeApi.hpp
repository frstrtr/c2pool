// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — the Qt Network implementation of the NodeApi seam
// (slice S2). It lives OUTSIDE the Qt-free c2wallet-companion library, in
// c2wallet-companion-qtnet, which only the companion GUI and the headless
// c2wallet-qt-schedd link; the signer never does (ci/check_no_network.sh).
//
// Each call runs one QNetworkAccessManager request to completion on a local
// QEventLoop (the scheduler core is synchronous by design), with:
//   * a loopback-only base URL (validate_node_url: http, 127.0.0.1 / [::1] /
//     localhost), so the node's is_direct_local() guard sees a direct peer;
//   * QNetworkProxy::NoProxy (no proxy environment variable is honoured);
//   * redirects never followed (ManualRedirectPolicy: a 3xx is returned as is);
//   * no HTTP/2, no cache, no cookies, no stored credentials;
//   * no custom headers: only Content-Type: application/json on a POST (the
//     node refuses X-Forwarded-* / Forwarded / X-Real-IP);
//   * a hard timeout per request (15 s default) and a reply size cap.
// transport_ok is true whenever an HTTP status arrived (4xx/5xx included, the
// body is kept for the outcome map); false on refused connections, timeouts
// and socket errors.
//
// The POST body may carry the control token. Our copy of it is wiped after a
// completed request (the caller wipes its own std::string); Qt's socket write
// buffer is outside our reach, the same exposure class as the kernel's
// loopback buffer, readable only by the token's owner or root.
//
// Shutdown: with a stop check installed (the daemon's SIGTERM flag), a request
// is not started once a stop was requested (transport error "runner
// stopping"), and an in-flight GET is aborted within 200 ms; an in-flight
// POST (submit, config apply) is left to finish within its timeout, so a
// stop never cuts a submit or a two-phase apply in half on our side.
//
// A QCoreApplication must exist in the process (the daemon's main creates
// one). Not thread-safe: one instance per thread.

#include "NodeApi.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

class QNetworkAccessManager;

namespace c2w::companion::sched {

class QtNodeApi : public NodeApi {
public:
    static constexpr int kDefaultTimeoutMs = 15000;
    static constexpr int64_t kMaxReplyBytes = 64LL * 1024 * 1024;

    // nullptr + why when `base_url` is not a loopback http URL.
    static std::unique_ptr<QtNodeApi> create(const std::string& base_url, std::string& why,
                                             int timeout_ms = kDefaultTimeoutMs);
    ~QtNodeApi() override;

    HttpReply get(const std::string& path) override;
    HttpReply post_json(const std::string& path, const std::string& body) override;
    const char* name() const override { return name_.c_str(); }

    void set_stop_check(std::function<bool()> fn) { stop_check_ = std::move(fn); }

private:
    QtNodeApi(std::string base, int timeout_ms);
    HttpReply request(bool post, const std::string& path, const std::string* body);

    std::string base_;
    std::string name_;
    int timeout_ms_;
    std::unique_ptr<QNetworkAccessManager> nam_;
    std::function<bool()> stop_check_;
};

} // namespace c2w::companion::sched
