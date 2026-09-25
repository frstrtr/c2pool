// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// c2wallet-qt COMPANION — the §5.4 validate_inject DRY-RUN client (request side)
// + the digest cross-check display.
//
// Design §5.4 recommends a `validate_inject` dry-run (a testmempoolaccept
// analog: validate WITHOUT admit) so the wallet can pre-flight BEFORE the
// operator signs. It is TAP-FREE / read-only (§5.5). This module implements the
// CLIENT: build the {op:validate, dry_run:true, coin, tx_hex} request, parse the
// {ok, cause, txid} response, and cross-check the response txid against the
// locally computed cross-gap sha256d digest.
//
// The actual online node endpoint (NodeCoinState::submit_inject) is CROSS-LANE
// — left as a clearly-named seam via the NodeTransport interface. The default
// UnwiredTransport performs NO I/O (the file/QR artifact is the real seam);
// LoopbackHttpTransport is an armed-flag-gated, loopback-only STUB for the
// online lane to wire when the endpoint lands on master. NO keys.

#include "ValidateSeam.hpp" // c2w::artifact::SeamRequest / SeamResponse

#include <memory>
#include <optional>
#include <string>

namespace c2w::companion {

// The online node transport — a NAMED SEAM. Implementations marshal the JSON
// request out and a JSON response back.
struct NodeTransport {
    virtual ~NodeTransport() = default;
    // Return true and fill `response_json` on a delivered response; false + err
    // otherwise. Even on false the caller still computes the local digest.
    virtual bool send(const std::string& request_json,
                      std::string& response_json, std::string& err) = 0;
    virtual const char* name() const = 0;
};

// Default: the M5-A UnwiredOnlineSeam. Performs NO I/O — the companion works
// with no live node. Echoes ok=false, cause="seam-unwired-cross-lane",
// txid=<cross-gap digest of the request tx>.
struct UnwiredTransport : NodeTransport {
    bool send(const std::string& request_json,
              std::string& response_json, std::string& err) override;
    const char* name() const override { return "unwired-cross-lane"; }
};

// Loopback HTTP transport STUB. The real POST to the online node is a
// cross-lane, money-adjacent seam; `armed` defaults OFF (money-path discipline
// §5.5) and even when armed this stub performs NO real I/O — it refuses with a
// named cause. The online lane wires the actual loopback QNetwork call here
// when the node's validate_inject endpoint lands on master.
struct LoopbackHttpTransport : NodeTransport {
    bool        armed = false; // default DISARMED
    std::string url   = "http://127.0.0.1:8080/validate_inject"; // loopback only
    bool send(const std::string& request_json,
              std::string& response_json, std::string& err) override;
    const char* name() const override { return "loopback-http-stub"; }
};

// The result of a dry-run pre-flight, including the cross-gap digest check.
struct ValidateResult {
    bool                                       transport_ok = false; // parseable response
    std::optional<c2w::artifact::SeamResponse> response;
    std::string                                local_txid;   // digest WE computed
    bool                                       digest_match = false; // response.txid == local
    std::string                                display;      // human-readable cross-check
    std::string                                error;
};

class ValidateInjectClient {
public:
    explicit ValidateInjectClient(std::shared_ptr<NodeTransport> transport);

    // §5.4 dry-run: {op:validate, dry_run:true, coin, tx_hex} -> {ok,cause,txid}.
    // Read-only / tap-free. Cross-checks the response txid against the locally
    // computed cross-gap sha256d digest and renders `display`.
    ValidateResult validate_dry_run(const std::string& coin, const std::string& tx_hex);

    const NodeTransport& transport() const { return *transport_; }

private:
    std::shared_ptr<NodeTransport> transport_;
};

} // namespace c2w::companion
