// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ValidateClient.hpp"

namespace c2w::companion {

bool UnwiredTransport::send(const std::string& request_json,
                            std::string& response_json, std::string& err) {
    err.clear();
    std::string perr;
    auto req = c2w::artifact::SeamRequest::from_json(request_json, perr);
    if (!req) { err = "bad request json: " + perr; return false; }
    // No I/O: the file/QR artifact is the real seam. The M5-A UnwiredOnlineSeam
    // returns a named cause and the cross-gap digest so the operator can still
    // compare by hand.
    c2w::artifact::UnwiredOnlineSeam seam;
    c2w::artifact::SeamResponse resp = seam.call(*req);
    response_json = resp.to_json();
    return true; // the (unwired) transport DID produce a response document
}

bool LoopbackHttpTransport::send(const std::string& /*request_json*/,
                                 std::string& /*response_json*/, std::string& err) {
    if (!armed) {
        err = "loopback-http-disarmed"; // money-path discipline: default OFF
        return false;
    }
    // Armed, but the online node's validate_inject endpoint is cross-lane and
    // not on master — this stub deliberately performs NO real I/O. The online
    // lane replaces this body with a loopback-only QNetworkAccessManager POST.
    err = "loopback-http-seam-unwired";
    return false;
}

ValidateInjectClient::ValidateInjectClient(std::shared_ptr<NodeTransport> transport)
    : transport_(std::move(transport)) {}

ValidateResult ValidateInjectClient::validate_dry_run(const std::string& coin,
                                                      const std::string& tx_hex) {
    ValidateResult r;
    // Local cross-gap digest: what WE compute from the tx bytes, independent of
    // the node's answer.
    r.local_txid = c2w::artifact::crossgap_txid(tx_hex);

    auto req = c2w::artifact::SeamRequest::validate_inject(coin, tx_hex);
    const std::string req_json = req.to_json();

    std::string resp_json, terr;
    if (!transport_->send(req_json, resp_json, terr)) {
        r.transport_ok = false;
        r.error = terr;
        r.display = std::string("validate_inject via [") + transport_->name() +
                    "]: NO RESPONSE (" + terr + "); local txid=" + r.local_txid;
        return r;
    }

    std::string perr;
    auto resp = c2w::artifact::SeamResponse::from_json(resp_json, perr);
    if (!resp) {
        r.transport_ok = false;
        r.error = "bad response json: " + perr;
        r.display = std::string("validate_inject via [") + transport_->name() +
                    "]: UNPARSEABLE RESPONSE; local txid=" + r.local_txid;
        return r;
    }

    r.transport_ok = true;
    r.response = *resp;
    r.digest_match = (!r.local_txid.empty() && resp->txid == r.local_txid);

    r.display = std::string("validate_inject via [") + transport_->name() + "]: ok=" +
                (resp->ok ? "true" : "false") + " cause=" + resp->cause +
                " node_txid=" + resp->txid + " local_txid=" + r.local_txid +
                " digest=" + (r.digest_match ? "MATCH" : "MISMATCH");
    return r;
}

} // namespace c2w::companion
