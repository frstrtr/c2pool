// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Diagnostic classifier for the p2p `bestblock` origination fetch path
// (issue #1046: bestblock in=5977 / out=0 on soak ddbd81ef7).
//
// The `announce_bestblock` lambda in src/c2pool/main_dash.cpp fetches the tip
// header via `getblockheader(tip, verbose=false)` and then broadcasts it. Two
// silent `return`s on that fetch path each yield out=0, and pre-#1046 they were
// indistinguishable in the log. This pure classifier maps the RPC result to one
// of three outcomes so the caller can emit one distinguishable message per case.
// It performs NO I/O and NO logging by design, so it is unit-testable against the
// real nlohmann::json type (see test_dash_poolnode_messages.cpp).
#pragma once

#include <string>
#include <nlohmann/json.hpp>

namespace dash {
namespace coin {

enum class BestblockFetch {
    Ok,            // r is a string of exactly 160 hex chars (an 80-byte header)
    RpcNotString,  // getblockheader(verbose=false) did not return a JSON string
    BadHexLen,     // r is a string, but not 160 chars (empty / truncated / padded)
};

// Classify the getblockheader RPC result. On Ok, `hdr_hex_out` holds the header
// hex; on BadHexLen it holds whatever string was returned (possibly empty) so the
// caller can log its length; on RpcNotString it is left empty.
inline BestblockFetch classify_bestblock_header(const nlohmann::json& r,
                                                std::string& hdr_hex_out)
{
    hdr_hex_out.clear();
    if (!r.is_string())
        return BestblockFetch::RpcNotString;
    hdr_hex_out = r.get<std::string>();
    if (hdr_hex_out.size() != 160)
        return BestblockFetch::BadHexLen;
    return BestblockFetch::Ok;
}

inline const char* bestblock_fetch_name(BestblockFetch c)
{
    switch (c) {
        case BestblockFetch::Ok:           return "Ok";
        case BestblockFetch::RpcNotString: return "RpcNotString";
        case BestblockFetch::BadHexLen:    return "BadHexLen";
    }
    return "Unknown";
}

} // namespace coin
} // namespace dash
