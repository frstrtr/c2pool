// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ValidateSeam.hpp"
#include "Digest.hpp"

#include <cctype>
#include <cstdint>

namespace c2w::artifact {

// ── minimal flat-JSON emit/scan (the contract is a flat object of string /
//    number / bool values; no nesting) ────────────────────────────────────

static std::string json_escape(const std::string& s) {
    std::string o;
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:   o += c;      break;
        }
    }
    return o;
}

// Extract the raw value token for "key" from a flat JSON object. Returns false
// if the key is absent. `is_string` reports whether the value was quoted; the
// returned value has quotes stripped + escapes decoded for strings.
static bool json_field(const std::string& s, const std::string& key,
                       std::string& value, bool& is_string) {
    const std::string needle = "\"" + key + "\"";
    size_t k = s.find(needle);
    if (k == std::string::npos) return false;
    size_t p = k + needle.size();
    // skip to ':'
    while (p < s.size() && s[p] != ':') ++p;
    if (p >= s.size()) return false;
    ++p;
    while (p < s.size() && std::isspace(static_cast<unsigned char>(s[p]))) ++p;
    if (p >= s.size()) return false;

    if (s[p] == '"') {
        ++p;
        is_string = true;
        value.clear();
        while (p < s.size() && s[p] != '"') {
            if (s[p] == '\\' && p + 1 < s.size()) {
                char n = s[p + 1];
                switch (n) {
                    case 'n': value += '\n'; break;
                    case 'r': value += '\r'; break;
                    case 't': value += '\t'; break;
                    case '"': value += '"';  break;
                    case '\\': value += '\\'; break;
                    default: value += n; break;
                }
                p += 2;
            } else {
                value += s[p++];
            }
        }
        return p < s.size(); // must have found the closing quote
    } else {
        is_string = false;
        value.clear();
        while (p < s.size() && s[p] != ',' && s[p] != '}' &&
               !std::isspace(static_cast<unsigned char>(s[p]))) {
            value += s[p++];
        }
        return !value.empty();
    }
}

std::string SeamRequest::to_json() const {
    std::string s = "{";
    s += "\"op\":\"";
    s += (op == SeamOp::Submit ? "submit" : "validate");
    s += "\",";
    s += "\"coin\":\"" + json_escape(coin) + "\",";
    s += "\"tx_hex\":\"" + json_escape(tx_hex) + "\",";
    s += "\"flags\":" + std::to_string(flags) + ",";
    s += "\"expiry_height\":" + std::to_string(expiry_height) + ",";
    s += "\"dry_run\":";
    s += (dry_run ? "true" : "false");
    s += "}";
    return s;
}

std::optional<SeamRequest> SeamRequest::from_json(const std::string& s, std::string& err) {
    err.clear();
    SeamRequest r;
    std::string v;
    bool is_str = false;

    if (!json_field(s, "op", v, is_str) || !is_str) { err = "missing op"; return std::nullopt; }
    if (v == "submit") r.op = SeamOp::Submit;
    else if (v == "validate") r.op = SeamOp::Validate;
    else { err = "unknown op"; return std::nullopt; }

    if (!json_field(s, "coin", r.coin, is_str) || !is_str) { err = "missing coin"; return std::nullopt; }
    if (!json_field(s, "tx_hex", r.tx_hex, is_str) || !is_str) { err = "missing tx_hex"; return std::nullopt; }

    if (json_field(s, "flags", v, is_str) && !is_str) {
        try { r.flags = static_cast<uint32_t>(std::stoul(v)); } catch (...) { err = "bad flags"; return std::nullopt; }
    }
    if (json_field(s, "expiry_height", v, is_str) && !is_str) {
        try { r.expiry_height = static_cast<int32_t>(std::stol(v)); } catch (...) { err = "bad expiry_height"; return std::nullopt; }
    }
    if (json_field(s, "dry_run", v, is_str) && !is_str) {
        r.dry_run = (v == "true");
    }
    return r;
}

SeamRequest SeamRequest::validate_inject(const std::string& coin, const std::string& tx_hex) {
    SeamRequest r;
    r.op = SeamOp::Validate;
    r.coin = coin;
    r.tx_hex = tx_hex;
    r.dry_run = true;
    return r;
}

std::string SeamResponse::to_json() const {
    std::string s = "{";
    s += "\"ok\":";
    s += (ok ? "true" : "false");
    s += ",";
    s += "\"cause\":\"" + json_escape(cause) + "\",";
    s += "\"txid\":\"" + json_escape(txid) + "\"";
    s += "}";
    return s;
}

std::optional<SeamResponse> SeamResponse::from_json(const std::string& s, std::string& err) {
    err.clear();
    SeamResponse r;
    std::string v;
    bool is_str = false;

    if (!json_field(s, "ok", v, is_str) || is_str) { err = "missing ok"; return std::nullopt; }
    r.ok = (v == "true");
    if (!json_field(s, "cause", r.cause, is_str) || !is_str) { err = "missing cause"; return std::nullopt; }
    if (!json_field(s, "txid", r.txid, is_str) || !is_str) { err = "missing txid"; return std::nullopt; }
    return r;
}

std::string crossgap_txid(const std::string& tx_hex) {
    auto raw = from_hex(tx_hex);
    if (!raw) return {};
    return sha256d_display(*raw);
}

SeamResponse UnwiredOnlineSeam::call(const SeamRequest& req) const {
    // NO I/O. The file/QR artifact is the seam; the online submit_inject call
    // is a separate lane. Still return the cross-gap digest so the operator can
    // compare it by hand.
    SeamResponse r;
    r.ok = false;
    r.cause = kUnwiredCause;
    r.txid = crossgap_txid(req.tx_hex);
    return r;
}

} // namespace c2w::artifact
