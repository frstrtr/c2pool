// SPDX-License-Identifier: AGPL-3.0-or-later
#include "FundingData.hpp"

#include <cctype>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace c2w::companion {

// ─────────────────────────────────────────────────────────────────────────
// Minimal, dependency-free JSON parser (this tree does not vendor nlohmann).
// Supports the object/array/string/number/bool/null shapes the funding schema
// uses. Numbers keep their raw token so int64 satoshi amounts never round-trip
// through a double.
// ─────────────────────────────────────────────────────────────────────────
namespace {

struct JVal {
    enum Type { Null, Bool, Num, Str, Arr, Obj } type = Null;
    bool                       b = false;
    std::string                num;  // raw numeric token
    std::string                str;
    std::vector<JVal>          arr;
    std::map<std::string, JVal> obj;

    const JVal* find(const std::string& k) const {
        auto it = obj.find(k);
        return it == obj.end() ? nullptr : &it->second;
    }
};

struct JParser {
    const std::string& s;
    size_t p = 0;
    std::string err;

    explicit JParser(const std::string& in) : s(in) {}

    void skip_ws() {
        while (p < s.size() && std::isspace(static_cast<unsigned char>(s[p]))) ++p;
    }

    bool fail(const std::string& m) { if (err.empty()) err = m; return false; }

    bool parse_string(std::string& out) {
        if (p >= s.size() || s[p] != '"') return fail("expected string");
        ++p;
        out.clear();
        while (p < s.size() && s[p] != '"') {
            char c = s[p];
            if (c == '\\' && p + 1 < s.size()) {
                char n = s[p + 1];
                switch (n) {
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case '"': out += '"';  break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    default:  out += n;   break;
                }
                p += 2;
            } else {
                out += c;
                ++p;
            }
        }
        if (p >= s.size()) return fail("unterminated string");
        ++p; // closing quote
        return true;
    }

    bool parse_value(JVal& v) {
        skip_ws();
        if (p >= s.size()) return fail("unexpected end");
        char c = s[p];
        if (c == '"') { v.type = JVal::Str; return parse_string(v.str); }
        if (c == '{') return parse_object(v);
        if (c == '[') return parse_array(v);
        if (c == 't' || c == 'f') {
            if (s.compare(p, 4, "true") == 0)  { v.type = JVal::Bool; v.b = true;  p += 4; return true; }
            if (s.compare(p, 5, "false") == 0) { v.type = JVal::Bool; v.b = false; p += 5; return true; }
            return fail("bad literal");
        }
        if (c == 'n') {
            if (s.compare(p, 4, "null") == 0) { v.type = JVal::Null; p += 4; return true; }
            return fail("bad literal");
        }
        // number
        size_t start = p;
        if (s[p] == '-' || s[p] == '+') ++p;
        while (p < s.size() && (std::isdigit(static_cast<unsigned char>(s[p])) ||
                                s[p] == '.' || s[p] == 'e' || s[p] == 'E' ||
                                s[p] == '-' || s[p] == '+')) ++p;
        if (p == start) return fail("bad value");
        v.type = JVal::Num;
        v.num = s.substr(start, p - start);
        return true;
    }

    bool parse_array(JVal& v) {
        v.type = JVal::Arr;
        ++p; // '['
        skip_ws();
        if (p < s.size() && s[p] == ']') { ++p; return true; }
        while (true) {
            JVal e;
            if (!parse_value(e)) return false;
            v.arr.push_back(std::move(e));
            skip_ws();
            if (p >= s.size()) return fail("unterminated array");
            if (s[p] == ',') { ++p; continue; }
            if (s[p] == ']') { ++p; return true; }
            return fail("expected , or ] in array");
        }
    }

    bool parse_object(JVal& v) {
        v.type = JVal::Obj;
        ++p; // '{'
        skip_ws();
        if (p < s.size() && s[p] == '}') { ++p; return true; }
        while (true) {
            skip_ws();
            std::string key;
            if (!parse_string(key)) return false;
            skip_ws();
            if (p >= s.size() || s[p] != ':') return fail("expected :");
            ++p;
            JVal val;
            if (!parse_value(val)) return false;
            v.obj[key] = std::move(val);
            skip_ws();
            if (p >= s.size()) return fail("unterminated object");
            if (s[p] == ',') { ++p; continue; }
            if (s[p] == '}') { ++p; return true; }
            return fail("expected , or } in object");
        }
    }
};

bool str_field(const JVal& o, const std::string& k, std::string& out) {
    const JVal* v = o.find(k);
    if (!v || v->type != JVal::Str) return false;
    out = v->str;
    return true;
}

// Accepts either a JSON number or a quoted numeric string.
bool int_field(const JVal& o, const std::string& k, long long& out) {
    const JVal* v = o.find(k);
    if (!v) return false;
    const std::string* tok = nullptr;
    if (v->type == JVal::Num) tok = &v->num;
    else if (v->type == JVal::Str) tok = &v->str;
    else return false;
    try { out = std::stoll(*tok); } catch (...) { return false; }
    return true;
}

} // namespace

std::optional<FundingData> FundingData::from_json(const std::string& s, std::string& err) {
    err.clear();
    JParser jp(s);
    JVal root;
    if (!jp.parse_value(root) || root.type != JVal::Obj) {
        err = jp.err.empty() ? "root is not a JSON object" : jp.err;
        return std::nullopt;
    }

    FundingData fd;
    if (!str_field(root, "coin", fd.coin)) { err = "missing/!string coin"; return std::nullopt; }

    long long n = 0;
    if (int_field(root, "network_version", n)) fd.network_version = static_cast<uint32_t>(n);
    if (int_field(root, "tx_version", n))      fd.tx_version = static_cast<int32_t>(n);
    if (int_field(root, "locktime", n))        fd.locktime = static_cast<uint32_t>(n);
    str_field(root, "preflight_verdict", fd.preflight_verdict);

    std::string alg;
    if (str_field(root, "algebra", alg)) {
        if (alg == "legacy")      fd.algebra = SighashAlgebra::Legacy;
        else if (alg == "bip143") fd.algebra = SighashAlgebra::Bip143;
        else if (alg == "bip341") fd.algebra = SighashAlgebra::Bip341;
        else { err = "unknown algebra: " + alg; return std::nullopt; }
    }

    const JVal* ins = root.find("inputs");
    if (!ins || ins->type != JVal::Arr || ins->arr.empty()) {
        err = "missing/empty inputs array"; return std::nullopt;
    }
    for (const JVal& e : ins->arr) {
        if (e.type != JVal::Obj) { err = "input is not an object"; return std::nullopt; }
        FundingInput in;

        std::string txid_disp;
        if (!str_field(e, "txid", txid_disp)) { err = "input missing txid"; return std::nullopt; }
        auto raw = c2w::artifact::from_hex(txid_disp);
        if (!raw || raw->size() != 32) { err = "input txid not 32-byte hex"; return std::nullopt; }
        // DISPLAY -> INTERNAL: byte-reverse.
        for (size_t i = 0; i < 32; ++i) in.prevout_txid[i] = (*raw)[31 - i];

        if (!int_field(e, "vout", n)) { err = "input missing vout"; return std::nullopt; }
        in.prevout_index = static_cast<uint32_t>(n);

        std::string spk_hex;
        if (!str_field(e, "script_pubkey", spk_hex)) { err = "input missing script_pubkey"; return std::nullopt; }
        auto spk = c2w::artifact::from_hex(spk_hex);
        if (!spk) { err = "input script_pubkey not valid hex"; return std::nullopt; }
        in.script_pubkey = std::move(*spk);

        if (!int_field(e, "amount", n)) { err = "input missing amount"; return std::nullopt; }
        in.amount = static_cast<int64_t>(n);

        str_field(e, "derivation", in.derivation_hint);
        if (int_field(e, "sequence", n)) in.sequence = static_cast<uint32_t>(n);

        fd.inputs.push_back(std::move(in));
    }

    const JVal* outs = root.find("outputs");
    if (!outs || outs->type != JVal::Arr || outs->arr.empty()) {
        err = "missing/empty outputs array"; return std::nullopt;
    }
    for (const JVal& e : outs->arr) {
        if (e.type != JVal::Obj) { err = "output is not an object"; return std::nullopt; }
        TargetOutput o;
        if (!int_field(e, "amount", n)) { err = "output missing amount"; return std::nullopt; }
        o.value = static_cast<int64_t>(n);
        std::string spk_hex;
        if (!str_field(e, "script_pubkey", spk_hex)) { err = "output missing script_pubkey"; return std::nullopt; }
        auto spk = c2w::artifact::from_hex(spk_hex);
        if (!spk) { err = "output script_pubkey not valid hex"; return std::nullopt; }
        o.script_pubkey = std::move(*spk);
        fd.outputs.push_back(std::move(o));
    }

    return fd;
}

// ─────────────────────────────────────────────────────────────────────────
// Legacy unsigned-tx serialization (no keys).
// ─────────────────────────────────────────────────────────────────────────
namespace {

void put_u32_le(Bytes& b, uint32_t v) {
    b.push_back(static_cast<uint8_t>(v & 0xff));
    b.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    b.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    b.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}

void put_i32_le(Bytes& b, int32_t v) { put_u32_le(b, static_cast<uint32_t>(v)); }

void put_i64_le(Bytes& b, int64_t v) {
    uint64_t u = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>((u >> (8 * i)) & 0xff));
}

// Bitcoin CompactSize / varint.
void put_varint(Bytes& b, uint64_t n) {
    if (n < 0xfd) {
        b.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffff) {
        b.push_back(0xfd);
        b.push_back(static_cast<uint8_t>(n & 0xff));
        b.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
    } else if (n <= 0xffffffffULL) {
        b.push_back(0xfe);
        put_u32_le(b, static_cast<uint32_t>(n));
    } else {
        b.push_back(0xff);
        for (int i = 0; i < 8; ++i) b.push_back(static_cast<uint8_t>((n >> (8 * i)) & 0xff));
    }
}

} // namespace

Bytes serialize_unsigned_tx(const FundingData& fd) {
    Bytes b;
    put_i32_le(b, fd.tx_version);

    put_varint(b, fd.inputs.size());
    for (const auto& in : fd.inputs) {
        b.insert(b.end(), in.prevout_txid.begin(), in.prevout_txid.end()); // 32 internal
        put_u32_le(b, in.prevout_index);
        put_varint(b, 0); // empty scriptSig (unsigned)
        put_u32_le(b, in.sequence);
    }

    put_varint(b, fd.outputs.size());
    for (const auto& o : fd.outputs) {
        put_i64_le(b, o.value);
        put_varint(b, o.script_pubkey.size());
        b.insert(b.end(), o.script_pubkey.begin(), o.script_pubkey.end());
    }

    put_u32_le(b, fd.locktime);
    return b;
}

} // namespace c2w::companion
