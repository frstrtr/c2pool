// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Descriptor.hpp"

#include "Address.hpp"
#include "HexUtil.hpp"
#include "KeyImport.hpp"
#include "Secp.hpp"

#include <btclibs/base58.h>
#include <btclibs/crypto/sha256.h>

#include <algorithm>
#include <cctype>

namespace c2w::hdkeys {

const char* to_string(DescType t)
{
    switch (t) {
        case DescType::P2PKH: return "pkh";
        case DescType::P2WPKH: return "wpkh";
        case DescType::P2SH_P2WPKH: return "sh(wpkh)";
        case DescType::P2TR: return "tr";
        case DescType::WSH_MULTI: return "wsh(multi)";
        case DescType::SH_WSH_MULTI: return "sh(wsh(multi))";
        case DescType::SH_MULTI: return "sh(multi)";
        case DescType::BARE_MULTI: return "multi";
        case DescType::COMBO: return "combo";
        default: return "unknown";
    }
}

// ── Core descriptor checksum (bitcoin/src/script/descriptor.cpp) ────────────
namespace {

const std::string kInputCharset =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const std::string kChecksumCharset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

uint64_t poly_mod(uint64_t c, int val)
{
    uint8_t c0 = c >> 35;
    c = ((c & 0x7ffffffffULL) << 5) ^ val;
    if (c0 & 1) c ^= 0xf5dee51989ULL;
    if (c0 & 2) c ^= 0xa9fdca3312ULL;
    if (c0 & 4) c ^= 0x1bab10e32dULL;
    if (c0 & 8) c ^= 0x3706b1677aULL;
    if (c0 & 16) c ^= 0x644d626ffdULL;
    return c;
}

} // namespace

std::string descriptor_checksum(const std::string& payload)
{
    uint64_t c = 1;
    int cls = 0, clscount = 0;
    for (char ch : payload) {
        auto pos = kInputCharset.find(ch);
        if (pos == std::string::npos) return "";
        c = poly_mod(c, pos & 31);
        cls = cls * 3 + static_cast<int>(pos >> 5);
        if (++clscount == 3) { c = poly_mod(c, cls); cls = 0; clscount = 0; }
    }
    if (clscount > 0) c = poly_mod(c, cls);
    for (int j = 0; j < 8; ++j) c = poly_mod(c, 0);
    c ^= 1;
    std::string ret(8, ' ');
    for (int j = 0; j < 8; ++j) ret[j] = kChecksumCharset[(c >> (5 * (7 - j))) & 31];
    return ret;
}

// ── parsing helpers ─────────────────────────────────────────────────────────
namespace {

bool split_func(const std::string& s, std::string& name, std::string& inner)
{
    auto lp = s.find('(');
    if (lp == std::string::npos || s.back() != ')') return false;
    name = s.substr(0, lp);
    inner = s.substr(lp + 1, s.size() - lp - 2);
    return true;
}

// Split by top-level commas (ignoring commas inside [], (), <>).
std::vector<std::string> split_top_commas(const std::string& s)
{
    std::vector<std::string> out;
    int depth = 0;
    std::string cur;
    for (char ch : s) {
        if (ch == '(' || ch == '[' || ch == '<') ++depth;
        else if (ch == ')' || ch == ']' || ch == '>') --depth;
        if (ch == ',' && depth == 0) { out.push_back(cur); cur.clear(); }
        else cur += ch;
    }
    out.push_back(cur);
    return out;
}

bool parse_index_token(std::string tok, uint32_t& out)
{
    bool hardened = false;
    if (!tok.empty() && (tok.back() == '\'' || tok.back() == 'h' || tok.back() == 'H')) {
        hardened = true; tok.pop_back();
    }
    if (tok.empty()) return false;
    uint64_t v = 0;
    for (char c : tok) { if (!std::isdigit((unsigned char)c)) return false; v = v * 10 + (c - '0'); if (v > 0x7fffffffULL) return false; }
    out = static_cast<uint32_t>(v) | (hardened ? kHardened : 0u);
    return true;
}

// Parse a single key expression: [origin]KEY[/steps.../*]
bool parse_key(const std::string& str, DescKey& k, std::string& err)
{
    k.raw = str;
    std::string body = str;
    if (!body.empty() && body[0] == '[') {
        auto rb = body.find(']');
        if (rb == std::string::npos) { err = "unterminated key origin ['"; return false; }
        std::string origin = body.substr(1, rb - 1);
        body = body.substr(rb + 1);
        // origin = fingerprint[/step]...
        std::vector<std::string> parts;
        std::string cur;
        for (char c : origin) { if (c == '/') { parts.push_back(cur); cur.clear(); } else cur += c; }
        parts.push_back(cur);
        if (parts.empty() || parts[0].size() != 8) { err = "bad key-origin fingerprint"; return false; }
        k.origin_fingerprint = parts[0];
        for (size_t i = 1; i < parts.size(); ++i) {
            uint32_t idx;
            if (!parse_index_token(parts[i], idx)) { err = "bad origin path step"; return false; }
            k.origin_path.push_back(idx);
        }
    }
    // Split key from its trailing derivation at the first '/'.
    std::string keypart = body, derivstr;
    auto slash = body.find('/');
    if (slash != std::string::npos) { keypart = body.substr(0, slash); derivstr = body.substr(slash + 1); }

    // Classify the key material.
    if (auto node = HDKey::parse(keypart)) {
        k.has_extended = true;
        k.node = std::move(node);
    } else if (auto wif = decode_wif(keypart); wif.ok) {
        k.scalar = wif.scalar.copy();
    } else if (auto hx = from_hex(keypart); hx && (hx->size() == 33 || hx->size() == 65)) {
        k.fixed_pubkey = *hx;
    } else {
        err = "unrecognised key: " + keypart;
        return false;
    }

    // Parse derivation steps.
    if (!derivstr.empty()) {
        std::vector<std::string> steps;
        std::string cur;
        for (char c : derivstr) { if (c == '/') { steps.push_back(cur); cur.clear(); } else cur += c; }
        steps.push_back(cur);
        for (auto& st : steps) {
            if (st == "*" || st == "*'" || st == "*h") {
                k.wildcard_step = static_cast<int>(k.derivation.size());
                k.derivation.push_back(0);   // placeholder; filled at derive time
            } else if (!st.empty() && st.front() == '<' && st.back() == '>') {
                // multipath <a;b;...> — take the first option (documented v1 limit).
                std::string first = st.substr(1, st.find(';') == std::string::npos
                                                    ? st.size() - 2 : st.find(';') - 1);
                uint32_t idx;
                if (!parse_index_token(first, idx)) { err = "bad multipath step"; return false; }
                k.derivation.push_back(idx);
            } else {
                uint32_t idx;
                if (!parse_index_token(st, idx)) { err = "bad derivation step: " + st; return false; }
                k.derivation.push_back(idx);
            }
        }
    }
    if ((k.fixed_pubkey.size() || !k.scalar.empty()) && k.wildcard_step >= 0) {
        err = "range wildcard requires an extended key";
        return false;
    }
    return true;
}

bool parse_multi(const std::string& inner, Descriptor& d, std::string& err)
{
    auto parts = split_top_commas(inner);
    if (parts.size() < 2) { err = "multi() needs threshold + keys"; return false; }
    uint32_t th = 0;
    if (!parse_index_token(parts[0], th) || (th & kHardened)) { err = "bad multi threshold"; return false; }
    d.threshold = static_cast<int>(th);
    for (size_t i = 1; i < parts.size(); ++i) {
        DescKey k;
        if (!parse_key(parts[i], k, err)) return false;
        d.keys.push_back(std::move(k));
    }
    if (d.threshold < 1 || d.threshold > (int)d.keys.size()) { err = "threshold out of range"; return false; }
    return true;
}

} // namespace

DescriptorParse parse_descriptor(const std::string& text)
{
    DescriptorParse r;
    // Trim whitespace.
    std::string s;
    for (char c : text) if (!std::isspace((unsigned char)c)) s += c;
    if (s.empty()) { r.error = "empty descriptor"; return r; }

    // Split off checksum.
    std::string payload = s;
    auto hash = s.find('#');
    if (hash != std::string::npos) {
        r.desc.has_checksum = true;
        r.desc.checksum = s.substr(hash + 1);
        payload = s.substr(0, hash);
        r.desc.checksum_valid = (descriptor_checksum(payload) == r.desc.checksum);
        if (!r.desc.checksum_valid) { r.error = "descriptor checksum mismatch"; return r; }
    }

    std::string name, inner;
    if (!split_func(payload, name, inner)) { r.error = "malformed descriptor (no function)"; return r; }

    auto& d = r.desc;
    if (name == "pkh" || name == "wpkh" || name == "tr" || name == "combo") {
        if (name == "tr" && split_top_commas(inner).size() > 1) {
            r.error = "tr() script paths are not supported in v1 (key-path only)"; return r;
        }
        DescKey k;
        if (!parse_key(inner, k, r.error)) return r;
        d.keys.push_back(std::move(k));
        d.type = name == "pkh" ? DescType::P2PKH : name == "wpkh" ? DescType::P2WPKH
               : name == "tr" ? DescType::P2TR : DescType::COMBO;
    } else if (name == "multi" || name == "sortedmulti") {
        d.type = DescType::BARE_MULTI;
        d.sorted = (name == "sortedmulti");
        if (!parse_multi(inner, d, r.error)) return r;
    } else if (name == "sh") {
        std::string in2, inner2;
        if (!split_func(inner, in2, inner2)) { r.error = "malformed sh() body"; return r; }
        if (in2 == "wpkh") {
            DescKey k;
            if (!parse_key(inner2, k, r.error)) return r;
            d.keys.push_back(std::move(k));
            d.type = DescType::P2SH_P2WPKH;
        } else if (in2 == "wsh") {
            std::string in3, inner3;
            if (!split_func(inner2, in3, inner3) || (in3 != "multi" && in3 != "sortedmulti")) {
                r.error = "sh(wsh(...)) only supports multi/sortedmulti in v1"; return r;
            }
            d.type = DescType::SH_WSH_MULTI;
            d.sorted = (in3 == "sortedmulti");
            if (!parse_multi(inner3, d, r.error)) return r;
        } else if (in2 == "multi" || in2 == "sortedmulti") {
            d.type = DescType::SH_MULTI;
            d.sorted = (in2 == "sortedmulti");
            if (!parse_multi(inner2, d, r.error)) return r;
        } else {
            r.error = "unsupported sh() inner: " + in2; return r;
        }
    } else if (name == "wsh") {
        std::string in2, inner2;
        if (!split_func(inner, in2, inner2) || (in2 != "multi" && in2 != "sortedmulti")) {
            r.error = "wsh(...) only supports multi/sortedmulti in v1"; return r;
        }
        d.type = DescType::WSH_MULTI;
        d.sorted = (in2 == "sortedmulti");
        if (!parse_multi(inner2, d, r.error)) return r;
    } else {
        r.error = "unsupported descriptor function: " + name; return r;
    }

    r.ok = true;
    return r;
}

// ── derivation ───────────────────────────────────────────────────────────────
namespace {

std::vector<uint8_t> resolve_pubkey(const DescKey& k, uint32_t index, std::string& err)
{
    if (k.has_extended) {
        HDKey node = *k.node;
        for (size_t i = 0; i < k.derivation.size(); ++i) {
            uint32_t val = ((int)i == k.wildcard_step) ? index : k.derivation[i];
            auto child = node.derive_child(val);
            if (!child) { err = "descriptor derivation failed (hardened from xpub, or invalid child)"; return {}; }
            node = std::move(*child);
        }
        return node.pubkey();  // 33-byte compressed
    }
    if (!k.fixed_pubkey.empty()) return k.fixed_pubkey;
    if (!k.scalar.empty()) return Secp::instance().pubkey_create(k.scalar.data(), true);
    err = "empty key expression";
    return {};
}

void push_data(std::vector<uint8_t>& s, const std::vector<uint8_t>& d)
{
    s.push_back(static_cast<uint8_t>(d.size()));  // pubkeys are 33/65 => single-byte push
    s.insert(s.end(), d.begin(), d.end());
}

std::array<uint8_t, 20> hash160_local(const std::vector<uint8_t>& v)
{
    return hash160(v.data(), v.size());
}

std::vector<uint8_t> sha256_of(const std::vector<uint8_t>& v)
{
    std::vector<uint8_t> out(32);
    CSHA256().Write(v.data(), v.size()).Finalize(out.data());
    return out;
}

// Build the m-of-n CHECKMULTISIG script for the given (already sorted) pubkeys.
std::vector<uint8_t> multisig_script(int m, std::vector<std::vector<uint8_t>> pubs, bool sorted)
{
    if (sorted) std::sort(pubs.begin(), pubs.end());
    std::vector<uint8_t> s;
    s.push_back(static_cast<uint8_t>(0x50 + m));
    for (auto& p : pubs) push_data(s, p);
    s.push_back(static_cast<uint8_t>(0x50 + (int)pubs.size()));
    s.push_back(0xae);  // OP_CHECKMULTISIG
    return s;
}

} // namespace

std::vector<DerivedAddress> derive_descriptor(const Descriptor& d, const CoinParams& coin,
                                              uint32_t lo, uint32_t hi, std::string& error)
{
    std::vector<DerivedAddress> out;
    bool ranged = false;
    for (const auto& k : d.keys) if (k.wildcard_step >= 0) ranged = true;
    if (!ranged) hi = lo;  // single address

    auto& secp = Secp::instance();

    for (uint32_t idx = lo; idx <= hi; ++idx) {
        if (d.type == DescType::BARE_MULTI || d.type == DescType::SH_MULTI ||
            d.type == DescType::WSH_MULTI || d.type == DescType::SH_WSH_MULTI) {
            std::vector<std::vector<uint8_t>> pubs;
            for (const auto& k : d.keys) {
                auto p = resolve_pubkey(k, idx, error);
                if (p.size() != 33 && p.size() != 65) { if (error.empty()) error = "bad multisig pubkey"; return {}; }
                pubs.push_back(std::move(p));
            }
            auto script = multisig_script(d.threshold, pubs, d.sorted);
            DerivedAddress da; da.index = idx;
            if (d.type == DescType::BARE_MULTI) {
                da.script_hex = to_hex(script);            // bare multisig has no address
            } else if (d.type == DescType::SH_MULTI) {
                auto h = hash160_local(script);
                da.address = encode_p2sh(coin.p2sh_version, h);
                std::vector<uint8_t> spk = {0xa9, 0x14}; spk.insert(spk.end(), h.begin(), h.end()); spk.push_back(0x87);
                da.script_hex = to_hex(spk);
                da.detail = "redeemScript=" + to_hex(script);
            } else if (d.type == DescType::WSH_MULTI) {
                if (!(coin.bech32_hrp && coin.bech32_hrp[0])) { error = "coin has no segwit for wsh()"; return {}; }
                auto wp = sha256_of(script);
                da.address = encode_segwit_v(coin.bech32_hrp, 0, wp, /*bech32m=*/false);
                std::vector<uint8_t> spk = {0x00, 0x20}; spk.insert(spk.end(), wp.begin(), wp.end());
                da.script_hex = to_hex(spk);
                da.detail = "witnessScript=" + to_hex(script);
            } else { // SH_WSH_MULTI
                if (!(coin.bech32_hrp && coin.bech32_hrp[0])) { error = "coin has no segwit for sh(wsh())"; return {}; }
                auto wp = sha256_of(script);
                std::vector<uint8_t> redeem = {0x00, 0x20}; redeem.insert(redeem.end(), wp.begin(), wp.end());
                auto h = hash160_local(redeem);
                da.address = encode_p2sh(coin.p2sh_version, h);
                std::vector<uint8_t> spk = {0xa9, 0x14}; spk.insert(spk.end(), h.begin(), h.end()); spk.push_back(0x87);
                da.script_hex = to_hex(spk);
                da.detail = "witnessScript=" + to_hex(script);
            }
            out.push_back(std::move(da));
            continue;
        }

        // Single-key script types (+ combo): reuse the M1-A address candidates.
        auto pub = resolve_pubkey(d.keys[0], idx, error);
        if (pub.size() != 33 && pub.size() != 65) { if (error.empty()) error = "bad pubkey"; return {}; }
        auto cands = address_candidates(pub, coin);

        auto emit = [&](const char* label) {
            for (const auto& c : cands) {
                if (c.label == label && (c.encoding == "compressed" || c.encoding == "x-only")) {
                    out.push_back({idx, c.address, c.script_hex, ""});
                    return true;
                }
            }
            return false;
        };
        bool ok = true;
        switch (d.type) {
            case DescType::P2PKH: ok = emit("P2PKH"); break;
            case DescType::P2WPKH: ok = emit("P2WPKH"); break;
            case DescType::P2SH_P2WPKH: ok = emit("P2SH-P2WPKH"); break;
            case DescType::P2TR: ok = emit("P2TR"); break;
            case DescType::COMBO:
                emit("P2PKH"); emit("P2WPKH"); emit("P2SH-P2WPKH"); break;
            default: ok = false; break;
        }
        if (!ok && d.type != DescType::COMBO) {
            error = std::string("script type ") + to_string(d.type) + " not available for this coin";
            return {};
        }
        (void)secp;
    }
    return out;
}

} // namespace c2w::hdkeys
