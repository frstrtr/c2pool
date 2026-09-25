// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Keystore.hpp"

#include "Bip32.hpp"
#include "HexUtil.hpp"
#include "KeyImport.hpp"

#include <cctype>
#include <map>
#include <memory>

namespace c2w::hdkeys {

// ── minimal JSON parser (objects/arrays/strings/numbers/bool/null) ──────────
namespace {

struct JVal {
    enum class T { Null, Bool, Num, Str, Arr, Obj } t = T::Null;
    bool b = false;
    double num = 0;
    std::string str;
    std::vector<JVal> arr;
    std::vector<std::pair<std::string, JVal>> obj;   // preserve order; small docs
};

struct JParser {
    const std::string& s;
    size_t i = 0;
    bool err = false;
    explicit JParser(const std::string& src) : s(src) {}

    void skip() { while (i < s.size() && std::isspace((unsigned char)s[i])) ++i; }

    bool parse_string(std::string& out) {
        if (i >= s.size() || s[i] != '"') { err = true; return false; }
        ++i;
        while (i < s.size()) {
            char c = s[i++];
            if (c == '"') return true;
            if (c == '\\') {
                if (i >= s.size()) { err = true; return false; }
                char e = s[i++];
                switch (e) {
                    case '"': out += '"'; break;  case '\\': out += '\\'; break;
                    case '/': out += '/'; break;  case 'n': out += '\n'; break;
                    case 't': out += '\t'; break; case 'r': out += '\r'; break;
                    case 'b': out += '\b'; break; case 'f': out += '\f'; break;
                    case 'u': {
                        if (i + 4 > s.size()) { err = true; return false; }
                        // Keep it simple: only handle the ASCII subrange (wallet
                        // keystore keys/values are ASCII). Skip the 4 hex digits.
                        int code = 0;
                        for (int k = 0; k < 4; ++k) {
                            char h = s[i++]; code <<= 4;
                            if (h >= '0' && h <= '9') code |= h - '0';
                            else if (h >= 'a' && h <= 'f') code |= h - 'a' + 10;
                            else if (h >= 'A' && h <= 'F') code |= h - 'A' + 10;
                            else { err = true; return false; }
                        }
                        if (code < 0x80) out += static_cast<char>(code);
                        break;
                    }
                    default: err = true; return false;
                }
            } else out += c;
        }
        err = true;
        return false;
    }

    JVal parse() {
        skip();
        JVal v;
        if (i >= s.size()) { err = true; return v; }
        char c = s[i];
        if (c == '{') {
            ++i; v.t = JVal::T::Obj; skip();
            if (i < s.size() && s[i] == '}') { ++i; return v; }
            while (!err) {
                skip();
                std::string key;
                if (!parse_string(key)) { err = true; break; }
                skip();
                if (i >= s.size() || s[i] != ':') { err = true; break; }
                ++i;
                JVal val = parse();
                v.obj.emplace_back(key, std::move(val));
                skip();
                if (i < s.size() && s[i] == ',') { ++i; continue; }
                if (i < s.size() && s[i] == '}') { ++i; break; }
                err = true; break;
            }
        } else if (c == '[') {
            ++i; v.t = JVal::T::Arr; skip();
            if (i < s.size() && s[i] == ']') { ++i; return v; }
            while (!err) {
                v.arr.push_back(parse());
                skip();
                if (i < s.size() && s[i] == ',') { ++i; continue; }
                if (i < s.size() && s[i] == ']') { ++i; break; }
                err = true; break;
            }
        } else if (c == '"') {
            v.t = JVal::T::Str; parse_string(v.str);
        } else if (c == 't' || c == 'f') {
            if (s.compare(i, 4, "true") == 0) { v.t = JVal::T::Bool; v.b = true; i += 4; }
            else if (s.compare(i, 5, "false") == 0) { v.t = JVal::T::Bool; v.b = false; i += 5; }
            else err = true;
        } else if (c == 'n') {
            if (s.compare(i, 4, "null") == 0) { v.t = JVal::T::Null; i += 4; } else err = true;
        } else if (c == '-' || std::isdigit((unsigned char)c)) {
            size_t start = i;
            if (s[i] == '-') ++i;
            while (i < s.size() && (std::isdigit((unsigned char)s[i]) || s[i] == '.' ||
                   s[i] == 'e' || s[i] == 'E' || s[i] == '+' || s[i] == '-')) ++i;
            v.t = JVal::T::Num; v.num = std::atof(s.substr(start, i - start).c_str());
        } else {
            err = true;
        }
        return v;
    }
};

std::string lower(std::string s) { for (char& c : s) c = (char)std::tolower((unsigned char)c); return s; }

bool is_mnemonic_field(const std::string& f) { return lower(f) == "mnemonic" || lower(f) == "seed_phrase" || lower(f) == "seedphrase"; }
bool is_xprv_field(const std::string& f) {
    auto l = lower(f);
    return l == "xprv" || l == "masterprivkey" || l == "master_priv" || l == "hdseed" || l == "xpriv";
}
bool is_wif_field(const std::string& f) {
    auto l = lower(f);
    return l == "wif" || l == "privkey" || l == "private_key" || l == "privatekey" || l == "key" || l == "secret";
}
bool is_key_array_field(const std::string& f) {
    auto l = lower(f);
    return l == "keys" || l == "private_keys" || l == "privatekeys" || l == "wifs" || l == "addresses";
}

void classify_string_value(const std::string& field, const std::string& val,
                           const std::string& passphrase, std::vector<KeystoreItem>& out)
{
    // Try WIF, then raw hex; xprv/mnemonic handled by field name.
    if (is_xprv_field(field)) {
        if (HDKey::parse(val)) { KeystoreItem it; it.kind = KeystoreItem::Kind::Xprv; it.source_field = field; it.text = val; out.push_back(std::move(it)); return; }
    }
    if (auto wif = decode_wif(val); wif.ok) {
        KeystoreItem it; it.kind = KeystoreItem::Kind::Wif; it.source_field = field;
        it.scalar = wif.scalar.copy(); it.compressed = wif.compressed;
        out.push_back(std::move(it)); return;
    }
    if (auto raw = decode_raw_hex(val); raw.ok && (val.size() == 64 || (val.size() == 66 && (val[1] == 'x' || val[1] == 'X')))) {
        KeystoreItem it; it.kind = KeystoreItem::Kind::RawHex; it.source_field = field;
        it.scalar = raw.scalar.copy(); it.compressed = raw.compressed;
        out.push_back(std::move(it)); return;
    }
    (void)passphrase;
}

void walk(const JVal& v, const std::string& field, const std::string& sibling_passphrase,
          std::vector<KeystoreItem>& out)
{
    if (v.t == JVal::T::Str) {
        if (is_mnemonic_field(field)) {
            KeystoreItem it; it.kind = KeystoreItem::Kind::Mnemonic; it.source_field = field;
            it.text = v.str; it.passphrase = sibling_passphrase; out.push_back(std::move(it));
            return;
        }
        if (is_wif_field(field) || is_xprv_field(field))
            classify_string_value(field, v.str, sibling_passphrase, out);
        return;
    }
    if (v.t == JVal::T::Obj) {
        // Find a sibling passphrase for a mnemonic in this object.
        std::string pass;
        for (auto& kv : v.obj) if (lower(kv.first) == "passphrase" && kv.second.t == JVal::T::Str) pass = kv.second.str;
        for (auto& kv : v.obj) {
            if (kv.second.t == JVal::T::Arr && is_key_array_field(kv.first)) {
                for (auto& e : kv.second.arr) {
                    if (e.t == JVal::T::Str) classify_string_value(kv.first, e.str, pass, out);
                    else walk(e, kv.first, pass, out);
                }
            } else {
                walk(kv.second, kv.first, pass, out);
            }
        }
        return;
    }
    if (v.t == JVal::T::Arr) {
        for (auto& e : v.arr) walk(e, field, sibling_passphrase, out);
    }
}

} // namespace

KeystoreImport import_json_keystore(const std::string& json)
{
    KeystoreImport r;
    JParser p(json);
    JVal root = p.parse();
    if (p.err) { r.error = "invalid JSON keystore"; return r; }
    p.skip();
    if (p.i != json.size()) {
        // allow trailing whitespace only
        bool trailing_ok = true;
        for (size_t k = p.i; k < json.size(); ++k) if (!std::isspace((unsigned char)json[k])) { trailing_ok = false; break; }
        if (!trailing_ok) { r.error = "trailing data after JSON value"; return r; }
    }
    r.ok = true;
    walk(root, "", "", r.items);
    if (r.items.empty()) r.error = "no recognised key material in keystore";
    return r;
}

} // namespace c2w::hdkeys
