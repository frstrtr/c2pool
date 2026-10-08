// SPDX-License-Identifier: AGPL-3.0-or-later
#include "MiniJson.hpp"

#include <cctype>
#include <cstdlib>

namespace c2w::hdkeys::mjson {

const JVal* JVal::find(const std::string& key) const
{
    if (t != T::Obj) return nullptr;
    for (const auto& kv : obj) if (kv.first == key) return &kv.second;
    return nullptr;
}

std::string JVal::str_of(const std::string& key) const
{
    const JVal* v = find(key);
    return (v && v->t == T::Str) ? v->str : std::string();
}

namespace {

struct Parser {
    const std::string& s;
    size_t i = 0;
    bool err = false;
    explicit Parser(const std::string& src) : s(src) {}

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

    JVal parse_value() {
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
                JVal val = parse_value();
                v.obj.emplace_back(std::move(key), std::move(val));
                skip();
                if (i < s.size() && s[i] == ',') { ++i; continue; }
                if (i < s.size() && s[i] == '}') { ++i; break; }
                err = true; break;
            }
        } else if (c == '[') {
            ++i; v.t = JVal::T::Arr; skip();
            if (i < s.size() && s[i] == ']') { ++i; return v; }
            while (!err) {
                v.arr.push_back(parse_value());
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

} // namespace

ParseResult parse(const std::string& s)
{
    ParseResult r;
    Parser p(s);
    JVal root = p.parse_value();
    if (p.err) { r.error = "invalid JSON"; return r; }
    p.skip();
    for (size_t k = p.i; k < s.size(); ++k)
        if (!std::isspace((unsigned char)s[k])) { r.error = "trailing data after JSON value"; return r; }
    r.ok = true;
    r.root = std::move(root);
    return r;
}

} // namespace c2w::hdkeys::mjson
