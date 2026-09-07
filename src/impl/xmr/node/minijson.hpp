/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version. See COPYING in the repository root.
 */

// ===========================================================================
// src/impl/xmr/node/minijson.hpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). A tiny, dependency-free JSON reader used to
// turn monerod JSON-RPC / ZMQ response bodies into the typed node structs, so
// the adapter's parse layer is exercisable in a single-TU KAT WITHOUT pulling
// rapidjson (which the production build uses). Numbers keep their source text so
// full u64 precision survives (JSON doubles would lose the low bits of piconero
// amounts and 64-bit difficulties). This is KAT-grade: it parses well-formed
// monerod output; it is NOT a hardened, adversarial-input parser. The consensus
// build MUST use the vetted rapidjson path -- this header exists so the field
// MAPPING (which JSON path -> which struct field) is testable in isolation.
// ===========================================================================
#pragma once

#include <array>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace c2pool::xmr::node::minijson {

enum class Type { Null, Bool, Number, String, Array, Object };

struct Value {
    Type type = Type::Null;
    bool boolean = false;
    std::string text;                 // raw token for Number, decoded bytes for String
    std::vector<Value> arr;
    std::map<std::string, Value> obj;

    bool is_object() const noexcept { return type == Type::Object; }
    bool is_array()  const noexcept { return type == Type::Array; }
    bool is_string() const noexcept { return type == Type::String; }
    bool is_number() const noexcept { return type == Type::Number; }

    // Object field lookup; returns a static Null when absent so chaining is safe.
    const Value& operator[](const std::string& key) const {
        static const Value kNull;
        if (type != Type::Object) return kNull;
        auto it = obj.find(key);
        return it == obj.end() ? kNull : it->second;
    }

    std::uint64_t as_u64(std::uint64_t dflt = 0) const {
        if (type != Type::Number || text.empty()) return dflt;
        return std::strtoull(text.c_str(), nullptr, 10);
    }
    std::uint32_t as_u32(std::uint32_t dflt = 0) const {
        return static_cast<std::uint32_t>(as_u64(dflt));
    }
    double as_double(double dflt = 0.0) const {
        if (type != Type::Number || text.empty()) return dflt;
        return std::strtod(text.c_str(), nullptr);
    }
    const std::string& as_string() const { return text; }
    bool as_bool(bool dflt = false) const { return type == Type::Bool ? boolean : dflt; }
};

// --- recursive-descent scanner ----------------------------------------------
class Parser {
public:
    explicit Parser(const char* p, std::size_t n) : s_(p), e_(p + n) {}

    bool parse(Value& out) {
        skip_ws();
        if (!value(out)) return false;
        skip_ws();
        return true; // trailing content tolerated
    }

private:
    const char* s_;
    const char* e_;

    void skip_ws() {
        while (s_ < e_ && (*s_ == ' ' || *s_ == '\t' || *s_ == '\n' || *s_ == '\r')) ++s_;
    }
    bool eof() const { return s_ >= e_; }

    bool value(Value& v) {
        skip_ws();
        if (eof()) return false;
        char c = *s_;
        switch (c) {
            case '{': return object(v);
            case '[': return array(v);
            case '"': { v.type = Type::String; return string(v.text); }
            case 't': case 'f': return boolean(v);
            case 'n': return null(v);
            default:  return number(v);
        }
    }

    bool object(Value& v) {
        v.type = Type::Object;
        ++s_; // '{'
        skip_ws();
        if (!eof() && *s_ == '}') { ++s_; return true; }
        for (;;) {
            skip_ws();
            if (eof() || *s_ != '"') return false;
            std::string key;
            if (!string(key)) return false;
            skip_ws();
            if (eof() || *s_ != ':') return false;
            ++s_;
            Value child;
            if (!value(child)) return false;
            v.obj.emplace(std::move(key), std::move(child));
            skip_ws();
            if (eof()) return false;
            if (*s_ == ',') { ++s_; continue; }
            if (*s_ == '}') { ++s_; return true; }
            return false;
        }
    }

    bool array(Value& v) {
        v.type = Type::Array;
        ++s_; // '['
        skip_ws();
        if (!eof() && *s_ == ']') { ++s_; return true; }
        for (;;) {
            Value child;
            if (!value(child)) return false;
            v.arr.push_back(std::move(child));
            skip_ws();
            if (eof()) return false;
            if (*s_ == ',') { ++s_; continue; }
            if (*s_ == ']') { ++s_; return true; }
            return false;
        }
    }

    bool string(std::string& out) {
        if (eof() || *s_ != '"') return false;
        ++s_;
        while (!eof()) {
            char c = *s_++;
            if (c == '"') return true;
            if (c == '\\') {
                if (eof()) return false;
                char esc = *s_++;
                switch (esc) {
                    case '"':  out.push_back('"');  break;
                    case '\\': out.push_back('\\'); break;
                    case '/':  out.push_back('/');  break;
                    case 'n':  out.push_back('\n'); break;
                    case 't':  out.push_back('\t'); break;
                    case 'r':  out.push_back('\r'); break;
                    case 'b':  out.push_back('\b'); break;
                    case 'f':  out.push_back('\f'); break;
                    case 'u': { // minimal \uXXXX: keep the ASCII low byte; enough
                                // for monerod (hex strings never contain \u anyway)
                        if (e_ - s_ < 4) return false;
                        auto hexval = [](char h) -> int {
                            if (h >= '0' && h <= '9') return h - '0';
                            if (h >= 'a' && h <= 'f') return h - 'a' + 10;
                            if (h >= 'A' && h <= 'F') return h - 'A' + 10;
                            return 0;
                        };
                        int cp = (hexval(s_[0]) << 12) | (hexval(s_[1]) << 8) |
                                 (hexval(s_[2]) << 4) | hexval(s_[3]);
                        s_ += 4;
                        if (cp < 0x80) out.push_back(static_cast<char>(cp));
                        break;
                    }
                    default: out.push_back(esc); break;
                }
            } else {
                out.push_back(c);
            }
        }
        return false; // unterminated
    }

    bool number(Value& v) {
        const char* start = s_;
        if (!eof() && (*s_ == '-' || *s_ == '+')) ++s_;
        bool any = false;
        while (!eof() && ((*s_ >= '0' && *s_ <= '9') || *s_ == '.' ||
                          *s_ == 'e' || *s_ == 'E' || *s_ == '+' || *s_ == '-')) {
            ++s_; any = true;
        }
        if (!any) return false;
        v.type = Type::Number;
        v.text.assign(start, s_);
        return true;
    }

    bool boolean(Value& v) {
        if (e_ - s_ >= 4 && std::string(s_, s_ + 4) == "true")  { s_ += 4; v.type = Type::Bool; v.boolean = true;  return true; }
        if (e_ - s_ >= 5 && std::string(s_, s_ + 5) == "false") { s_ += 5; v.type = Type::Bool; v.boolean = false; return true; }
        return false;
    }

    bool null(Value& v) {
        if (e_ - s_ >= 4 && std::string(s_, s_ + 4) == "null") { s_ += 4; v.type = Type::Null; return true; }
        return false;
    }
};

inline bool parse(const char* p, std::size_t n, Value& out) {
    Parser parser(p, n);
    return parser.parse(out);
}
inline bool parse(const std::string& s, Value& out) { return parse(s.data(), s.size(), out); }

// --- hex helpers (monerod emits 32-byte ids/hashes as 64-char hex strings) ----
inline bool hex_to_hash(const std::string& hex, std::array<std::uint8_t, 32>& out) {
    if (hex.size() != 64) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < 32; ++i) {
        int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    return true;
}

inline std::string hash_to_hex(const std::array<std::uint8_t, 32>& h) {
    static const char* d = "0123456789abcdef";
    std::string out(64, '0');
    for (std::size_t i = 0; i < 32; ++i) {
        out[2 * i]     = d[h[i] >> 4];
        out[2 * i + 1] = d[h[i] & 0xf];
    }
    return out;
}

// monerod >= v0.18 emits get_miner_data.difficulty (and block_header
// .wide_difficulty) as a "0x..." hex STRING of up to 32 nibbles -- a 128-bit
// cryptonote::difficulty_type -- not as a JSON number. Parses it into (hi, lo).
// Returns false on an empty, non-hex, or > 128-bit string (caller keeps zero).
inline bool hex_to_u128(const std::string& hex, std::uint64_t& hi, std::uint64_t& lo) {
    std::size_t p = 0;
    if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) p = 2;
    if (p >= hex.size() || hex.size() - p > 32) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::uint64_t h = 0, l = 0;
    for (; p < hex.size(); ++p) {
        int n = nib(hex[p]);
        if (n < 0) return false;
        h = (h << 4) | (l >> 60);
        l = (l << 4) | static_cast<std::uint64_t>(n);
    }
    hi = h;
    lo = l;
    return true;
}

} // namespace c2pool::xmr::node::minijson
