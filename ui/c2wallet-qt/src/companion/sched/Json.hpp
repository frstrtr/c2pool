// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Inject scheduler — internal JSON helpers over nlohmann::json (the node's own
// wire library). Not part of the public scheduler API: the public headers carry
// plain structs, so a consumer of the companion library never needs nlohmann.
//
// Every parse goes through parse_bounded(): a pre-scan caps the nesting depth
// at 64 (the hdkeys MiniJson bound) before nlohmann recurses, so a hostile or
// corrupted document cannot exhaust the stack.

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace c2w::companion::sched::json {

using J = nlohmann::ordered_json;

inline constexpr int kMaxDepth = 64;

inline bool depth_ok(const std::string& text, int max_depth)
{
    int depth = 0;
    bool in_str = false, esc = false;
    for (char c : text) {
        if (in_str) {
            if (esc) esc = false;
            else if (c == '\\') esc = true;
            else if (c == '"') in_str = false;
            continue;
        }
        if (c == '"') in_str = true;
        else if (c == '{' || c == '[') {
            if (++depth > max_depth) return false;
        } else if (c == '}' || c == ']') --depth;
    }
    return true;
}

inline bool parse_bounded(const std::string& text, J& out, std::string& why)
{
    if (!depth_ok(text, kMaxDepth)) {
        why = "JSON nesting deeper than " + std::to_string(kMaxDepth) + " levels";
        return false;
    }
    out = J::parse(text, nullptr, /*allow_exceptions=*/false);
    if (out.is_discarded()) {
        why = "not valid JSON";
        return false;
    }
    return true;
}

inline std::string dump(const J& j)
{
    return j.dump(2, ' ', false, J::error_handler_t::replace) + "\n";
}

inline std::string dump_compact(const J& j)
{
    return j.dump(-1, ' ', false, J::error_handler_t::replace);
}

// Typed field reader that records the first error with its path. A missing
// key or a null yields the default; a value of the wrong type is an error.
class Reader {
public:
    std::string err;
    bool ok() const { return err.empty(); }
    void fail(const std::string& path, const std::string& what)
    {
        if (err.empty()) err = path + ": " + what;
    }

    static const J* at(const J& o, const char* k)
    {
        if (!o.is_object()) return nullptr;
        auto it = o.find(k);
        if (it == o.end() || it->is_null()) return nullptr;
        return &*it;
    }

    int64_t i64(const J& o, const char* k, const std::string& p, int64_t def = 0)
    {
        const J* v = at(o, k);
        if (!v) return def;
        if (!v->is_number_integer()) { fail(p + "." + k, "expected an integer"); return def; }
        return v->get<int64_t>();
    }
    std::optional<int64_t> oi64(const J& o, const char* k, const std::string& p)
    {
        const J* v = at(o, k);
        if (!v) return std::nullopt;
        if (!v->is_number_integer()) { fail(p + "." + k, "expected an integer or null"); return std::nullopt; }
        return v->get<int64_t>();
    }
    std::string str(const J& o, const char* k, const std::string& p, const std::string& def = {})
    {
        const J* v = at(o, k);
        if (!v) return def;
        if (!v->is_string()) { fail(p + "." + k, "expected a string"); return def; }
        return v->get<std::string>();
    }
    std::string req_str(const J& o, const char* k, const std::string& p)
    {
        const J* v = at(o, k);
        if (!v || !v->is_string()) { fail(p + "." + k, "required string missing"); return {}; }
        return v->get<std::string>();
    }
    std::optional<std::string> ostr(const J& o, const char* k, const std::string& p)
    {
        const J* v = at(o, k);
        if (!v) return std::nullopt;
        if (!v->is_string()) { fail(p + "." + k, "expected a string or null"); return std::nullopt; }
        return v->get<std::string>();
    }
    bool boolean(const J& o, const char* k, const std::string& p, bool def = false)
    {
        const J* v = at(o, k);
        if (!v) return def;
        if (!v->is_boolean()) { fail(p + "." + k, "expected a boolean"); return def; }
        return v->get<bool>();
    }
    std::optional<bool> obool(const J& o, const char* k, const std::string& p)
    {
        const J* v = at(o, k);
        if (!v) return std::nullopt;
        if (!v->is_boolean()) { fail(p + "." + k, "expected a boolean or null"); return std::nullopt; }
        return v->get<bool>();
    }
    const J* obj(const J& o, const char* k, const std::string& p)
    {
        const J* v = at(o, k);
        if (!v) return nullptr;
        if (!v->is_object()) { fail(p + "." + k, "expected an object"); return nullptr; }
        return v;
    }
    const J* arr(const J& o, const char* k, const std::string& p)
    {
        const J* v = at(o, k);
        if (!v) return nullptr;
        if (!v->is_array()) { fail(p + "." + k, "expected an array"); return nullptr; }
        return v;
    }
};

template <class T>
inline J opt(const std::optional<T>& v)
{
    return v ? J(*v) : J(nullptr);
}

} // namespace c2w::companion::sched::json
