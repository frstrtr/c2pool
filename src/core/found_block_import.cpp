// SPDX-License-Identifier: AGPL-3.0-or-later
#include "found_block_import.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <cmath>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>

namespace core {
namespace found_block_import {

namespace {

constexpr size_t kMaxProblems = 5;

void note(Parsed& out, std::string what)
{
    ++out.malformed;
    if (out.problems.size() < kMaxProblems)
        out.problems.push_back(std::move(what));
}

/// 64 hex chars, lowercased; "" when `s` is not one.
std::string hash_hex(const std::string& s)
{
    if (s.size() != 64) return {};
    std::string out = s;
    for (auto& c : out) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return {};
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

std::string trim(const std::string& s)
{
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

/// A non-negative integer; nullopt for anything else (a fraction, a sign).
std::optional<uint64_t> whole(const nlohmann::json& v)
{
    if (v.is_number_unsigned()) return v.get<uint64_t>();
    if (v.is_number_integer()) {
        const int64_t i = v.get<int64_t>();
        if (i >= 0) return static_cast<uint64_t>(i);
        return std::nullopt;
    }
    if (v.is_number_float()) {
        const double d = v.get<double>();
        if (std::isfinite(d) && d >= 0.0 && d == std::floor(d) && d < 1.8e19)
            return static_cast<uint64_t>(d);
    }
    return std::nullopt;
}

/// A positive finite number; 0 for anything else (null, a string, <= 0).
double positive(const nlohmann::json& obj, const char* key)
{
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_number()) return 0.0;
    const double d = it->get<double>();
    return (std::isfinite(d) && d > 0.0) ? d : 0.0;
}

std::string string_field(const nlohmann::json& obj, const char* key)
{
    auto it = obj.find(key);
    return (it != obj.end() && it->is_string()) ? it->get<std::string>() : std::string();
}

/// An address-looking miner (base58 / bech32: letters and digits only).
std::string miner_field(const nlohmann::json& obj)
{
    std::string m = string_field(obj, "miner");
    if (m.size() < 20 || m.size() > 100) return {};
    for (char c : m)
        if (!std::isalnum(static_cast<unsigned char>(c))) return {};
    return m;
}

/// One JSON entry: a block hash string, or a row object.
void parse_entry(const nlohmann::json& e, size_t index, Parsed& out)
{
    const std::string where = "entry " + std::to_string(index);
    if (e.is_string()) {
        Row r;
        r.hash = hash_hex(trim(e.get<std::string>()));
        if (r.hash.empty()) { note(out, where + ": not a block hash"); return; }
        out.rows.push_back(std::move(r));
        return;
    }
    if (!e.is_object()) { note(out, where + ": neither a row nor a hash"); return; }

    Row r;
    // /recent_blocks names it hash; /recent_merged_blocks pow_hash.
    std::string h = string_field(e, "hash");
    if (h.empty()) h = string_field(e, "pow_hash");
    r.hash = hash_hex(h);
    if (r.hash.empty()) { note(out, where + ": no block hash"); return; }

    // height (or its p2pool alias number): absent / null = not known; any
    // other non-integer means the file is not what it claims to be.
    for (const char* key : {"height", "number"}) {
        auto it = e.find(key);
        if (it == e.end() || it->is_null()) continue;
        const auto v = whole(*it);
        if (!v) { note(out, where + ": bad " + key); return; }
        if (!r.height) r.height = *v;
    }
    if (auto it = e.find("ts"); it != e.end() && !it->is_null()) {
        const auto v = whole(*it);
        if (!v) { note(out, where + ": bad ts"); return; }
        r.ts = *v;
    }
    for (const char* key : {"chain", "symbol"}) {
        auto it = e.find(key);
        if (it == e.end() || it->is_null()) continue;
        if (!it->is_string()) { note(out, where + ": bad " + key); return; }
        if (r.chain.empty()) r.chain = trim(it->get<std::string>());
    }

    // Display fields: taken when well-formed, ignored otherwise.
    r.network_difficulty = positive(e, "network_difficulty");
    r.share_difficulty   = positive(e, "share_difficulty");
    r.pool_hashrate      = positive(e, "pool_hashrate_at_find");
    r.share_hash         = hash_hex(string_field(e, "share"));
    r.miner              = miner_field(e);
    r.coinbase_txid      = hash_hex(string_field(e, "coinbase_txid"));
    r.parent_hash        = hash_hex(string_field(e, "parent_hash"));
    if (auto it = e.find("subsidy"); it != e.end()) {
        if (const auto v = whole(*it)) r.subsidy = *v;
    }
    if (auto it = e.find("tx_count"); it != e.end()) {
        const auto v = whole(*it);
        if (v && *v > 0 && *v <= std::numeric_limits<uint32_t>::max())
            r.tx_count = static_cast<uint32_t>(*v);
    }
    out.rows.push_back(std::move(r));
}

} // namespace

Parsed parse(const std::string& text_in)
{
    Parsed out;
    std::string text = text_in;
    if (text.size() >= 3 && static_cast<unsigned char>(text[0]) == 0xEF
        && static_cast<unsigned char>(text[1]) == 0xBB
        && static_cast<unsigned char>(text[2]) == 0xBF)
        text.erase(0, 3);   // UTF-8 BOM

    size_t first = 0;
    while (first < text.size() && std::isspace(static_cast<unsigned char>(text[first]))) ++first;
    if (first == text.size()) {
        out.error = "the file is empty";
        return out;
    }

    if (text[first] == '[' || text[first] == '{') {
        out.format = "json";
        const auto doc = nlohmann::json::parse(text, nullptr, /*allow_exceptions=*/false);
        if (doc.is_discarded()) {
            out.error = "not valid JSON (expected the /recent_blocks array)";
            return out;
        }
        const nlohmann::json* arr = &doc;
        nlohmann::json one;
        if (doc.is_object()) {
            if (doc.contains("blocks") && doc["blocks"].is_array()) {
                arr = &doc["blocks"];
            } else if (doc.contains("hash") || doc.contains("pow_hash")) {
                one = nlohmann::json::array({doc});   // a single row (/found_block/<hash>)
                arr = &one;
            } else {
                out.error = "a JSON object without rows (expected the /recent_blocks array)";
                return out;
            }
        }
        size_t i = 0;
        for (const auto& e : *arr)
            parse_entry(e, i++, out);
        return out;
    }

    // One block hash per line; blank lines and # comments are skipped.
    out.format = "hash_list";
    std::istringstream in(text);
    std::string line;
    size_t n = 0;
    while (std::getline(in, line)) {
        ++n;
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        Row r;
        r.hash = hash_hex(line);
        if (r.hash.empty()) { note(out, "line " + std::to_string(n) + ": not a block hash"); continue; }
        out.rows.push_back(std::move(r));
    }
    return out;
}

Parsed read_file(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        Parsed out;
        out.error = "cannot open " + path;
        return out;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    return parse(ss.str());
}

void Report::add(const Report& pass)
{
    // `rows` counts each row once: a deferred row is counted by the pass that
    // first saw it, and comes back in a later pass's `rows` again.
    imported         += pass.imported;
    imported_aux     += pass.imported_aux;
    merged           += pass.merged;
    unchanged        += pass.unchanged;
    height_filled    += pass.height_filled;
    height_corrected += pass.height_corrected;
    pool_verified    += pass.pool_verified;
    rate_refused     += pass.rate_refused;
    pending          += pass.pending;
    for (const auto& [reason, n] : pass.rejected) rejected[reason] += n;
    deferred = pass.deferred;
}

std::string Report::summary() const
{
    std::ostringstream os;
    os << rows << " rows: imported " << imported;
    if (imported_aux) os << " (" << imported_aux << " merged-chain)";
    os << ", already held " << (merged + unchanged) << " (" << merged
       << " gained a missing field), rejected " << rejected_total();
    if (!rejected.empty()) {
        os << " (";
        bool first = true;
        for (const auto& [reason, n] : rejected) {
            os << (first ? "" : " ") << reason << "=" << n;
            first = false;
        }
        os << ")";
    }
    if (!deferred.empty()) os << ", waiting " << deferred.size();
    os << "; heights from the header chain: filled " << height_filled
       << ", corrected " << height_corrected
       << "; pool_hashrate_at_find refused " << rate_refused
       << "; coinbase-verified " << pool_verified;
    if (pending) os << "; pending (<6 deep) " << pending;
    return os.str();
}

} // namespace found_block_import
} // namespace core
