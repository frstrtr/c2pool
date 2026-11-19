// SPDX-License-Identifier: AGPL-3.0-or-later
#include "found_block_import.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <cmath>
#include <filesystem>
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
        // Whole when nothing is left above its floor (ordered comparisons:
        // no float equality).
        const double d = v.get<double>();
        if (std::isfinite(d) && d >= 0.0 && d < 1.8e19 && !(d - std::floor(d) > 0.0))
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
    // The source's measured effort of the round: offered when it says it
    // integrated it ("imported": a node that took another's integral) and
    // was watching when the block was found. A first block's 1.0 and a
    // single sample are no such measurement (the single sample is this
    // node's own to compute, from pool_hashrate_at_find).
    const std::string method = string_field(e, "effort_method");
    auto measured = e.find("measured");
    if ((method == "integrated" || method == "imported")
        && measured != e.end() && measured->is_boolean() && measured->get<bool>()) {
        auto number = [&e](const char* key) {
            auto it = e.find(key);
            return (it != e.end() && it->is_number()) ? it->get<double>()
                                                      : std::numeric_limits<double>::quiet_NaN();
        };
        r.effort_offered   = true;
        r.effort           = number("effort");
        r.effort_coverage  = number("history_coverage");
        r.effort_prev_hash = hash_hex(string_field(e, "prev_block_hash"));
    }
    out.rows.push_back(std::move(r));
}

} // namespace

Parsed parse(const std::string& text_in)
{
    Parsed out;
    if (text_in.size() > kMaxFileBytes) {
        out.error = std::to_string(text_in.size()) + " bytes, above the cap of "
            + std::to_string(kMaxFileBytes) + " bytes per file";
        return out;
    }
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
        if (arr->size() > kMaxRows) {
            out.error = std::to_string(arr->size()) + " entries, above the cap of "
                + std::to_string(kMaxRows) + " rows per file";
            return out;
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
        if (out.rows.size() + out.malformed >= kMaxRows) {
            out = Parsed{};
            out.format = "hash_list";
            out.error = "more than " + std::to_string(kMaxRows) + " entries, above the cap of "
                + std::to_string(kMaxRows) + " rows per file";
            return out;
        }
        Row r;
        r.hash = hash_hex(line);
        if (r.hash.empty()) { note(out, "line " + std::to_string(n) + ": not a block hash"); continue; }
        out.rows.push_back(std::move(r));
    }
    return out;
}

OpenedFile open_import_file(const std::string& value)
{
    namespace fs = std::filesystem;
    OpenedFile out;
    if (value.empty()) {
        out.error = "no file named";
        return out;
    }
    if (value[0] == '-') {
        out.error = "'" + value + "' is an option, not a file (the flag needs a FILE)";
        return out;
    }
    // From here on only the CANONICAL path is used: absolute, "." and ".."
    // folded, every symlink followed to its final target.
    std::error_code ec;
    const fs::path absolute = fs::absolute(fs::path(value), ec);
    if (ec) {
        out.error = "cannot resolve the path";
        return out;
    }
    const fs::path canonical = fs::weakly_canonical(absolute, ec);
    if (ec || canonical.empty()) {
        out.error = "cannot resolve the path";
        return out;
    }
    const fs::file_status st = fs::status(canonical, ec);
    if (st.type() == fs::file_type::not_found) {
        out.error = "no such file";
        return out;
    }
    if (ec || !fs::exists(st)) {
        out.error = "cannot read its status";
        return out;
    }
    // A directory, a device (/dev/null, /dev/zero: endless), a FIFO (a read
    // would block the start) or a socket is never an import file -- also
    // not behind a symlink, which `canonical` has already followed.
    if (!fs::is_regular_file(st)) {
        out.error = "not a regular file";
        return out;
    }
    const auto size = fs::file_size(canonical, ec);
    if (ec) {
        out.error = "cannot read its size";
        return out;
    }
    if (size > kMaxFileBytes) {
        out.error = std::to_string(size) + " bytes, above the cap of "
            + std::to_string(kMaxFileBytes) + " bytes per file";
        return out;
    }
    std::ifstream f(canonical, std::ios::in | std::ios::binary);   // read-only
    if (!f) {
        out.error = "cannot be opened for reading";
        return out;
    }
    // The cap holds while reading too: a file that grew since its size was
    // read is refused, never loaded past the cap.
    std::string contents;
    contents.reserve(static_cast<size_t>(size));
    char buf[65536];
    while (f.read(buf, sizeof(buf)) || f.gcount() > 0) {
        contents.append(buf, static_cast<size_t>(f.gcount()));
        if (contents.size() > kMaxFileBytes) {
            out.error = "above the cap of " + std::to_string(kMaxFileBytes) + " bytes per file";
            return out;
        }
    }
    if (f.bad()) {
        out.error = "read error";
        return out;
    }
    out.path = canonical.string();
    out.contents = std::move(contents);
    return out;
}

std::string file_problem(const std::string& value)
{
    return open_import_file(value).error;
}

Parsed read_file(const std::string& path)
{
    OpenedFile file = open_import_file(path);
    if (!file.error.empty()) {
        Parsed out;
        out.error = path + ": " + file.error;
        return out;
    }
    return parse(file.contents);
}

std::vector<std::string> split_paths(const std::string& list)
{
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= list.size()) {
        const size_t comma = list.find(',', start);
        const size_t end = comma == std::string::npos ? list.size() : comma;
        std::string item = trim(list.substr(start, end - start));
        if (!item.empty()) out.push_back(std::move(item));
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return out;
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
    effort_taken     += pass.effort_taken;
    effort_refused   += pass.effort_refused;
    effort_not_used  += pass.effort_not_used;
    effort_not_judged += pass.effort_not_judged;
    pending          += pass.pending;
    for (const auto& [chain, n] : pass.imported_by_chain) imported_by_chain[chain] += n;
    for (const auto& [reason, n] : pass.rejected) rejected[reason] += n;
    for (const auto& [chain, reasons] : pass.rejected_by_chain)
        for (const auto& [reason, n] : reasons) rejected_by_chain[chain][reason] += n;
    deferred.insert(deferred.end(), pass.deferred.begin(), pass.deferred.end());
}

std::string Report::summary() const
{
    std::ostringstream os;
    os << rows << " rows: imported " << imported;
    if (!imported_by_chain.empty()) {
        os << " (";
        bool first = true;
        for (const auto& [chain, n] : imported_by_chain) {
            os << (first ? "" : ", ") << chain << " " << n;
            first = false;
        }
        os << ")";
    }
    os << ", already held " << (merged + unchanged) << " (" << merged
       << " gained a missing field), rejected " << rejected_total();
    if (!rejected_by_chain.empty()) {
        // Per chain: "(LTC: not_on_chain=2; DOGE: below_header_chain=1)".
        os << " (";
        bool first_chain = true;
        for (const auto& [chain, reasons] : rejected_by_chain) {
            os << (first_chain ? "" : "; ") << chain << ":";
            for (const auto& [reason, n] : reasons) os << " " << reason << "=" << n;
            first_chain = false;
        }
        os << ")";
    }
    if (!deferred.empty()) os << ", waiting " << deferred.size();
    os << "; heights from the header chain: filled " << height_filled
       << ", corrected " << height_corrected
       << "; pool_hashrate_at_find refused " << rate_refused
       << "; source effort taken " << effort_taken << ", refused " << effort_refused
       << ", not used " << effort_not_used << ", not judged " << effort_not_judged
       << "; coinbase-verified " << pool_verified;
    if (pending) os << "; pending (<6 deep) " << pending;
    return os.str();
}

} // namespace found_block_import
} // namespace core
