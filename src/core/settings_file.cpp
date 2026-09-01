// src/core/settings_file.cpp
//
// M0 settings-file loader + money gate. Qt-free, boost-free, link-free.
//
// PARSER NOTE: the design calls for vendored toml11. To keep M0 self-contained
// and fully unit-testable without pulling a new conan/vendor dependency into the
// build in the same change, this file uses a compact, STRICT TOML-subset reader
// (sections, dotted headers, inline tables, scalar + array values). The public
// SettingsFile/ResolvedConfig interface is parser-agnostic: swapping in toml11
// (with a TOML11_VERSION static_assert, per the vendored-header fake-green
// lesson) is a localized change confined to read_toml() below.
//
// DIGEST NOTE: the money_ack_hash is an integrity/UX digest over the money-class
// key set (NOT consensus). A small self-contained SHA-256 is used so the gate has
// ZERO link dependencies and cannot be perturbed by SIMD-dispatch/link-order
// issues; it is intentionally independent of the consensus hashers in core/hash.
#include "settings_file.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace c2pool::settings {

// ----------------------------------------------------------------------------
// Self-contained SHA-256 (public-domain style) for the money-ack digest only.
// ----------------------------------------------------------------------------
namespace {

class Sha256 {
public:
    Sha256() { reset(); }
    void update(const uint8_t* p, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            buf_[buflen_++] = p[i];
            if (buflen_ == 64) { block(buf_); buflen_ = 0; bits_ += 512; }
        }
    }
    void update(const std::string& s) {
        update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    std::string hex() {
        uint64_t total = bits_ + uint64_t(buflen_) * 8;
        uint8_t pad = 0x80;
        update(&pad, 1);
        uint8_t zero = 0;
        while (buflen_ != 56) update(&zero, 1);
        uint8_t lenb[8];
        for (int i = 0; i < 8; ++i) lenb[7 - i] = uint8_t(total >> (8 * i));
        update(lenb, 8);
        std::string out;
        static const char* H = "0123456789abcdef";
        for (int i = 0; i < 8; ++i) {
            for (int j = 3; j >= 0; --j) {
                uint8_t b = uint8_t(h_[i] >> (8 * j));
                out.push_back(H[b >> 4]);
                out.push_back(H[b & 0xf]);
            }
        }
        return out;
    }
private:
    uint32_t h_[8];
    uint8_t  buf_[64];
    size_t   buflen_ = 0;
    uint64_t bits_   = 0;
    void reset() {
        static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
            0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        std::memcpy(h_, iv, sizeof(iv));
    }
    static uint32_t ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void block(const uint8_t* p) {
        static const uint32_t k[64] = {
            0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
            0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
            0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
            0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
            0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
            0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
            0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
            0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (uint32_t(p[i*4]) << 24) | (uint32_t(p[i*4+1]) << 16) |
                   (uint32_t(p[i*4+2]) << 8) | uint32_t(p[i*4+3]);
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = ror(w[i-15],7) ^ ror(w[i-15],18) ^ (w[i-15] >> 3);
            uint32_t s1 = ror(w[i-2],17) ^ ror(w[i-2],19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        uint32_t a=h_[0],b=h_[1],c=h_[2],d=h_[3],e=h_[4],f=h_[5],g=h_[6],hh=h_[7];
        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = ror(e,6) ^ ror(e,11) ^ ror(e,25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + k[i] + w[i];
            uint32_t S0 = ror(a,2) ^ ror(a,13) ^ ror(a,22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + maj;
            hh=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
        }
        h_[0]+=a; h_[1]+=b; h_[2]+=c; h_[3]+=d; h_[4]+=e; h_[5]+=f; h_[6]+=g; h_[7]+=hh;
    }
};

std::string sha256_hex(const std::string& s) {
    Sha256 h; h.update(s); return h.hex();
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b - a);
}

std::string strip_comment(const std::string& line) {
    // strip a trailing # comment that is not inside a string literal
    bool in_str = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (c == '"') in_str = !in_str;
        else if (c == '#' && !in_str) return line.substr(0, i);
    }
    return line;
}

std::string unquote(const std::string& v) {
    std::string t = trim(v);
    if (t.size() >= 2 && t.front() == '"' && t.back() == '"')
        return t.substr(1, t.size() - 2);
    return t;
}

} // namespace

// ----------------------------------------------------------------------------
// Compact TOML-subset reader. Emits a flat map: full.dotted.path -> literal.
// Supports: [section], [a.b] headers; key = scalar; key = { k = v, ... } inline
// tables (one level); key = [ ... ] arrays (kept as raw literal text).
// ----------------------------------------------------------------------------
namespace {

struct FlatToml {
    // insertion-ordered for stable diagnostics; also a lookup index
    std::vector<std::pair<std::string, std::string>> kv;
    bool ok = true;
    std::string error;
};

void emit_inline_table(FlatToml& out, const std::string& prefix,
                       const std::string& body) {
    // body is the text between { and }
    std::string cur;
    int depth = 0;
    std::vector<std::string> parts;
    for (char c : body) {
        if (c == '{' || c == '[') depth++;
        if (c == '}' || c == ']') depth--;
        if (c == ',' && depth == 0) { parts.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    if (!trim(cur).empty()) parts.push_back(cur);
    for (auto& p : parts) {
        auto eq = p.find('=');
        if (eq == std::string::npos) continue;
        std::string k = trim(p.substr(0, eq));
        std::string v = trim(p.substr(eq + 1));
        out.kv.emplace_back(prefix + "." + k, unquote(v));
    }
}

FlatToml read_toml(const std::string& text) {
    FlatToml out;
    std::string section;
    std::istringstream ss(text);
    std::string raw;
    int lineno = 0;
    while (std::getline(ss, raw)) {
        ++lineno;
        std::string line = trim(strip_comment(raw));
        if (line.empty()) continue;
        if (line.front() == '[') {
            auto close = line.find(']');
            if (close == std::string::npos) {
                out.ok = false;
                out.error = "line " + std::to_string(lineno) + ": unterminated section header";
                return out;
            }
            section = trim(line.substr(1, close - 1));
            continue;
        }
        auto eq = line.find('=');
        if (eq == std::string::npos) {
            out.ok = false;
            out.error = "line " + std::to_string(lineno) + ": expected key = value";
            return out;
        }
        std::string key = trim(line.substr(0, eq));
        std::string val = trim(line.substr(eq + 1));
        std::string path = section.empty() ? key : section + "." + key;
        if (!val.empty() && val.front() == '{') {
            auto close = val.rfind('}');
            emit_inline_table(out, path, val.substr(1, close - 1));
        } else {
            out.kv.emplace_back(path, unquote(val));
        }
    }
    return out;
}

// Map a file dotted path to a catalog canonical name for the given coin.
// Coin-specific sections are stored under [<coin>.<section>]; strip the coin
// prefix. Top-level [global]/[meta] keep their names. [gate].* is special.
std::string file_path_to_canon(const std::string& path,
                               const std::string& coin_name) {
    std::string p = path;
    std::string cp = coin_name + ".";
    if (p.rfind(cp, 0) == 0) p = p.substr(cp.size());
    return p;
}

const char* coin_file_name(c2pool::catalog::CoinBit c) {
    using namespace c2pool::catalog;
    switch (c) {
        case C_DASH: return "dash";
        case C_LTC:  return "ltc";
        case C_BTC:  return "btc";
        case C_DGB:  return "dgb";
        case C_BCH:  return "bch";
        default:     return "?";
    }
}

} // namespace

// ----------------------------------------------------------------------------
// ResolvedConfig
// ----------------------------------------------------------------------------
using c2pool::catalog::ParamRow;
using c2pool::catalog::PType;

void ResolvedConfig::seed_compiled_defaults(c2pool::catalog::CoinBit coin) {
    for (const auto& r : c2pool::catalog::all_params()) {
        if (!r.applies_to(coin)) continue;
        Setting s;
        s.source = Source::CompiledDefault;
        s.present = false;  // pure compiled default until explicitly set
        if (r.type == PType::TRISTATE_BOOL) {
            s.tri = TriBool::Unset;  // loader never defaults a tristate
        } else if (r.default_kind == c2pool::catalog::DefaultKind::LIT) {
            s.value = r.default_literal;
        }
        by_canon_[r.canon] = s;
    }
}

void ResolvedConfig::set(const std::string& canon, const std::string& value, Source src) {
    auto& s = by_canon_[canon];
    s.value = value;
    s.source = src;
    s.present = true;
}

void ResolvedConfig::set_tri(const std::string& canon, TriBool tri, Source src) {
    auto& s = by_canon_[canon];
    s.tri = tri;
    s.source = src;
    s.present = (tri != TriBool::Unset);
}

bool ResolvedConfig::has(const std::string& canon) const {
    auto it = by_canon_.find(canon);
    return it != by_canon_.end() && it->second.present;
}

bool ResolvedConfig::file_set(const std::string& canon) const {
    auto it = by_canon_.find(canon);
    return it != by_canon_.end() && it->second.present && it->second.source == Source::File;
}

std::optional<Source> ResolvedConfig::source_of(const std::string& canon) const {
    auto it = by_canon_.find(canon);
    if (it == by_canon_.end() || !it->second.present) return std::nullopt;
    return it->second.source;
}

std::optional<std::string> ResolvedConfig::get_string(const std::string& canon) const {
    auto it = by_canon_.find(canon);
    if (it == by_canon_.end() || !it->second.present) return std::nullopt;
    return it->second.value;
}

std::optional<int64_t> ResolvedConfig::get_i64(const std::string& canon) const {
    auto v = get_string(canon);
    if (!v) return std::nullopt;
    try { return std::stoll(*v); } catch (...) { return std::nullopt; }
}

std::optional<double> ResolvedConfig::get_double(const std::string& canon) const {
    auto v = get_string(canon);
    if (!v) return std::nullopt;
    try { return std::stod(*v); } catch (...) { return std::nullopt; }
}

std::optional<uint16_t> ResolvedConfig::get_u16(const std::string& canon) const {
    auto v = get_i64(canon);
    if (!v || *v < 0 || *v > 65535) return std::nullopt;
    return static_cast<uint16_t>(*v);
}

TriBool ResolvedConfig::get_tri(const std::string& canon) const {
    auto it = by_canon_.find(canon);
    if (it == by_canon_.end()) return TriBool::Unset;
    return it->second.tri;
}

void ResolvedConfig::apply_runtime(const std::string& canon, const std::string& value) {
    set(canon, value, Source::Runtime);  // L3 stub for M1
}

std::string ResolvedConfig::dump() const {
    // sorted by canon; std::map is already ordered
    std::ostringstream os;
    for (const auto& [canon, s] : by_canon_) {
        if (!s.present) continue;
        const ParamRow* row = c2pool::catalog::find_by_canon(canon);
        const char* src = "compiled";
        switch (s.source) {
            case Source::CompiledDefault: src = "compiled"; break;
            case Source::File: src = "file"; break;
            case Source::Cli: src = "cli"; break;
            case Source::Runtime: src = "runtime"; break;
        }
        std::string val = s.value;
        if (row && row->type == PType::TRISTATE_BOOL) {
            val = (s.tri == TriBool::True) ? "true"
                : (s.tri == TriBool::False) ? "false" : "unset";
        }
        os << canon << "=" << val << " source=" << src << "\n";
    }
    return os.str();
}

// ----------------------------------------------------------------------------
// Money digest + gate
// ----------------------------------------------------------------------------
std::string SettingsFile::money_digest(
    const std::vector<std::pair<std::string, std::string>>& money_kv) {
    std::vector<std::pair<std::string, std::string>> sorted = money_kv;
    std::sort(sorted.begin(), sorted.end());
    std::string canonical;
    for (const auto& [path, lit] : sorted) {
        canonical += path;
        canonical += "=";
        canonical += lit;
        canonical += "\n";
    }
    return sha256_hex(canonical);
}

namespace {
// Collect the money-class (path, literal) pairs present in a parsed file for a
// coin. `path` is the FULL file path (e.g. "dash.money.node_owner_fee_pct").
std::vector<std::pair<std::string, std::string>> collect_money_kv(
    const FlatToml& flat, c2pool::catalog::CoinBit coin) {
    std::string coin_name = coin_file_name(coin);
    std::vector<std::pair<std::string, std::string>> out;
    for (const auto& [path, lit] : flat.kv) {
        std::string canon = file_path_to_canon(path, coin_name);
        const ParamRow* row = c2pool::catalog::find_by_canon(canon);
        if (row && row->is_money()) out.emplace_back(path, lit);
    }
    return out;
}
} // namespace

std::string SettingsFile::compute_money_ack_hash(const std::string& path,
                                                 c2pool::catalog::CoinBit coin) {
    std::ifstream f(path);
    if (!f) return std::string();
    std::stringstream buf; buf << f.rdbuf();
    FlatToml flat = read_toml(buf.str());
    if (!flat.ok) return std::string();
    return money_digest(collect_money_kv(flat, coin));
}

LoadResult SettingsFile::load(const std::string& path,
                              c2pool::catalog::CoinBit coin,
                              const CliTracker& cli,
                              ResolvedConfig& out) {
    LoadResult res;
    std::ifstream f(path);
    if (!f) {
        res.status = LoadStatus::AbsentOk;
        res.messages.push_back("settings: no file at " + path +
                               " (pure compiled + CLI)");
        return res;
    }
    std::stringstream buf; buf << f.rdbuf();
    FlatToml flat = read_toml(buf.str());
    if (!flat.ok) {
        res.status = LoadStatus::ParseError;
        res.exit_code = 78;
        res.messages.push_back("settings: parse error: " + flat.error);
        return res;
    }

    std::string coin_name = coin_file_name(coin);

    // 1) validate every key against the catalog; collect the ack hash.
    std::string ack_hash;
    std::vector<std::pair<std::string, std::string>> apply_kv;   // non-money, catalog-valid
    for (const auto& [fpath, lit] : flat.kv) {
        if (fpath == "gate.money_ack_hash") { ack_hash = lit; continue; }
        if (fpath.rfind("gate.", 0) == 0) continue;  // other gate.* keys (e.g. lax flag)
        if (fpath.rfind("meta.generation", 0) == 0 ||
            fpath.rfind("meta.last_writer", 0) == 0 ||
            fpath.rfind("meta.schema_version", 0) == 0 ||
            fpath.rfind("meta.created_by_version", 0) == 0) continue;  // ledger meta

        // Only enforce catalog membership for keys in THIS coin's section or the
        // shared top-level sections. Other-coin sections are ignored (a shared
        // file can carry all coins); own-section unknowns are fatal.
        bool own_section =
            fpath.rfind(coin_name + ".", 0) == 0 ||
            fpath.rfind("global.", 0) == 0 ||
            fpath.rfind("meta.", 0) == 0;
        std::string canon = file_path_to_canon(fpath, coin_name);
        const ParamRow* row = c2pool::catalog::find_by_canon(canon);
        if (!row) {
            if (own_section) {
                res.status = LoadStatus::ParseError;
                res.exit_code = 78;
                res.messages.push_back("settings: unknown key '" + fpath +
                    "' (no catalog row) -- refusing to start (would mask a typo)");
                return res;
            }
            continue;  // another coin's key in a shared file
        }
        if (row->is_compile_readonly()) {
            res.status = LoadStatus::ParseError;
            res.exit_code = 78;
            res.messages.push_back("settings: key '" + fpath +
                "' is compile-time read-only and cannot be set from a file");
            return res;
        }
        if (!row->is_money())
            apply_kv.emplace_back(canon, lit);
    }

    // 2) MONEY GATE (fail-closed). Any money-class key present requires a
    //    matching [gate].money_ack_hash. Refusal => node exits.
    auto money_kv = collect_money_kv(flat, coin);
    if (!money_kv.empty()) {
        std::string expect = money_digest(money_kv);
        if (ack_hash.empty() || ack_hash != expect) {
            res.status = LoadStatus::RefusedMoney;
            res.exit_code = 78;
            for (const auto& [p, _] : money_kv) res.offending_money_keys.push_back(p);
            for (const auto& [p, _] : money_kv)
                res.messages.push_back("settings: money-class key present: " + p);
            res.messages.push_back(
                "settings: money-class settings present without a matching "
                "gate.money_ack_hash -- refusing to start; remove the keys, pass "
                "them on the command line, or ack via --ack-money-settings");
            return res;
        }
        // acked: money keys become applicable (still CLI-overridable by caller)
        for (const auto& [fpath, lit] : money_kv) {
            std::string canon = file_path_to_canon(fpath, coin_name);
            apply_kv.emplace_back(canon, lit);
        }
    }

    // 3) OVERLAY: only fill keys the CLI did NOT explicitly set (generalizes
    //    main_ltc's cli_explicit). Tri-state mapping preserved.
    for (const auto& [canon, lit] : apply_kv) {
        if (cli.has(canon)) continue;  // CLI wins
        const ParamRow* row = c2pool::catalog::find_by_canon(canon);
        if (row && row->type == PType::TRISTATE_BOOL) {
            std::string t = lit;
            std::transform(t.begin(), t.end(), t.begin(), ::tolower);
            out.set_tri(canon, (t == "true") ? TriBool::True : TriBool::False, Source::File);
        } else {
            out.set(canon, lit, Source::File);
        }
    }

    res.status = LoadStatus::Ok;
    res.messages.push_back("settings: loaded " + path);
    return res;
}

} // namespace c2pool::settings
