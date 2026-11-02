#include "utxo_snapshot.hpp"

#include "coin_compressor.hpp"

#include <btclibs/crypto/common.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <map>
#include <sstream>

#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace core::coin {

namespace {

using Clock = std::chrono::steady_clock;

double seconds_since(Clock::time_point t0)
{
    return std::chrono::duration<double>(Clock::now() - t0).count();
}

int cmp_outpoint(const Outpoint& a, const Outpoint& b)
{
    const int c = std::memcmp(a.txid.data(), b.txid.data(), 32);
    if (c != 0) return c;
    if (a.index < b.index) return -1;
    if (a.index > b.index) return 1;
    return 0;
}

std::string outpoint_str(const Outpoint& op)
{
    return op.txid.GetHex() + ":" + std::to_string(op.index);
}

std::string finalize_hex(CSHA256& sha)
{
    unsigned char out[CSHA256::OUTPUT_SIZE];
    sha.Finalize(out);
    return bytes_to_hex(out, sizeof(out));
}

bool parse_u64(const std::string& s, uint64_t& out)
{
    if (s.empty() || s.size() > 20) return false;
    uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        const uint64_t d = static_cast<uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    if (s.size() > 1 && s[0] == '0') return false;
    out = v;
    return true;
}

bool is_lower_hex(const std::string& s, size_t len)
{
    if (s.size() != len) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

bool is_token(const std::string& s)
{
    if (s.empty()) return false;
    for (char c : s)
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    return true;
}

std::string rstrip(std::string s)
{
    while (!s.empty() && (s.back() == '\r' || s.back() == ' ' || s.back() == '\t'))
        s.pop_back();
    return s;
}

bool in_digest_domain(const std::string& line)
{
    if (line.empty()) return false;
    if (line[0] == '#') return false;
    if (line.rfind("digest", 0) == 0 && (line.size() == 6 || line[6] == ' ' || line[6] == '\t'))
        return false;
    return true;
}

bool split_kv(const std::string& line, std::string& key, std::string& val)
{
    const size_t sp = line.find_first_of(" \t");
    if (sp == std::string::npos) {
        key = line;
        val.clear();
        return true;
    }
    key = line.substr(0, sp);
    const size_t v = line.find_first_not_of(" \t", sp);
    val = (v == std::string::npos) ? std::string() : line.substr(v);
    return true;
}

/// The `.inc` form: `// comment` lines and lines of C string literals. True
/// when the first meaningful line is a literal.
bool looks_like_inc(const std::string& text)
{
    std::istringstream in(text);
    std::string raw;
    while (std::getline(in, raw)) {
        const size_t p = raw.find_first_not_of(" \t\r");
        if (p == std::string::npos) continue;
        if (raw.compare(p, 2, "//") == 0) continue;
        return raw[p] == '"';
    }
    return false;
}

bool inc_to_text(const std::string& inc, std::string& text, std::string& error)
{
    text.clear();
    std::istringstream in(inc);
    std::string raw;
    size_t lineno = 0;
    while (std::getline(in, raw)) {
        ++lineno;
        size_t p = raw.find_first_not_of(" \t\r");
        if (p == std::string::npos) continue;
        if (raw.compare(p, 2, "//") == 0) continue;
        while (p < raw.size()) {
            if (raw[p] == ' ' || raw[p] == '\t' || raw[p] == '\r') { ++p; continue; }
            if (raw[p] != '"') {
                error = "inc line " + std::to_string(lineno) + ": not a string literal";
                return false;
            }
            ++p;
            bool closed = false;
            while (p < raw.size()) {
                const char c = raw[p++];
                if (c == '"') { closed = true; break; }
                if (c == '\\') {
                    if (p >= raw.size()) break;
                    const char e = raw[p++];
                    if (e == 'n') text.push_back('\n');
                    else if (e == 't') text.push_back('\t');
                    else if (e == '\\') text.push_back('\\');
                    else if (e == '"') text.push_back('"');
                    else {
                        error = "inc line " + std::to_string(lineno) + ": unsupported escape";
                        return false;
                    }
                } else {
                    text.push_back(c);
                }
            }
            if (!closed) {
                error = "inc line " + std::to_string(lineno) + ": unterminated literal";
                return false;
            }
        }
    }
    return true;
}

} // namespace

std::string bytes_to_hex(const unsigned char* p, size_t n)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(kHex[p[i] >> 4]);
        out.push_back(kHex[p[i] & 0x0f]);
    }
    return out;
}

bool parse_hash_hex(const std::string& hex, uint256& out)
{
    std::string lower = hex;
    for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (!is_lower_hex(lower, 64)) return false;
    uint256 v;
    v.SetHex(lower);
    if (v.GetHex() != lower) return false;
    out = v;
    return true;
}

// ─── Reader ─────────────────────────────────────────────────────────────────

SnapshotReader::SnapshotReader(std::vector<std::string> part_paths, size_t buffer_bytes)
    : m_paths(std::move(part_paths)), m_buf(std::max<size_t>(buffer_bytes, 4096))
{
}

SnapshotReader::~SnapshotReader()
{
    if (m_file) std::fclose(m_file);
}

bool SnapshotReader::refuse(const char* name, std::string detail)
{
    if (m_refusal.empty()) {
        m_refusal = name;
        m_detail = std::move(detail);
    }
    return false;
}

void SnapshotReader::close_part()
{
    SnapshotPartDigest d;
    d.path = m_paths[m_part_index];
    d.bytes = m_part_bytes;
    d.sha256 = finalize_hex(m_part_sha);
    m_parts.push_back(std::move(d));
    if (m_file) std::fclose(m_file);
    m_file = nullptr;
}

bool SnapshotReader::open()
{
    if (m_paths.empty())
        return refuse(snapshot_refusal::kOpenFailed, "no snapshot file given");
    m_part_index = 0;
    m_file = std::fopen(m_paths[0].c_str(), "rb");
    if (!m_file)
        return refuse(snapshot_refusal::kOpenFailed, m_paths[0] + ": " + std::strerror(errno));
    m_part_sha.Reset();
    m_part_bytes = 0;
    unsigned char md[SNAPSHOT_METADATA_SIZE];
    if (!read(md, sizeof(md))) {
        if (!refused())
            refuse(snapshot_refusal::kTruncated, "the file ends inside the 40-byte metadata");
        return false;
    }
    std::memcpy(m_meta.base_blockhash.data(), md, 32);
    m_meta.coins_count = ReadLE64(md + 32);
    return true;
}

bool SnapshotReader::fill()
{
    while (true) {
        if (m_eof_all || refused() || !m_file)
            return false;
        const size_t n = std::fread(m_buf.data(), 1, m_buf.size(), m_file);
        if (n > 0) {
            m_part_sha.Write(m_buf.data(), n);
            m_part_bytes += n;
            m_total_bytes += n;
            m_pos = 0;
            m_len = n;
            return true;
        }
        if (std::ferror(m_file))
            return refuse(snapshot_refusal::kOpenFailed, m_paths[m_part_index] + ": read error");
        close_part();
        if (++m_part_index >= m_paths.size()) {
            m_eof_all = true;
            return false;
        }
        m_file = std::fopen(m_paths[m_part_index].c_str(), "rb");
        if (!m_file)
            return refuse(snapshot_refusal::kOpenFailed,
                          m_paths[m_part_index] + ": " + std::strerror(errno));
        m_part_sha.Reset();
        m_part_bytes = 0;
    }
}

bool SnapshotReader::read(unsigned char* dst, size_t n)
{
    while (n > 0) {
        if (m_pos == m_len && !fill())
            return false;
        const size_t take = std::min(n, m_len - m_pos);
        std::memcpy(dst, m_buf.data() + m_pos, take);
        m_pos += take;
        dst += take;
        n -= take;
    }
    return true;
}

bool SnapshotReader::skip(size_t n)
{
    while (n > 0) {
        if (m_pos == m_len && !fill())
            return false;
        const size_t take = std::min(n, m_len - m_pos);
        m_pos += take;
        n -= take;
    }
    return true;
}

bool SnapshotReader::next(Outpoint& outpoint, Coin& coin)
{
    if (refused() || m_coins >= m_meta.coins_count)
        return false;
    auto where = [this]() {
        return "coin " + std::to_string(m_coins) + " of " + std::to_string(m_meta.coins_count);
    };
    unsigned char key[36];
    if (!read(key, sizeof(key))) {
        if (!refused())
            refuse(snapshot_refusal::kTruncated, where() + ": the file ends inside the outpoint");
        return false;
    }
    std::memcpy(outpoint.txid.data(), key, 32);
    outpoint.index = ReadLE32(key + 32);

    const CodecStatus st = UnserializeCoreCoin(*this, coin);
    if (refused())
        return false;
    switch (st) {
    case CodecStatus::ok:
        break;
    case CodecStatus::truncated:
        return refuse(snapshot_refusal::kTruncated, where() + " (" + outpoint_str(outpoint) + "): the file ends inside the coin");
    case CodecStatus::oversized_script:
        return refuse(snapshot_refusal::kUnspendable, where() + " (" + outpoint_str(outpoint) + "): script larger than MAX_SCRIPT_SIZE");
    default:
        return refuse(snapshot_refusal::kBadCoin, where() + " (" + outpoint_str(outpoint) + "): " + codec_status_name(st));
    }
    if (IsUnspendableScript(coin.scriptPubKey.m_data))
        return refuse(snapshot_refusal::kUnspendable, where() + " (" + outpoint_str(outpoint) + "): OP_RETURN script");
    if (m_have_prev && cmp_outpoint(outpoint, m_prev) <= 0)
        return refuse(snapshot_refusal::kUnordered, where() + ": " + outpoint_str(outpoint) +
                                                       " does not follow " + outpoint_str(m_prev));
    m_prev = outpoint;
    m_have_prev = true;
    ++m_coins;
    return true;
}

bool SnapshotReader::finish()
{
    if (refused())
        return false;
    if (m_coins != m_meta.coins_count)
        return refuse(snapshot_refusal::kTruncated, "finish() after " + std::to_string(m_coins) +
                                                        " of " + std::to_string(m_meta.coins_count) + " coins");
    unsigned char extra;
    if (read(&extra, 1))
        return refuse(snapshot_refusal::kOverrun, "bytes follow coin " + std::to_string(m_coins) +
                                                      " (coins_count " + std::to_string(m_meta.coins_count) + ")");
    return !refused();
}

// ─── Writer ─────────────────────────────────────────────────────────────────

SnapshotWriter::SnapshotWriter(std::string path)
    : m_path(std::move(path)), m_tmp_path(m_path + ".incomplete")
{
    m_buf.reserve(256);
}

SnapshotWriter::~SnapshotWriter()
{
    if (m_file) std::fclose(m_file);
    if (!m_finished) {
        std::error_code ec;
        std::filesystem::remove(m_tmp_path, ec);
    }
}

bool SnapshotWriter::refuse(const char* name, std::string detail)
{
    if (m_refusal.empty()) {
        m_refusal = name;
        m_detail = std::move(detail);
    }
    return false;
}

bool SnapshotWriter::write(const unsigned char* p, size_t n)
{
    if (std::fwrite(p, 1, n, m_file) != n)
        return refuse(snapshot_refusal::kWriteFailed, m_tmp_path + ": " + std::strerror(errno));
    m_sha.Write(p, n);
    m_bytes += n;
    return true;
}

bool SnapshotWriter::begin(const SnapshotMetadata& meta)
{
    if (!m_refusal.empty()) return false;
    m_file = std::fopen(m_tmp_path.c_str(), "wb");
    if (!m_file)
        return refuse(snapshot_refusal::kWriteFailed, m_tmp_path + ": " + std::strerror(errno));
    m_meta = meta;
    unsigned char md[SNAPSHOT_METADATA_SIZE];
    std::memcpy(md, meta.base_blockhash.data(), 32);
    WriteLE64(md + 32, meta.coins_count);
    return write(md, sizeof(md));
}

bool SnapshotWriter::append(const Outpoint& outpoint, const Coin& coin)
{
    if (!m_refusal.empty() || !m_file) return false;
    if (m_coins >= m_meta.coins_count)
        return refuse(snapshot_refusal::kOverrun, "more coins than coins_count " + std::to_string(m_meta.coins_count));
    if (IsUnspendableScript(coin.scriptPubKey.m_data))
        return refuse(snapshot_refusal::kUnspendable, outpoint_str(outpoint));
    if (coin.height >= (uint32_t{1} << 31) || coin.value < 0)
        return refuse(snapshot_refusal::kBadCoin, outpoint_str(outpoint) + ": height or value out of range");
    if (m_have_prev && cmp_outpoint(outpoint, m_prev) <= 0)
        return refuse(snapshot_refusal::kUnordered, outpoint_str(outpoint) + " does not follow " + outpoint_str(m_prev));
    m_buf.clear();
    m_buf.insert(m_buf.end(), outpoint.txid.data(), outpoint.txid.data() + 32);
    for (int i = 0; i < 4; ++i) m_buf.push_back(static_cast<unsigned char>(outpoint.index >> (8 * i)));
    SerializeCoreCoin(m_buf, coin);
    if (!write(m_buf.data(), m_buf.size())) return false;
    m_prev = outpoint;
    m_have_prev = true;
    ++m_coins;
    return true;
}

bool SnapshotWriter::finish()
{
    if (!m_refusal.empty() || !m_file) return false;
    if (m_coins != m_meta.coins_count)
        return refuse(snapshot_refusal::kCountMismatch, "wrote " + std::to_string(m_coins) + " of coins_count " +
                                                            std::to_string(m_meta.coins_count));
    if (std::fflush(m_file) != 0)
        return refuse(snapshot_refusal::kWriteFailed, m_tmp_path + ": flush failed");
#if !defined(_WIN32)
    if (::fsync(fileno(m_file)) != 0)
        return refuse(snapshot_refusal::kWriteFailed, m_tmp_path + ": fsync failed");
#endif
    const int rc = std::fclose(m_file);
    m_file = nullptr;
    if (rc != 0)
        return refuse(snapshot_refusal::kWriteFailed, m_tmp_path + ": close failed");
    std::error_code ec;
    std::filesystem::rename(m_tmp_path, m_path, ec);
    if (ec)
        return refuse(snapshot_refusal::kWriteFailed, "rename to " + m_path + ": " + ec.message());
    m_sha256 = finalize_hex(m_sha);
    m_finished = true;
    return true;
}

// ─── Pin ────────────────────────────────────────────────────────────────────

std::string snapshot_pin_digest(const std::string& text)
{
    std::string domain;
    domain.reserve(text.size());
    std::istringstream in(text);
    std::string raw;
    while (std::getline(in, raw)) {
        const std::string line = rstrip(raw);
        if (!in_digest_domain(line)) continue;
        domain += line;
        domain += '\n';
    }
    CSHA256 sha;
    sha.Write(reinterpret_cast<const unsigned char*>(domain.data()), domain.size());
    return finalize_hex(sha);
}

std::optional<SnapshotPin> parse_snapshot_pin(const std::string& input, std::string& error)
{
    std::string text;
    if (looks_like_inc(input)) {
        if (!inc_to_text(input, text, error)) return std::nullopt;
    } else {
        text = input;
    }

    auto fail = [&](const std::string& why) -> std::optional<SnapshotPin> {
        error = why;
        return std::nullopt;
    };

    SnapshotPin pin;
    pin.format.clear();
    bool seen_magic = false;
    std::map<std::string, int> seen;
    uint64_t parts_declared = 0;
    bool have_parts = false;
    std::string digest;

    std::istringstream in(text);
    std::string raw;
    size_t lineno = 0;
    while (std::getline(in, raw)) {
        ++lineno;
        const std::string line = rstrip(raw);
        if (line.empty() || line[0] == '#') continue;
        const std::string at = "line " + std::to_string(lineno) + ": ";
        if (!seen_magic) {
            if (line != kSnapshotPinMagic) return fail(at + "magic '" + kSnapshotPinMagic + "' expected");
            seen_magic = true;
            continue;
        }
        std::string key, val;
        split_kv(line, key, val);
        if (key != "part" && seen[key]++ > 0) return fail(at + "duplicate '" + key + "'");
        if (key == "network") {
            if (!is_token(val)) return fail(at + "bad network");
            pin.network = val;
        } else if (key == "coin") {
            if (!is_token(val)) return fail(at + "bad coin");
            pin.coin = val;
        } else if (key == "height") {
            uint64_t h;
            if (!parse_u64(val, h) || h > 0x7fffffffULL) return fail(at + "bad height");
            pin.height = static_cast<uint32_t>(h);
        } else if (key == "blockhash") {
            if (!is_lower_hex(val, 64) || !parse_hash_hex(val, pin.blockhash)) return fail(at + "bad blockhash");
        } else if (key == "coins") {
            if (!parse_u64(val, pin.coins)) return fail(at + "bad coins");
        } else if (key == "muhash") {
            if (!is_lower_hex(val, 64) || !parse_hash_hex(val, pin.muhash)) return fail(at + "bad muhash");
        } else if (key == "hash_serialized_2") {
            uint256 h;
            if (!is_lower_hex(val, 64) || !parse_hash_hex(val, h)) return fail(at + "bad hash_serialized_2");
            pin.hash_serialized_2 = h;
        } else if (key == "format") {
            if (val != kSnapshotFormat) return fail(at + "unsupported format '" + val + "'");
            pin.format = val;
        } else if (key == "parts") {
            if (!parse_u64(val, parts_declared) || parts_declared == 0 || parts_declared > 1000)
                return fail(at + "bad parts");
            have_parts = true;
        } else if (key == "part") {
            if (!have_parts) return fail(at + "'part' before 'parts'");
            std::istringstream ps(val);
            std::string idx, size, sha, extra;
            ps >> idx >> size >> sha;
            if (ps >> extra) return fail(at + "bad part line");
            uint64_t i, sz;
            if (!parse_u64(idx, i) || i != pin.parts.size()) return fail(at + "part index out of order");
            if (!parse_u64(size, sz) || !is_lower_hex(sha, 64)) return fail(at + "bad part size or sha256");
            pin.parts.push_back({sz, sha});
        } else if (key == "url") {
            if (val.empty()) return fail(at + "empty url");
            pin.url = val;
        } else if (key == "sources") {
            if (val.empty()) return fail(at + "empty sources");
            pin.sources = val;
        } else if (key == "generated") {
            if (val.empty()) return fail(at + "empty generated");
            pin.generated = val;
        } else if (key == "digest") {
            if (!is_lower_hex(val, 64)) return fail(at + "bad digest");
            digest = val;
        } else {
            return fail(at + "unknown key '" + key + "'");
        }
    }
    if (!seen_magic) return fail("empty pin");
    for (const char* req : {"network", "coin", "height", "blockhash", "coins", "muhash", "format", "parts", "digest"})
        if (!seen.count(req)) return fail(std::string("missing '") + req + "'");
    if (pin.parts.size() != parts_declared)
        return fail("parts " + std::to_string(parts_declared) + " declared, " + std::to_string(pin.parts.size()) + " listed");
    const std::string want = snapshot_pin_digest(text);
    if (digest != want)
        return fail("digest mismatch: the pin says " + digest + ", its lines hash to " + want);
    return pin;
}

std::string render_snapshot_pin(const SnapshotPin& pin)
{
    std::ostringstream o;
    o << kSnapshotPinMagic << "\n";
    o << "network " << pin.network << "\n";
    o << "coin " << pin.coin << "\n";
    o << "height " << pin.height << "\n";
    o << "blockhash " << pin.blockhash.GetHex() << "\n";
    o << "coins " << pin.coins << "\n";
    o << "muhash " << pin.muhash.GetHex() << "\n";
    if (pin.hash_serialized_2)
        o << "hash_serialized_2 " << pin.hash_serialized_2->GetHex() << "\n";
    o << "format " << (pin.format.empty() ? std::string(kSnapshotFormat) : pin.format) << "\n";
    o << "parts " << pin.parts.size() << "\n";
    for (size_t i = 0; i < pin.parts.size(); ++i)
        o << "part " << i << " " << pin.parts[i].size << " " << pin.parts[i].sha256 << "\n";
    if (!pin.url.empty()) o << "url " << pin.url << "\n";
    if (!pin.sources.empty()) o << "sources " << pin.sources << "\n";
    if (!pin.generated.empty()) o << "generated " << pin.generated << "\n";
    std::string text = o.str();
    text += "digest " + snapshot_pin_digest(text) + "\n";
    return text;
}

std::string render_snapshot_pin_inc(const SnapshotPin& pin)
{
    const std::string text = render_snapshot_pin(pin);
    std::ostringstream o;
    o << "// GENERATED by c2pool-utxo --dump-utxo-snapshot-pin -- DO NOT EDIT BY HAND.\n";
    o << "// The trailing `digest` line commits every other line.\n";
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        std::string esc;
        for (char c : line) {
            if (c == '\\' || c == '"') esc.push_back('\\');
            esc.push_back(c);
        }
        o << "\"" << esc << "\\n\"\n";
    }
    return o.str();
}

// ─── Scan ───────────────────────────────────────────────────────────────────

SnapshotScanResult scan_utxo_snapshot(const std::vector<std::string>& parts, const SnapshotScanOptions& opts)
{
    SnapshotScanResult r;
    SnapshotReader rd(parts);
    if (!rd.open()) {
        r.refusal = rd.refusal();
        r.detail = rd.detail();
        return r;
    }
    r.meta = rd.metadata();
    UtxoSetHasher hasher(r.meta.base_blockhash, opts.hashes);
    Outpoint op;
    Coin coin;
    CompressedScript compr;
    while (rd.next(op, coin)) {
        if (!hasher.add(op, coin)) {
            r.refusal = snapshot_refusal::kUnordered;
            r.detail = hasher.refusal();
            return r;
        }
        compr.clear();
        if (CompressScript(coin.scriptPubKey.m_data, compr) && !compr.empty() && compr[0] < 6)
            ++r.special_scripts[compr[0]];
        else
            ++r.raw_scripts;
        if (opts.log && opts.log_every && rd.coins_read() % opts.log_every == 0)
            opts.log("[UTXO-SNAPSHOT] scan " + std::to_string(rd.coins_read()) + "/" +
                     std::to_string(r.meta.coins_count) + " coins");
    }
    if (rd.refused() || !rd.finish()) {
        r.refusal = rd.refusal();
        r.detail = rd.detail();
        return r;
    }
    auto hashes = hasher.finalize();
    if (!hashes) {
        r.refusal = snapshot_refusal::kUnordered;
        r.detail = hasher.refusal();
        return r;
    }
    r.hashes = *hashes;
    r.parts = rd.parts();
    r.bytes = rd.bytes_read();
    r.ok = true;
    return r;
}

// ─── DB helpers ─────────────────────────────────────────────────────────────

bool leveldb_dir_lock_held(const std::string& dir, long* holder_pid)
{
    if (holder_pid) *holder_pid = 0;
#if defined(_WIN32)
    (void)dir;
    return false;
#else
    const std::string lock = (std::filesystem::path(dir) / "LOCK").string();
    {
        // Our own open DB first: the probe below closes a descriptor of LOCK,
        // which would drop this process's record lock if it held one.
        std::error_code ec;
        const auto want = std::filesystem::weakly_canonical(lock, ec);
        if (!ec && std::filesystem::exists("/proc/self/fd", ec)) {
            for (const auto& ent : std::filesystem::directory_iterator("/proc/self/fd", ec)) {
                std::error_code lec;
                const auto target = std::filesystem::read_symlink(ent.path(), lec);
                if (!lec && target == want) {
                    if (holder_pid) *holder_pid = static_cast<long>(::getpid());
                    return true;
                }
            }
        }
    }
    const int fd = ::open(lock.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;  // no LOCK file: nobody has opened this directory as a DB
    struct flock fl;
    std::memset(&fl, 0, sizeof(fl));
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0;
    const int rc = ::fcntl(fd, F_GETLK, &fl);
    ::close(fd);
    if (rc == -1) {
        if (holder_pid) *holder_pid = -1;
        return true;  // cannot tell: fail closed
    }
    if (fl.l_type == F_UNLCK)
        return false;
    if (holder_pid) *holder_pid = static_cast<long>(fl.l_pid);
    return true;
#endif
}

bool leveldb_store_empty(core::LevelDBStore& store)
{
    bool empty = true;
    const bool ok = store.for_each_prefix(std::string(), [&](const std::string&, const std::vector<uint8_t>&) {
        empty = false;
        return false;
    });
    return ok && empty;
}

bool leveldb_wipe_all(core::LevelDBStore& store, size_t batch_records)
{
    if (batch_records == 0) batch_records = 16384;
    std::optional<core::LevelDBStore::BatchWriter> batch;
    batch.emplace(&store);
    size_t n = 0;
    bool ok = true;
    const bool scan = store.for_each_prefix(std::string(), [&](const std::string& key, const std::vector<uint8_t>&) {
        batch->remove(key);
        if (++n == batch_records) {
            if (!batch->commit()) {
                ok = false;
                return false;
            }
            batch.emplace(&store);
            n = 0;
        }
        return true;
    });
    if (ok && n > 0) ok = batch->commit();
    store.compact();
    return scan && ok && leveldb_store_empty(store);
}

// ─── Import ─────────────────────────────────────────────────────────────────

SnapshotImportResult import_utxo_snapshot(const std::vector<std::string>& parts,
                                          const std::string& db_path,
                                          const SnapshotPin& pin,
                                          const SnapshotImportOptions& opts)
{
    namespace R = snapshot_refusal;
    SnapshotImportResult r;
    auto log = [&](const std::string& line) {
        if (opts.log) opts.log(line);
    };
    auto fail = [&](const std::string& name, const std::string& detail) {
        r.ok = false;
        r.refusal = name;
        r.detail = detail;
        log("[UTXO-SNAPSHOT] REFUSED " + name + ": " + detail);
        return r;
    };

    if (pin.muhash.IsNull() || pin.blockhash.IsNull())
        return fail(R::kNoPin, "a snapshot is loaded only against a pin with blockhash and muhash");
    if (!opts.hash_at_height && !opts.offline_no_header_chain)
        return fail(R::kNoHeaderChain, "no header chain to place the base in");
    if (!pin.parts.empty() && pin.parts.size() != parts.size())
        return fail(R::kSha256Mismatch, "the pin lists " + std::to_string(pin.parts.size()) + " parts, " +
                                            std::to_string(parts.size()) + " files given");

    long holder = 0;
    if (leveldb_dir_lock_held(db_path, &holder))
        return fail(R::kDbHeld, db_path + " is held by pid " + std::to_string(holder));
    core::LevelDBStore store(db_path, opts.db_options);
    if (!store.open())
        return fail(R::kDbOpenFailed, db_path);
    if (!leveldb_store_empty(store))
        return fail(R::kDbNotEmpty, db_path + " already holds records; import into a fresh directory");

    // ── Verify pass: nothing is written. ────────────────────────────────────
    const auto t0 = Clock::now();
    SnapshotReader rd(parts);
    if (!rd.open())
        return fail(rd.refusal(), rd.detail());
    const SnapshotMetadata meta = rd.metadata();
    r.base_blockhash = meta.base_blockhash;
    if (meta.base_blockhash != pin.blockhash)
        return fail(R::kBaseMismatch, "file base " + meta.base_blockhash.GetHex() + ", pin " + pin.blockhash.GetHex());
    if (meta.coins_count != pin.coins)
        return fail(R::kCountMismatch, "file coins_count " + std::to_string(meta.coins_count) + ", pin " +
                                           std::to_string(pin.coins));
    if (opts.hash_at_height) {
        const auto h = opts.hash_at_height(pin.height);
        if (!h || *h != meta.base_blockhash)
            return fail(R::kNotInHeaderChain, "header at " + std::to_string(pin.height) + " is " +
                                                  (h ? h->GetHex() : std::string("absent")) + ", base " +
                                                  meta.base_blockhash.GetHex());
    } else {
        log("[UTXO-SNAPSHOT] base-in-header-chain: NOT checked (offline, no header chain); the node checks at open");
    }

    UtxoSetHasher hasher(meta.base_blockhash);
    Outpoint op;
    Coin coin;
    while (rd.next(op, coin)) {
        if (opts.refuse_spent_shaped_coins && coin.value == 0 && coin.scriptPubKey.m_data.empty())
            return fail(R::kSpentShapedCoin, "coin " + outpoint_str(op) +
                                                 " has value 0 and an empty script (Coin::is_spent() reads it as absent)");
        if (!hasher.add(op, coin))
            return fail(R::kUnordered, hasher.refusal());
        if (opts.log_every && rd.coins_read() % opts.log_every == 0)
            log("[UTXO-SNAPSHOT] verify " + std::to_string(rd.coins_read()) + "/" + std::to_string(meta.coins_count) +
                " coins " + std::to_string(static_cast<long>(seconds_since(t0))) + " s");
    }
    if (rd.refused() || !rd.finish())
        return fail(rd.refusal(), rd.detail());
    const std::vector<SnapshotPartDigest> digests = rd.parts();
    r.parts = digests;
    for (size_t i = 0; i < pin.parts.size(); ++i) {
        if (digests[i].bytes != pin.parts[i].size || digests[i].sha256 != pin.parts[i].sha256)
            return fail(R::kSha256Mismatch, "part " + std::to_string(i) + " (" + digests[i].path + "): " +
                                                std::to_string(digests[i].bytes) + " B sha256 " + digests[i].sha256 +
                                                ", pin " + std::to_string(pin.parts[i].size) + " B sha256 " +
                                                pin.parts[i].sha256);
    }
    auto hashes = hasher.finalize();
    if (!hashes)
        return fail(R::kUnordered, hasher.refusal());
    r.hashes = *hashes;
    r.coins = hashes->coins;
    if (hashes->muhash != pin.muhash)
        return fail(R::kMuhashMismatch, "muhash " + hashes->muhash.GetHex() + ", pin " + pin.muhash.GetHex());
    if (pin.hash_serialized_2 && hashes->hash_serialized_2 != *pin.hash_serialized_2)
        return fail(R::kHashSer2Mismatch, "hash_serialized_2 " + hashes->hash_serialized_2.GetHex() + ", pin " +
                                              pin.hash_serialized_2->GetHex());
    r.verify_seconds = seconds_since(t0);
    log("[UTXO-SNAPSHOT] verified coins=" + std::to_string(r.coins) + " muhash=" + hashes->muhash.GetHex() +
        " hash_serialized_2=" + hashes->hash_serialized_2.GetHex() + " in " +
        std::to_string(static_cast<long>(r.verify_seconds)) + " s");

    // ── Write pass. Any failure from here wipes every key. ──────────────────
    const auto t1 = Clock::now();
    auto abort_wipe = [&](const std::string& name, const std::string& detail) {
        const bool wiped = leveldb_wipe_all(store, opts.batch_records);
        return fail(name, detail + (wiped ? "; the DB was wiped back to empty"
                                          : "; WIPE FAILED: the DB is not empty, delete " + db_path));
    };
    SnapshotReader rd2(parts);
    if (!rd2.open())
        return abort_wipe(R::kChangedDuringImport, rd2.refusal() + ": " + rd2.detail());
    if (rd2.metadata().base_blockhash != meta.base_blockhash || rd2.metadata().coins_count != meta.coins_count)
        return abort_wipe(R::kChangedDuringImport, "metadata changed between the passes");
    const size_t batch_records = opts.batch_records ? opts.batch_records : 16384;
    std::optional<core::LevelDBStore::BatchWriter> batch;
    batch.emplace(&store);
    size_t in_batch = 0;
    uint64_t committed = 0;
    auto commit = [&]() -> bool {
        if (in_batch == 0) return true;
        if (!batch->commit()) return false;
        committed += in_batch;
        in_batch = 0;
        batch.emplace(&store);
        return true;
    };
    while (rd2.next(op, coin)) {
        coin.pegout = false;
        batch->put(view_db_coin_key(op), serialize_coin(coin));
        if (++in_batch == batch_records) {
            if (!commit())
                return abort_wipe(R::kDbWriteFailed, "batch commit after " + std::to_string(committed) + " coins");
            if (opts.test_fail_write_after && committed >= opts.test_fail_write_after)
                return abort_wipe(R::kDbWriteFailed, "test fault after " + std::to_string(committed) + " coins");
        }
        if (opts.log_every && rd2.coins_read() % opts.log_every == 0)
            log("[UTXO-SNAPSHOT] write " + std::to_string(rd2.coins_read()) + "/" + std::to_string(meta.coins_count) +
                " coins " + std::to_string(static_cast<long>(seconds_since(t1))) + " s");
    }
    if (rd2.refused() || !rd2.finish())
        return abort_wipe(R::kChangedDuringImport, rd2.refusal() + ": " + rd2.detail());
    if (!commit())
        return abort_wipe(R::kDbWriteFailed, "final coin batch");
    if (opts.test_fail_write_after && committed >= opts.test_fail_write_after)
        return abort_wipe(R::kDbWriteFailed, "test fault after " + std::to_string(committed) + " coins");
    const auto& digests2 = rd2.parts();
    if (digests2.size() != digests.size())
        return abort_wipe(R::kChangedDuringImport, "part count changed between the passes");
    for (size_t i = 0; i < digests.size(); ++i)
        if (digests2[i].bytes != digests[i].bytes || digests2[i].sha256 != digests[i].sha256)
            return abort_wipe(R::kChangedDuringImport, "part " + std::to_string(i) + " changed between the passes");
    if (committed != r.coins)
        return abort_wipe(R::kChangedDuringImport, "wrote " + std::to_string(committed) + " coins, verified " +
                                                       std::to_string(r.coins));

    // The best block goes in last, synced: a DB without 'B' is not a set.
    {
        core::LevelDBStore::BatchWriter fb(&store);
        fb.put(std::string(1, 'B'), encode_view_db_best(meta.base_blockhash, pin.height));
        for (const auto& [key, value] : opts.final_records)
            fb.put(key, value);
        if (!fb.commit_sync())
            return abort_wipe(R::kDbWriteFailed, "best block record");
    }
    r.best_height = pin.height;
    r.write_seconds = seconds_since(t1);
    r.ok = true;
    log("[UTXO-SNAPSHOT] imported coins=" + std::to_string(r.coins) + " height=" + std::to_string(pin.height) +
        " muhash=" + r.hashes.muhash.GetHex() + " hash_serialized_2=" + r.hashes.hash_serialized_2.GetHex() + " in " +
        std::to_string(static_cast<long>(seconds_since(t0))) + " s");
    store.close();
    return r;
}

// ─── Dump ───────────────────────────────────────────────────────────────────

SnapshotDumpResult dump_utxo_snapshot(core::LevelDBStore& store, const std::string& out_path)
{
    namespace R = snapshot_refusal;
    SnapshotDumpResult r;
    auto fail = [&](const std::string& name, const std::string& detail) {
        r.ok = false;
        r.refusal = name;
        r.detail = detail;
        return r;
    };
    std::vector<uint8_t> best;
    if (!store.get(std::string(1, 'B'), best) || !decode_view_db_best(best, r.base_blockhash, r.base_height))
        return fail(R::kDbNoBest, "no best block record");
    if (r.base_blockhash.IsNull())
        return fail(R::kDbNoBest, "best block is null");

    uint64_t count = 0;
    bool bad_key = false;
    if (!store.for_each_prefix(std::string(1, 'C'), [&](const std::string& key, const std::vector<uint8_t>&) {
            if (key.size() != 37) {
                bad_key = true;
                return false;
            }
            ++count;
            return true;
        }) || bad_key)
        return fail(R::kDbCorrupt, "coin key scan");

    SnapshotWriter w(out_path);
    if (!w.begin(SnapshotMetadata{r.base_blockhash, count}))
        return fail(w.refusal(), w.detail());
    UtxoSetHasher hasher(r.base_blockhash);
    std::map<uint32_t, Coin> group;
    uint256 group_txid;
    bool have_group = false;
    std::string bad;
    auto flush = [&]() -> bool {
        for (auto& [n, c] : group) {
            const Outpoint op(group_txid, n);
            if (!w.append(op, c)) {
                bad = w.refusal() + ": " + w.detail();
                return false;
            }
            if (!hasher.add(op, c)) {
                bad = hasher.refusal();
                return false;
            }
        }
        group.clear();
        return true;
    };
    const bool scan_ok = store.for_each_prefix(std::string(1, 'C'), [&](const std::string& key, const std::vector<uint8_t>& value) {
        if (key.size() != 37) {
            bad = std::string(R::kDbCorrupt) + ": coin key";
            return false;
        }
        const Outpoint op = key_to_outpoint(key.substr(1));
        Coin c;
        if (!decode_view_db_coin(value, c)) {
            bad = std::string(R::kDbCorrupt) + ": coin " + outpoint_str(op);
            return false;
        }
        if (have_group && op.txid != group_txid && !flush())
            return false;
        group_txid = op.txid;
        have_group = true;
        group[op.index] = std::move(c);
        return true;
    });
    if (!scan_ok)
        return fail(R::kDbCorrupt, "coin scan failed");
    if (!bad.empty())
        return fail(R::kWriteFailed, bad);
    if (have_group && !flush())
        return fail(R::kWriteFailed, bad);
    if (w.coins() != count)
        return fail(R::kCountChanged, "counted " + std::to_string(count) + ", wrote " + std::to_string(w.coins()));
    if (!w.finish())
        return fail(w.refusal(), w.detail());
    auto hashes = hasher.finalize();
    if (!hashes)
        return fail(R::kUnordered, hasher.refusal());
    r.hashes = *hashes;
    r.coins = w.coins();
    r.sha256 = w.sha256_hex();
    r.bytes = w.bytes();
    r.ok = true;
    return r;
}

} // namespace core::coin
