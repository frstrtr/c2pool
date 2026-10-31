#include "utxo_tools.hpp"

#include <core/coin/utxo_set_hash.hpp>
#include <core/coin/utxo_snapshot.hpp>
#include <core/leveldb_store.hpp>

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>

namespace core {

namespace {

using namespace core::coin;

constexpr int kExitOk = 0;
constexpr int kExitRefused = 1;
constexpr int kExitUsage = 2;

struct Args {
    std::map<std::string, std::vector<std::string>> values;   // flag -> positional values after it
    std::set<std::string> flags;
    std::string command;

    bool has(const std::string& f) const { return flags.count(f) || values.count(f); }
    std::optional<std::string> get(const std::string& f, size_t i = 0) const
    {
        auto it = values.find(f);
        if (it == values.end() || it->second.size() <= i) return std::nullopt;
        return it->second[i];
    }
};

const std::set<std::string> kCommands = {
    "--utxo-inspect", "--utxo-import", "--utxo-hash", "--utxo-dump", "--dump-utxo-snapshot-pin",
};

/// Flags that take N values.
const std::map<std::string, size_t> kValueFlags = {
    {"--utxo-inspect", 1}, {"--utxo-import", 1}, {"--utxo-hash", 1}, {"--utxo-dump", 2},
    {"--dump-utxo-snapshot-pin", 1}, {"--utxo-db", 1}, {"--utxo-snapshot-pin", 1},
    {"--expect-coins", 1}, {"--expect-base", 1}, {"--expect-muhash", 1},
    {"--expect-hash-serialized-2", 1}, {"--expect-sha256", 1}, {"--expect-height", 1},
    {"--coin", 1}, {"--network", 1}, {"--height", 1}, {"--url", 1}, {"--sources", 1},
    {"--generated", 1},
};

const std::set<std::string> kBoolFlags = {
    "--no-muhash", "--no-serialized", "--muhash", "--serialized", "--utxo-dump-at-best", "--inc",
};

bool parse_args(const std::vector<std::string>& in, Args& a, std::string& error)
{
    for (size_t i = 0; i < in.size(); ++i) {
        const std::string& f = in[i];
        if (kBoolFlags.count(f)) {
            a.flags.insert(f);
            continue;
        }
        auto vf = kValueFlags.find(f);
        if (vf == kValueFlags.end()) {
            error = "unknown argument '" + f + "'";
            return false;
        }
        if (a.values.count(f)) {
            error = "duplicate '" + f + "'";
            return false;
        }
        std::vector<std::string> vals;
        for (size_t k = 0; k < vf->second; ++k) {
            if (i + 1 >= in.size()) {
                error = f + " needs " + std::to_string(vf->second) + " value(s)";
                return false;
            }
            vals.push_back(in[++i]);
        }
        a.values[f] = vals;
        if (kCommands.count(f)) {
            if (!a.command.empty()) {
                error = "two commands: " + a.command + " and " + f;
                return false;
            }
            a.command = f;
        }
    }
    if (a.command.empty()) {
        error = "no command";
        return false;
    }
    return true;
}

std::vector<std::string> split_parts(const std::string& s)
{
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, ','))
        if (!item.empty()) out.push_back(item);
    return out;
}

bool parse_u64(const std::string& s, uint64_t& v)
{
    if (s.empty() || s.size() > 20) return false;
    for (char c : s)
        if (c < '0' || c > '9') return false;
    try {
        v = std::stoull(s);
    } catch (...) {
        return false;
    }
    return true;
}

std::string utc_now_iso()
{
    const std::time_t t = std::time(nullptr);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

void print_usage(std::ostream& err)
{
    err << "usage:\n"
           "  c2pool-utxo --utxo-inspect FILE[,PART...] [--expect-coins N] [--expect-base HEX]\n"
           "              [--expect-muhash HEX] [--expect-hash-serialized-2 HEX] [--expect-sha256 HEX]\n"
           "              [--no-muhash] [--no-serialized]\n"
           "  c2pool-utxo --utxo-import FILE[,PART...] --utxo-db DIR\n"
           "              (--utxo-snapshot-pin PINFILE | --expect-height H --expect-base HEX\n"
           "               --expect-coins N --expect-muhash HEX [--expect-hash-serialized-2 HEX]\n"
           "               [--expect-sha256 HEX])\n"
           "  c2pool-utxo --utxo-hash DIR [--muhash | --serialized]\n"
           "  c2pool-utxo --utxo-dump DIR FILE --utxo-dump-at-best\n"
           "  c2pool-utxo --dump-utxo-snapshot-pin FILE[,PART...] --coin C --network N --height H\n"
           "              [--url U] [--sources S] [--generated ISO8601] [--inc]\n";
}

/// An existing, unheld LevelDB directory, opened. Never creates one.
std::optional<std::string> open_existing_db(const std::string& dir, core::LevelDBStore& store)
{
    if (!std::filesystem::exists(std::filesystem::path(dir) / "CURRENT"))
        return std::string("utxo-db-absent: ") + dir + " is not a LevelDB directory";
    long holder = 0;
    if (leveldb_dir_lock_held(dir, &holder))
        return std::string(snapshot_refusal::kDbHeld) + ": " + dir + " is held by pid " + std::to_string(holder) +
               "; stop that process first";
    if (!store.open())
        return std::string(snapshot_refusal::kDbOpenFailed) + ": " + dir;
    return std::nullopt;
}

int cmd_inspect(const Args& a, std::ostream& out, std::ostream& err)
{
    const auto parts = split_parts(*a.get("--utxo-inspect"));
    SnapshotScanOptions so;
    so.hashes.muhash = !a.has("--no-muhash");
    so.hashes.hash_serialized_2 = !a.has("--no-serialized");
    so.log_every = 500000;
    so.log = [&](const std::string& l) { err << l << "\n"; };
    const auto t0 = std::chrono::steady_clock::now();
    const SnapshotScanResult r = scan_utxo_snapshot(parts, so);
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (!r.ok) {
        out << "RESULT REFUSED " << r.refusal << ": " << r.detail << "\n";
        return kExitRefused;
    }
    for (const auto& p : r.parts)
        out << "part " << p.path << " bytes " << p.bytes << " sha256 " << p.sha256 << "\n";
    out << "bytes " << r.bytes << "\n";
    out << "base_blockhash " << r.meta.base_blockhash.GetHex() << "\n";
    out << "coins_count " << r.meta.coins_count << "\n";
    out << "coins " << r.hashes.coins << "\n";
    out << "tx_groups " << r.hashes.tx_groups << "\n";
    if (r.hashes.have_muhash) out << "muhash " << r.hashes.muhash.GetHex() << "\n";
    if (r.hashes.have_hash_serialized_2) out << "hash_serialized_2 " << r.hashes.hash_serialized_2.GetHex() << "\n";
    out << "total_amount " << r.hashes.total_amount << "\n";
    out << "zero_value_coins " << r.hashes.zero_value_coins << "\n";
    out << "empty_script_coins " << r.hashes.empty_script_coins << "\n";
    out << "scripts p2pkh " << r.special_scripts[0] << " p2sh " << r.special_scripts[1] << " p2pk02 "
        << r.special_scripts[2] << " p2pk03 " << r.special_scripts[3] << " p2pk04even " << r.special_scripts[4]
        << " p2pk04odd " << r.special_scripts[5] << " raw " << r.raw_scripts << "\n";
    out << "seconds " << static_cast<long>(secs) << "\n";

    bool all_ok = true;
    auto check = [&](const std::string& what, bool ok, const std::string& got, const std::string& want) {
        out << "check " << what << " " << (ok ? "OK" : "MISMATCH") << " got " << got << " want " << want << "\n";
        all_ok = all_ok && ok;
    };
    if (auto v = a.get("--expect-coins")) {
        uint64_t n = 0;
        if (!parse_u64(*v, n)) { err << "bad --expect-coins\n"; return kExitUsage; }
        check("coins", r.hashes.coins == n && r.meta.coins_count == n, std::to_string(r.hashes.coins), *v);
    }
    if (auto v = a.get("--expect-base")) {
        uint256 h;
        if (!parse_hash_hex(*v, h)) { err << "bad --expect-base\n"; return kExitUsage; }
        check("base_blockhash", r.meta.base_blockhash == h, r.meta.base_blockhash.GetHex(), h.GetHex());
    }
    if (auto v = a.get("--expect-muhash")) {
        uint256 h;
        if (!parse_hash_hex(*v, h)) { err << "bad --expect-muhash\n"; return kExitUsage; }
        check("muhash", r.hashes.have_muhash && r.hashes.muhash == h, r.hashes.muhash.GetHex(), h.GetHex());
    }
    if (auto v = a.get("--expect-hash-serialized-2")) {
        uint256 h;
        if (!parse_hash_hex(*v, h)) { err << "bad --expect-hash-serialized-2\n"; return kExitUsage; }
        check("hash_serialized_2", r.hashes.have_hash_serialized_2 && r.hashes.hash_serialized_2 == h,
              r.hashes.hash_serialized_2.GetHex(), h.GetHex());
    }
    if (auto v = a.get("--expect-sha256")) {
        const bool ok = r.parts.size() == 1 && r.parts[0].sha256 == *v;
        check("sha256", ok, r.parts.empty() ? std::string("-") : r.parts[0].sha256, *v);
    }
    out << "RESULT " << (all_ok ? "OK" : "MISMATCH") << "\n";
    return all_ok ? kExitOk : kExitRefused;
}

int cmd_import(const Args& a, std::ostream& out, std::ostream& err)
{
    const auto parts = split_parts(*a.get("--utxo-import"));
    const auto db = a.get("--utxo-db");
    if (!db) {
        err << "--utxo-import needs --utxo-db DIR\n";
        return kExitUsage;
    }
    SnapshotPin pin;
    if (auto pf = a.get("--utxo-snapshot-pin")) {
        std::ifstream f(*pf, std::ios::binary);
        if (!f) {
            err << "cannot read " << *pf << "\n";
            return kExitUsage;
        }
        std::stringstream ss;
        ss << f.rdbuf();
        std::string perr;
        auto parsed = parse_snapshot_pin(ss.str(), perr);
        if (!parsed) {
            out << "RESULT REFUSED utxo-snapshot-pin-invalid: " << perr << "\n";
            return kExitRefused;
        }
        pin = *parsed;
    } else {
        uint64_t height = 0;
        const auto h = a.get("--expect-height");
        const auto b = a.get("--expect-base");
        const auto c = a.get("--expect-coins");
        const auto m = a.get("--expect-muhash");
        if (!h || !b || !c || !m) {
            out << "RESULT REFUSED " << snapshot_refusal::kNoPin
                << ": give --utxo-snapshot-pin, or --expect-height, --expect-base, --expect-coins and --expect-muhash\n";
            return kExitRefused;
        }
        if (!parse_u64(*h, height) || height > 0x7fffffffULL || !parse_hash_hex(*b, pin.blockhash) ||
            !parse_u64(*c, pin.coins) || !parse_hash_hex(*m, pin.muhash)) {
            err << "bad --expect-* value\n";
            return kExitUsage;
        }
        pin.height = static_cast<uint32_t>(height);
        if (auto s = a.get("--expect-hash-serialized-2")) {
            uint256 hs;
            if (!parse_hash_hex(*s, hs)) { err << "bad --expect-hash-serialized-2\n"; return kExitUsage; }
            pin.hash_serialized_2 = hs;
        }
        if (auto s = a.get("--expect-sha256")) {
            if (parts.size() != 1) { err << "--expect-sha256 pins a single-part file\n"; return kExitUsage; }
            std::error_code ec;
            const auto size = std::filesystem::file_size(parts[0], ec);
            if (ec) { out << "RESULT REFUSED " << snapshot_refusal::kOpenFailed << ": " << parts[0] << "\n"; return kExitRefused; }
            pin.parts.push_back({static_cast<uint64_t>(size), *s});
        }
    }
    SnapshotImportOptions opts;
    opts.offline_no_header_chain = true;
    opts.log = [&](const std::string& l) { err << l << "\n"; };
    const SnapshotImportResult r = import_utxo_snapshot(parts, *db, pin, opts);
    if (!r.ok) {
        out << "RESULT REFUSED " << r.refusal << ": " << r.detail << "\n";
        return kExitRefused;
    }
    out << "imported " << r.coins << " coins into " << *db << "\n";
    out << "best_block " << r.base_blockhash.GetHex() << "\n";
    out << "best_height " << r.best_height << "\n";
    out << "muhash " << r.hashes.muhash.GetHex() << "\n";
    out << "hash_serialized_2 " << r.hashes.hash_serialized_2.GetHex() << "\n";
    for (const auto& p : r.parts)
        out << "part " << p.path << " bytes " << p.bytes << " sha256 " << p.sha256 << "\n";
    out << "header_chain_check skipped (offline tool)\n";
    out << "seconds verify " << static_cast<long>(r.verify_seconds) << " write " << static_cast<long>(r.write_seconds) << "\n";
    out << "RESULT OK\n";
    return kExitOk;
}

int cmd_hash(const Args& a, std::ostream& out, std::ostream&)
{
    const std::string dir = *a.get("--utxo-hash");
    UtxoSetHasher::Options ho;
    if (a.has("--muhash") && !a.has("--serialized")) ho.hash_serialized_2 = false;
    if (a.has("--serialized") && !a.has("--muhash")) ho.muhash = false;
    core::LevelDBStore store(dir, core::LevelDBOptions{});
    if (auto why = open_existing_db(dir, store)) {
        out << "RESULT REFUSED " << *why << "\n";
        return kExitRefused;
    }
    std::string refusal;
    const auto t0 = std::chrono::steady_clock::now();
    auto res = hash_utxo_view_db(store, ho, refusal);
    const double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    store.close();
    if (!res) {
        out << "RESULT REFUSED " << refusal << "\n";
        return kExitRefused;
    }
    out << "best_block " << res->hashes.best_block.GetHex() << "\n";
    out << "best_height " << res->best_height << "\n";
    out << "coins " << res->hashes.coins << "\n";
    out << "tx_groups " << res->hashes.tx_groups << "\n";
    if (res->hashes.have_muhash) out << "muhash " << res->hashes.muhash.GetHex() << "\n";
    if (res->hashes.have_hash_serialized_2) out << "hash_serialized_2 " << res->hashes.hash_serialized_2.GetHex() << "\n";
    out << "seconds " << static_cast<long>(secs) << "\n";
    out << "RESULT OK\n";
    return kExitOk;
}

int cmd_dump(const Args& a, std::ostream& out, std::ostream& err)
{
    const std::string dir = *a.get("--utxo-dump", 0);
    const std::string file = *a.get("--utxo-dump", 1);
    if (!a.has("--utxo-dump-at-best")) {
        err << "--utxo-dump writes the DB's best block; an offline dump needs --utxo-dump-at-best\n";
        return kExitUsage;
    }
    core::LevelDBStore store(dir, core::LevelDBOptions{});
    if (auto why = open_existing_db(dir, store)) {
        out << "RESULT REFUSED " << *why << "\n";
        return kExitRefused;
    }
    const SnapshotDumpResult r = dump_utxo_snapshot(store, file);
    store.close();
    if (!r.ok) {
        out << "RESULT REFUSED " << r.refusal << ": " << r.detail << "\n";
        return kExitRefused;
    }
    out << "coins " << r.coins << "\n";
    out << "base_hash " << r.base_blockhash.GetHex() << "\n";
    out << "base_height " << r.base_height << "\n";
    out << "muhash " << r.hashes.muhash.GetHex() << "\n";
    out << "hash_serialized_2 " << r.hashes.hash_serialized_2.GetHex() << "\n";
    out << "sha256 " << r.sha256 << "\n";
    out << "bytes " << r.bytes << "\n";
    out << "RESULT OK\n";
    return kExitOk;
}

int cmd_pin(const Args& a, std::ostream& out, std::ostream& err)
{
    const auto parts = split_parts(*a.get("--dump-utxo-snapshot-pin"));
    const auto coin = a.get("--coin");
    const auto network = a.get("--network");
    const auto height = a.get("--height");
    uint64_t h = 0;
    if (!coin || !network || !height || !parse_u64(*height, h) || h > 0x7fffffffULL) {
        err << "--dump-utxo-snapshot-pin needs --coin, --network and --height\n";
        return kExitUsage;
    }
    SnapshotScanOptions so;
    so.log_every = 500000;
    so.log = [&](const std::string& l) { err << l << "\n"; };
    const SnapshotScanResult r = scan_utxo_snapshot(parts, so);
    if (!r.ok) {
        out << "RESULT REFUSED " << r.refusal << ": " << r.detail << "\n";
        return kExitRefused;
    }
    SnapshotPin pin;
    pin.coin = *coin;
    pin.network = *network;
    pin.height = static_cast<uint32_t>(h);
    pin.blockhash = r.meta.base_blockhash;
    pin.coins = r.hashes.coins;
    pin.muhash = r.hashes.muhash;
    pin.hash_serialized_2 = r.hashes.hash_serialized_2;
    for (const auto& p : r.parts) pin.parts.push_back({p.bytes, p.sha256});
    pin.url = a.get("--url").value_or("");
    pin.sources = a.get("--sources").value_or("");
    pin.generated = a.get("--generated").value_or(utc_now_iso());
    std::string perr;
    const std::string text = render_snapshot_pin(pin);
    if (!parse_snapshot_pin(text, perr)) {
        out << "RESULT REFUSED utxo-snapshot-pin-invalid: " << perr << "\n";
        return kExitRefused;
    }
    out << (a.has("--inc") ? render_snapshot_pin_inc(pin) : text);
    return kExitOk;
}

} // namespace

int run_utxo_tool(const std::vector<std::string>& args, std::ostream& out, std::ostream& err)
{
    Args a;
    std::string error;
    if (!parse_args(args, a, error)) {
        err << "c2pool-utxo: " << error << "\n";
        print_usage(err);
        return kExitUsage;
    }
    if (a.command == "--utxo-inspect") return cmd_inspect(a, out, err);
    if (a.command == "--utxo-import") return cmd_import(a, out, err);
    if (a.command == "--utxo-hash") return cmd_hash(a, out, err);
    if (a.command == "--utxo-dump") return cmd_dump(a, out, err);
    if (a.command == "--dump-utxo-snapshot-pin") return cmd_pin(a, out, err);
    print_usage(err);
    return kExitUsage;
}

} // namespace core
