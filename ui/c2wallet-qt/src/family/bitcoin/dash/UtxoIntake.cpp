// SPDX-License-Identifier: AGPL-3.0-or-later
#include "UtxoIntake.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"
#include "InjectMaturity.hpp"

// Reused M1-A hdkeys leaf helpers (btclibs closure). NO dashscript headers.
#include "../hdkeys/HexUtil.hpp"
#include "../hdkeys/MiniJson.hpp"

#include <algorithm>
#include <cmath>
#include <optional>
#include <set>
#include <utility>

namespace c2w::dash {

namespace {

namespace mjson = hdkeys::mjson;

// A satoshis field above Dash Core MAX_MONEY is not a UTXO.
constexpr double kMaxMoneyDuffs = static_cast<double>(kMaxMoney);

std::string lower_ascii(std::string s)
{
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

// A JSON number that is a whole value in [0, max]. MiniJson holds numbers as
// doubles, which are exact for every integer below 2^53 (> MAX_MONEY).
bool whole_number(const mjson::JVal* v, double max, int64_t& out)
{
    if (!v || v->t != mjson::JVal::T::Num) return false;
    const double x = v->num;
    if (!std::isfinite(x) || x < 0 || x > max || std::floor(x) != x) return false;
    out = static_cast<int64_t>(x);
    return true;
}

} // namespace

std::vector<Utxo> parse_insight_utxos(const std::string& json, std::string& err)
{
    err.clear();
    const mjson::ParseResult pr = mjson::parse(json);
    if (!pr.ok) {
        err = "UTXO JSON does not parse: " + pr.error;
        return {};
    }
    if (!pr.root.is_arr()) {
        err = "UTXO JSON must be an array of UTXO objects (insight /addr/<address>/utxo)";
        return {};
    }

    std::vector<Utxo> out;
    out.reserve(pr.root.arr.size());
    for (size_t i = 0; i < pr.root.arr.size(); ++i) {
        const mjson::JVal& e = pr.root.arr[i];
        const std::string where = "UTXO entry " + std::to_string(i);
        if (!e.is_obj()) { err = where + " is not an object"; return {}; }

        Utxo u;
        const mjson::JVal* txid = e.find("txid");
        if (!txid || !txid->is_str() || txid->str.size() != 64 || !hdkeys::from_hex(txid->str)) {
            err = where + ": txid must be 64 hex characters";
            return {};
        }
        u.txid = lower_ascii(txid->str);

        int64_t n = 0;
        if (!whole_number(e.find("vout"), 4294967295.0, n)) {
            err = where + ": vout must be a whole number in [0, 2^32)";
            return {};
        }
        u.vout = static_cast<uint32_t>(n);

        // Integer duffs only — the floating `amount` field is never read.
        if (!whole_number(e.find("satoshis"), kMaxMoneyDuffs, u.satoshis)) {
            err = where + ": satoshis must be a whole number of duffs in [0, MAX_MONEY]";
            return {};
        }

        const mjson::JVal* conf = e.find("confirmations");
        if (conf && conf->t != mjson::JVal::T::Null) {
            if (!whole_number(conf, 1e15, u.confirmations)) {
                err = where + ": confirmations must be a whole number >= 0";
                return {};
            }
        }

        const mjson::JVal* spk = e.find("scriptPubKey");
        if (spk && spk->t != mjson::JVal::T::Null) {
            if (!spk->is_str() || !hdkeys::from_hex(spk->str)) {
                err = where + ": scriptPubKey must be hex";
                return {};
            }
            u.script_pubkey_hex = lower_ascii(spk->str);
        }

        const mjson::JVal* height = e.find("height");
        if (height && height->t != mjson::JVal::T::Null) {
            if (!whole_number(height, 1e15, u.height)) {
                err = where + ": height must be a whole number >= 0";
                return {};
            }
        }

        // Insight has no coinbase flag: leave it unknown (held to the coinbase rule).
        u.coinbase = std::nullopt;
        out.push_back(std::move(u));
    }
    return out;
}

int64_t confirmations_needed(const Utxo& u, int64_t min_confirmations)
{
    // Only a UTXO KNOWN not to be coinbase escapes the coinbase rule; an unknown
    // one is treated as coinbase, so lowering min_confirmations can never let a
    // possibly-coinbase output through before it matures.
    if (u.coinbase.has_value() && !*u.coinbase) return 1;
    return std::max(min_confirmations, kCoinbaseMaturity);
}

UtxoScreen screen_utxos(const std::vector<Utxo>& raw,
                        const std::array<uint8_t, 20>& funding_h160,
                        int64_t min_confirmations,
                        int64_t dust_floor,
                        bool strict)
{
    const std::array<uint8_t, 25> want_script = p2pkh_script(funding_h160);
    std::set<std::pair<std::string, uint32_t>> seen;
    UtxoScreen out;
    for (const Utxo& u : raw) {
        if (u.txid.size() != 64 || !hdkeys::from_hex(u.txid))
            throw DashAbort("malformed UTXO entry: bad txid");
        if (u.satoshis < 0)
            throw DashAbort("malformed UTXO entry: negative value");
        if (u.script_pubkey_hex.empty()) {
            if (strict)
                throw DashAbort("UTXO " + u.txid + ":" + std::to_string(u.vout) +
                                " has no scriptPubKey — inject mode needs every UTXO's "
                                "scriptPubKey to prove it pays the funding address");
        } else {
            auto spk = hdkeys::from_hex(u.script_pubkey_hex);
            if (!spk)
                throw DashAbort("malformed UTXO entry: scriptPubKey is not hex");
            if (spk->size() != want_script.size() ||
                !std::equal(spk->begin(), spk->end(), want_script.begin()))
                throw DashAbort("UTXO " + u.txid + " scriptPubKey does NOT pay the funding "
                                "address — refusing to touch it");
        }
        if (!seen.insert({lower_ascii(u.txid), u.vout}).second)
            throw DashAbort("UTXO " + u.txid + ":" + std::to_string(u.vout) +
                            " is listed twice — a tx spending it twice is invalid");

        if (u.satoshis < dust_floor) {
            out.dust.push_back(u);
            continue;
        }
        if (u.confirmations < confirmations_needed(u, min_confirmations)) {
            out.immature.push_back(u);
            continue;
        }
        out.spendable.push_back(u);
    }
    return out;
}

void sort_by_outpoint(std::vector<Utxo>& utxos)
{
    std::stable_sort(utxos.begin(), utxos.end(), [](const Utxo& a, const Utxo& b) {
        const std::string ta = lower_ascii(a.txid), tb = lower_ascii(b.txid);
        if (ta != tb) return ta < tb;
        return a.vout < b.vout;
    });
}

std::string format_dash(int64_t duffs)
{
    const bool neg = duffs < 0;
    const uint64_t v = neg ? 0 - static_cast<uint64_t>(duffs) : static_cast<uint64_t>(duffs);
    std::string frac = std::to_string(v % static_cast<uint64_t>(kCoin));
    frac.insert(0, 8 - frac.size(), '0');
    return std::string(neg ? "-" : "") + std::to_string(v / static_cast<uint64_t>(kCoin)) + "." +
           frac;
}

std::string describe_skipped(const UtxoScreen& screen, int64_t min_confirmations,
                             int64_t dust_floor)
{
    std::string s;
    if (!screen.immature.empty()) {
        s += "skipped immature (" + std::to_string(screen.immature.size()) +
             ") -- NOT spent by this plan:\n";
        for (const Utxo& u : screen.immature) {
            const int64_t n = confirmations_needed(u, min_confirmations) - u.confirmations;
            s += "  " + u.txid + ":" + std::to_string(u.vout) + "  " + format_dash(u.satoshis) +
                 " DASH  (" + std::to_string(u.confirmations) + " conf) matures in " +
                 std::to_string(n) + (n == 1 ? " block\n" : " blocks\n");
        }
    }
    if (!screen.dust.empty()) {
        s += "skipped dust below " + std::to_string(dust_floor) + " duffs (" +
             std::to_string(screen.dust.size()) + ") -- NOT spent by this plan:\n";
        for (const Utxo& u : screen.dust)
            s += "  " + u.txid + ":" + std::to_string(u.vout) + "  " + format_dash(u.satoshis) +
                 " DASH\n";
    }
    if (!s.empty())
        s += "NOTE: no follow-up tx is built for the skipped UTXOs. The funding address keeps\n"
             "      receiving outputs, so there is always an immature tail: re-plan later to\n"
             "      sweep what has matured since.\n";
    return s;
}

} // namespace c2w::dash


// ── Slice 2: export v1 / getaddressutxos / auto-detect ──────────────────────
namespace c2w::dash {

namespace {

[[noreturn]] void refuse(const std::string& why) { throw DashAbort(why); }

std::string row_where(size_t i) { return "UTXO row " + std::to_string(i); }

// A required whole-number field of a row.
int64_t need_whole(const mjson::JVal& row, const char* key, double max, size_t i, const char* what)
{
    int64_t v = 0;
    if (!whole_number(row.find(key), max, v))
        refuse(row_where(i) + ": " + key + " must be " + what);
    return v;
}

std::string need_txid(const mjson::JVal& row, size_t i)
{
    const mjson::JVal* t = row.find("txid");
    if (!t || !t->is_str() || t->str.size() != 64 || !hdkeys::from_hex(t->str))
        refuse(row_where(i) + ": txid must be 64 hex characters");
    return lower_ascii(t->str);
}

std::string need_script(const mjson::JVal& row, const char* key, size_t i)
{
    const mjson::JVal* t = row.find(key);
    if (!t || !t->is_str() || t->str.empty() || !hdkeys::from_hex(t->str))
        refuse(row_where(i) + ": " + key + " must be the output's scriptPubKey hex");
    return lower_ascii(t->str);
}

// The hash160 a 25-byte P2PKH script pays, or nullopt for any other script.
std::optional<std::array<uint8_t, 20>> p2pkh_h160(const std::string& spk_hex)
{
    auto spk = hdkeys::from_hex(spk_hex);
    if (!spk || spk->size() != 25 || (*spk)[0] != 0x76 || (*spk)[1] != 0xa9 || (*spk)[2] != 0x14 ||
        (*spk)[23] != 0x88 || (*spk)[24] != 0xac)
        return std::nullopt;
    std::array<uint8_t, 20> h{};
    std::copy(spk->begin() + 3, spk->begin() + 23, h.begin());
    return h;
}

// Checks shared by every format, after the rows are read: one P2PKH payee for
// every row that carries a script (the funding address is derived from it and
// must equal any stated address), no outpoint twice, the sum within MAX_MONEY,
// and no row above the tip.
void finish_import(UtxoImport& imp, const std::string& stated_address,
                   const std::vector<std::string>& row_addresses)
{
    if (imp.utxos.empty())
        refuse("the UTXO list is empty: nothing to spend");
    std::optional<std::array<uint8_t, 20>> payee;
    std::set<std::pair<std::string, uint32_t>> seen;
    int64_t total = 0;
    for (size_t i = 0; i < imp.utxos.size(); ++i) {
        const Utxo& u = imp.utxos[i];
        if (!u.script_pubkey_hex.empty()) {
            auto h = p2pkh_h160(u.script_pubkey_hex);
            if (!h)
                refuse(row_where(i) + " (" + u.txid + ":" + std::to_string(u.vout) +
                       ") is not a P2PKH output — only P2PKH funding is supported");
            if (payee && *h != *payee)
                refuse(row_where(i) + " (" + u.txid + ":" + std::to_string(u.vout) +
                       ") pays another script than row 0 — one funding address per import");
            payee = h;
        }
        if (!seen.insert({u.txid, u.vout}).second)
            refuse(row_where(i) + ": " + u.txid + ":" + std::to_string(u.vout) +
                   " is listed twice — refusing the whole list");
        if (__builtin_add_overflow(total, u.satoshis, &total) || total > kMaxMoney)
            refuse("the UTXO amounts sum above MAX_MONEY — not a real UTXO list");
        if (imp.tip_height > 0 && u.height > imp.tip_height)
            refuse(row_where(i) + " height " + std::to_string(u.height) + " is above the tip " +
                   std::to_string(imp.tip_height) + " — wrong tip?");
    }
    imp.total = total;

    std::string derived;
    if (payee) derived = h160_to_addr(*payee, imp.testnet);
    std::string stated = stated_address;
    for (size_t i = 0; i < row_addresses.size(); ++i) {
        if (row_addresses[i].empty()) continue;
        if (stated.empty()) stated = row_addresses[i];
        if (row_addresses[i] != stated)
            refuse(row_where(i) + " address " + row_addresses[i] + " differs from " + stated +
                   " — one funding address per import");
    }
    if (!stated.empty()) {
        // Decoding refuses a wrong-network or corrupt address.
        const std::array<uint8_t, 20> h = addr_to_h160(stated, imp.testnet);
        if (payee && h != *payee)
            refuse("the stated address " + stated + " is not the address the scripts pay (" +
                   derived + ")");
        if (!payee) derived = stated;
    }
    if (derived.empty())
        refuse("no row carries a scriptPubKey and no address is stated: the funding address "
               "cannot be established");
    imp.address = derived;
}

UtxoImport getaddressutxos_rows(const mjson::JVal& arr, int64_t tip_height, bool testnet)
{
    if (tip_height <= 0)
        refuse("getaddressutxos carries no tip: give the tip height the list was taken at "
               "(dash-cli getblockcount), or use the export v1 / chainInfo form");
    UtxoImport imp;
    imp.source = UtxoSource::GetAddressUtxos;
    imp.testnet = testnet;
    imp.tip_height = tip_height;
    std::vector<std::string> addrs;
    for (size_t i = 0; i < arr.arr.size(); ++i) {
        const mjson::JVal& r = arr.arr[i];
        if (!r.is_obj()) refuse(row_where(i) + " is not an object");
        Utxo u;
        u.txid = need_txid(r, i);
        u.vout = static_cast<uint32_t>(need_whole(r, "outputIndex", 4294967295.0, i, "a whole number in [0, 2^32)"));
        u.satoshis = need_whole(r, "satoshis", kMaxMoneyDuffs, i, "a whole number of duffs in [0, MAX_MONEY]");
        u.height = need_whole(r, "height", 1e15, i, "a whole number >= 1");
        if (u.height < 1) refuse(row_where(i) + ": height must be >= 1");
        u.script_pubkey_hex = need_script(r, "script", i);
        u.coinbase = std::nullopt; // getaddressutxos does not say: held to the coinbase rule
        if (u.height <= tip_height) u.confirmations = tip_height - u.height + 1;
        addrs.push_back(r.str_of("address"));
        imp.utxos.push_back(std::move(u));
    }
    finish_import(imp, "", addrs);
    return imp;
}

} // namespace

const char* utxo_source_name(UtxoSource s)
{
    switch (s) {
    case UtxoSource::ExportV1: return "c2wallet export v1";
    case UtxoSource::GetAddressUtxos: return "dashd getaddressutxos";
    case UtxoSource::Insight: return "insight";
    }
    return "?";
}

UtxoImport parse_getaddressutxos(const std::string& json, int64_t tip_height, bool testnet)
{
    const mjson::ParseResult pr = mjson::parse(json);
    if (!pr.ok) refuse("UTXO JSON does not parse: " + pr.error);
    if (pr.root.is_arr()) return getaddressutxos_rows(pr.root, tip_height, testnet);
    if (!pr.root.is_obj()) refuse("getaddressutxos must be an array, or the {utxos, hash, height} object");
    const mjson::JVal* rows = pr.root.find("utxos");
    if (!rows || !rows->is_arr()) refuse("getaddressutxos object without a \"utxos\" array");
    int64_t obj_tip = 0;
    if (!whole_number(pr.root.find("height"), 1e15, obj_tip) || obj_tip <= 0)
        refuse("getaddressutxos object without a whole \"height\" (the tip)");
    if (tip_height != 0 && tip_height != obj_tip)
        refuse("the typed tip " + std::to_string(tip_height) + " differs from the object's height " +
               std::to_string(obj_tip));
    UtxoImport imp = getaddressutxos_rows(*rows, obj_tip, testnet);
    imp.tip_hash = lower_ascii(pr.root.str_of("hash"));
    return imp;
}

UtxoImport parse_utxo_export_v1(const std::string& json, bool testnet)
{
    const mjson::ParseResult pr = mjson::parse(json);
    if (!pr.ok) refuse("UTXO JSON does not parse: " + pr.error);
    const mjson::JVal& root = pr.root;
    if (!root.is_obj()) refuse("export v1 must be a JSON object");
    if (root.str_of("schema") != kUtxoExportSchema)
        refuse("schema \"" + root.str_of("schema") + "\" is not " + kUtxoExportSchema);
    if (root.str_of("coin") != "dash")
        refuse("coin \"" + root.str_of("coin") + "\" is not dash");
    const std::string want_net = testnet ? "testnet" : "mainnet";
    if (root.str_of("network") != want_net)
        refuse("network \"" + root.str_of("network") + "\" does not match this page (" + want_net + ")");

    UtxoImport imp;
    imp.source = UtxoSource::ExportV1;
    imp.testnet = testnet;
    if (!whole_number(root.find("tip_height"), 1e15, imp.tip_height) || imp.tip_height <= 0)
        refuse("export v1 needs tip_height > 0");
    imp.tip_hash = lower_ascii(root.str_of("tip_hash"));
    const mjson::JVal* rows = root.find("utxos");
    if (!rows || !rows->is_arr()) refuse("export v1 without a \"utxos\" array");

    bool all_flags = true;
    for (size_t i = 0; i < rows->arr.size(); ++i) {
        const mjson::JVal& r = rows->arr[i];
        if (!r.is_obj()) refuse(row_where(i) + " is not an object");
        Utxo u;
        u.txid = need_txid(r, i);
        u.vout = static_cast<uint32_t>(need_whole(r, "vout", 4294967295.0, i, "a whole number in [0, 2^32)"));
        u.satoshis = need_whole(r, "satoshis", kMaxMoneyDuffs, i, "a whole number of duffs in [0, MAX_MONEY]");
        u.height = need_whole(r, "height", 1e15, i, "a whole number >= 1");
        if (u.height < 1) refuse(row_where(i) + ": height must be >= 1");
        const int64_t conf = need_whole(r, "confirmations", 1e15, i, "a whole number >= 0");
        // Recomputed, never trusted: a mismatch means rows from two tips were mixed.
        if (u.height > imp.tip_height || conf != imp.tip_height - u.height + 1)
            refuse(row_where(i) + " (" + u.txid + ":" + std::to_string(u.vout) + ") confirmations " +
                   std::to_string(conf) + " != tip - height + 1 = " +
                   std::to_string(imp.tip_height - u.height + 1) + " — two different tips were mixed");
        u.confirmations = conf;
        u.script_pubkey_hex = need_script(r, "scriptPubKey", i);
        const mjson::JVal* cb = r.find("coinbase");
        if (cb && cb->t == mjson::JVal::T::Bool) {
            u.coinbase = cb->b;
        } else if (!cb || cb->t == mjson::JVal::T::Null) {
            u.coinbase = true; // absent => coinbase (conservative)
            all_flags = false;
        } else {
            refuse(row_where(i) + ": coinbase must be true or false");
        }
        imp.utxos.push_back(std::move(u));
    }
    imp.coinbase_flags = all_flags;
    finish_import(imp, root.str_of("address"), {});
    return imp;
}

UtxoImport parse_utxo_json(const std::string& json, int64_t tip_height, bool testnet)
{
    const mjson::ParseResult pr = mjson::parse(json);
    if (!pr.ok) refuse("UTXO JSON does not parse: " + pr.error);
    if (pr.root.is_obj()) {
        if (pr.root.find("schema")) {
            if (tip_height != 0)
                refuse("an export v1 carries its own tip; do not type one");
            return parse_utxo_export_v1(json, testnet);
        }
        if (pr.root.find("utxos")) return parse_getaddressutxos(json, tip_height, testnet);
        refuse("unrecognised UTXO JSON object (expected the export v1 or the getaddressutxos "
               "{utxos, hash, height} object)");
    }
    if (!pr.root.is_arr()) refuse("unrecognised UTXO JSON: expected an object or an array");
    if (pr.root.arr.empty()) refuse("the UTXO list is empty: nothing to spend");
    const mjson::JVal& first = pr.root.arr[0];
    if (first.is_obj() && first.find("outputIndex")) return parse_getaddressutxos(json, tip_height, testnet);
    if (!first.is_obj() || !first.find("vout"))
        refuse("unrecognised UTXO rows: expected getaddressutxos (outputIndex) or insight (vout)");

    std::string err;
    UtxoImport imp;
    imp.source = UtxoSource::Insight;
    imp.testnet = testnet;
    imp.utxos = parse_insight_utxos(json, err);
    if (!err.empty()) refuse(err);
    // The tip: typed, else derived from rows that carry both height and
    // confirmations — every such row must agree on it.
    int64_t derived_tip = 0;
    for (size_t i = 0; i < imp.utxos.size(); ++i) {
        const Utxo& u = imp.utxos[i];
        if (u.height <= 0 || u.confirmations <= 0) continue;
        const int64_t t = u.height + u.confirmations - 1;
        if (derived_tip == 0) derived_tip = t;
        if (t != derived_tip)
            refuse(row_where(i) + " implies tip " + std::to_string(t) + ", an earlier row " +
                   std::to_string(derived_tip) + " — two different tips were mixed");
    }
    if (tip_height != 0 && derived_tip != 0 && tip_height != derived_tip)
        refuse("the typed tip " + std::to_string(tip_height) + " differs from the tip the rows imply (" +
               std::to_string(derived_tip) + ")");
    imp.tip_height = tip_height != 0 ? tip_height : derived_tip;
    std::vector<std::string> addrs;
    {
        for (const mjson::JVal& r : pr.root.arr) addrs.push_back(r.is_obj() ? r.str_of("address") : "");
    }
    finish_import(imp, "", addrs);
    return imp;
}

// ── maturity at a target height ─────────────────────────────────────────────

int64_t confirmations_at(const Utxo& u, int64_t tip_height, int64_t target_height)
{
    if (u.height > 0) return std::max<int64_t>(0, target_height - u.height);
    if (tip_height > 0 && u.confirmations > 0)
        return std::max<int64_t>(0, u.confirmations + (target_height - tip_height - 1));
    return u.confirmations;
}

int64_t matures_in(const Utxo& u, int64_t tip_height, int64_t target_height,
                   int64_t min_confirmations)
{
    return std::max<int64_t>(0, confirmations_needed(u, min_confirmations) -
                                    confirmations_at(u, tip_height, target_height));
}

int64_t effective_height(const Utxo& u, int64_t tip_height)
{
    if (u.height > 0) return u.height;
    if (tip_height > 0 && u.confirmations > 0) return tip_height - u.confirmations + 1;
    return 0;
}

int64_t safe_from_height(const std::vector<Utxo>& inputs, int64_t tip_height)
{
    // The rule itself lives in the std-only InjectMaturity.hpp, shared with the
    // online companion's inject scheduler.
    return maturity::safe_from_height(inputs, [tip_height](const Utxo& u) {
        const bool known_non_coinbase = u.coinbase.has_value() && !*u.coinbase;
        return maturity::InputHeight{effective_height(u, tip_height), !known_non_coinbase};
    });
}

TargetScreen rescreen_at_height(const std::vector<Utxo>& utxos,
                                const std::array<uint8_t, 20>& funding_h160,
                                int64_t tip_height,
                                int64_t target_height,
                                int64_t min_confirmations,
                                int64_t dust_floor,
                                bool strict)
{
    if (target_height <= 0)
        refuse("target height must be > 0");
    if (tip_height > 0 && target_height <= tip_height)
        refuse("target height " + std::to_string(target_height) + " is not above the screened tip " +
               std::to_string(tip_height) + ": a tx can only land in a later block");
    if (dust_floor < 0)
        refuse("dust_floor must be >= 0");

    TargetScreen out;
    out.tip_height = tip_height;
    out.target_height = target_height;
    out.min_confirmations = min_confirmations;
    out.dust_floor = dust_floor;
    out.projected.reserve(utxos.size());
    for (const Utxo& u : utxos) {
        Utxo p = u;
        p.confirmations = confirmations_at(u, tip_height, target_height);
        if (p.height <= 0) p.height = effective_height(u, tip_height);
        out.projected.push_back(std::move(p));
    }
    out.screen = screen_utxos(out.projected, funding_h160, min_confirmations, dust_floor, strict);
    // The immature list, oldest-maturing first: by height, then outpoint.
    std::stable_sort(out.screen.immature.begin(), out.screen.immature.end(),
                     [](const Utxo& a, const Utxo& b) {
                         if (a.height != b.height) return a.height < b.height;
                         if (a.txid != b.txid) return a.txid < b.txid;
                         return a.vout < b.vout;
                     });
    out.safe_from_height = safe_from_height(out.screen.spendable, tip_height);
    for (const Utxo& u : out.screen.spendable) {
        const int64_t h = effective_height(u, tip_height);
        if (h <= 0) { out.youngest_height = 0; break; }
        out.youngest_height = std::max(out.youngest_height, h);
    }
    return out;
}

} // namespace c2w::dash
