// SPDX-License-Identifier: AGPL-3.0-or-later
#include "UtxoIntake.hpp"

#include "DashAddress.hpp"
#include "DashError.hpp"

// Reused M1-A hdkeys leaf helpers (btclibs closure). NO dashscript headers.
#include "../hdkeys/HexUtil.hpp"
#include "../hdkeys/MiniJson.hpp"

#include <algorithm>
#include <cmath>
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
