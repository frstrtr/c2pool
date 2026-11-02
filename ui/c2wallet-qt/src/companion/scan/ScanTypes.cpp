// SPDX-License-Identifier: AGPL-3.0-or-later
#include "ScanTypes.hpp"

#include "../../family/bitcoin/dash/DashAddress.hpp"
#include "../../family/bitcoin/dash/DashError.hpp"

#include "Digest.hpp" // artifact to_hex

#include <algorithm>
#include <cmath>
#include <map>
#include <set>
#include <tuple>

namespace c2w::companion::scan {

using c2w::dash::Utxo;
using c2w::dash::UtxoImport;

bool operator<(const Outpoint& a, const Outpoint& b)
{
    return std::tie(a.txid, a.vout) < std::tie(b.txid, b.vout);
}

bool operator==(const Outpoint& a, const Outpoint& b)
{
    return a.txid == b.txid && a.vout == b.vout;
}

std::string outpoint_str(const Outpoint& o)
{
    return o.txid + ":" + std::to_string(o.vout);
}

std::string lower(std::string s)
{
    for (char& c : s)
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    return s;
}

bool is_hex64(const std::string& s)
{
    return s.size() == 64 && std::all_of(s.begin(), s.end(), [](char c) {
               return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
           });
}

bool dash_to_duffs(double x, int64_t& duffs)
{
    if (!std::isfinite(x) || x < 0) return false;
    const double d = std::round(x * 1e8);
    if (d > static_cast<double>(c2w::dash::kMaxMoney)) return false;
    duffs = static_cast<int64_t>(d);
    return true;
}

std::vector<AddressScript> address_scripts(const std::vector<std::string>& addresses, bool testnet)
{
    if (addresses.empty())
        throw ScanRefusal(cause::kBadAddress, "no address to scan");
    if (addresses.size() > kMaxScanAddresses)
        throw ScanRefusal(cause::kBadAddress, std::to_string(addresses.size()) + " addresses; one scan takes at most " +
                                                  std::to_string(kMaxScanAddresses));
    std::vector<AddressScript> out;
    std::set<std::string> seen;
    for (const std::string& a : addresses) {
        if (!seen.insert(a).second)
            throw ScanRefusal(cause::kBadAddress, "address " + a + " is listed twice");
        std::array<uint8_t, 20> h{};
        try {
            h = c2w::dash::addr_to_h160(a, testnet);
        } catch (const c2w::dash::DashAbort& e) {
            throw ScanRefusal(cause::kBadAddress, e.what());
        }
        const std::array<uint8_t, 25> s = c2w::dash::p2pkh_script(h);
        out.push_back({a, c2w::artifact::to_hex(s.data(), s.size())});
    }
    return out;
}

std::vector<UtxoImport> group_rows(const std::vector<RawRow>& rows, const std::vector<AddressScript>& scripts,
                                   int64_t tip_height, const std::string& tip_hash, bool testnet)
{
    if (tip_height <= 0 || !is_hex64(tip_hash))
        throw ScanRefusal(cause::kBadReply, "the source gave no usable tip (height " + std::to_string(tip_height) +
                                                ", hash \"" + tip_hash + "\")");
    std::map<std::string, size_t> by_script;
    std::vector<UtxoImport> out(scripts.size());
    for (size_t i = 0; i < scripts.size(); ++i) {
        by_script[scripts[i].script_hex] = i;
        UtxoImport& imp = out[i];
        imp.source = c2w::dash::UtxoSource::ExportV1; // the shape <name>.utxos.json carries
        imp.address = scripts[i].address;
        imp.testnet = testnet;
        imp.tip_height = tip_height;
        imp.tip_hash = lower(tip_hash);
        imp.coinbase_flags = true;
    }
    std::set<Outpoint> seen;
    for (const RawRow& r : rows) {
        const Utxo& u = r.utxo;
        const std::string where = u.txid + ":" + std::to_string(u.vout);
        if (!is_hex64(u.txid))
            throw ScanRefusal(cause::kBadReply, "row txid \"" + u.txid + "\" is not 64 hex characters");
        auto it = by_script.find(lower(u.script_pubkey_hex));
        if (it == by_script.end())
            throw ScanRefusal(cause::kForeignScript, where + " pays script " + u.script_pubkey_hex +
                                                         ", which is not the P2PKH of any requested address");
        if (!r.stated_address.empty() && r.stated_address != scripts[it->second].address)
            throw ScanRefusal(cause::kSourceInconsistent, where + " is listed for address " + r.stated_address +
                                                              " but pays " + scripts[it->second].address);
        if (!seen.insert({lower(u.txid), u.vout}).second)
            throw ScanRefusal(cause::kSourceInconsistent, where + " is listed twice");
        if (u.height < 1 || u.height > tip_height)
            throw ScanRefusal(cause::kSourceInconsistent, where + " height " + std::to_string(u.height) +
                                                              " is not in [1, tip " + std::to_string(tip_height) + "]");
        if (!u.coinbase.has_value())
            throw ScanRefusal(cause::kBadReply, where + " carries no coinbase flag");
        if (u.satoshis < 0 || u.satoshis > c2w::dash::kMaxMoney)
            throw ScanRefusal(cause::kBadReply, where + " value is not a real amount");
        Utxo v = u;
        v.txid = lower(v.txid);
        v.script_pubkey_hex = lower(v.script_pubkey_hex);
        v.confirmations = tip_height - v.height + 1;
        UtxoImport& imp = out[it->second];
        if (__builtin_add_overflow(imp.total, v.satoshis, &imp.total) || imp.total > c2w::dash::kMaxMoney)
            throw ScanRefusal(cause::kBadReply, "the amounts of " + imp.address + " sum above MAX_MONEY");
        imp.utxos.push_back(std::move(v));
    }
    for (UtxoImport& imp : out)
        std::sort(imp.utxos.begin(), imp.utxos.end(), [](const Utxo& a, const Utxo& b) {
            return std::tie(a.height, a.txid, a.vout) < std::tie(b.height, b.txid, b.vout);
        });
    return out;
}

} // namespace c2w::companion::scan
