// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Classifier.hpp"

#include "../sched/Triggers.hpp" // format_eta_blocks (156 s per block)

#include "../../family/bitcoin/dash/DashAddress.hpp"
#include "../../family/bitcoin/dash/DashError.hpp"
#include "../../family/bitcoin/dash/InjectMaturity.hpp"

#include "Digest.hpp"

#include <algorithm>

namespace c2w::companion::scan {

using c2w::dash::Utxo;
using c2w::dash::UtxoImport;

namespace {

bool read_compact(const std::vector<uint8_t>& b, size_t& p, uint64_t& n)
{
    if (p >= b.size()) return false;
    const uint8_t c = b[p++];
    int width = 0;
    if (c < 0xfd) { n = c; return true; }
    width = c == 0xfd ? 2 : (c == 0xfe ? 4 : 8);
    if (p + static_cast<size_t>(width) > b.size()) return false;
    n = 0;
    for (int i = 0; i < width; ++i) n |= static_cast<uint64_t>(b[p + static_cast<size_t>(i)]) << (8 * i);
    p += static_cast<size_t>(width);
    return true;
}

} // namespace

std::vector<Outpoint> tx_prevouts(const std::string& raw_tx_hex)
{
    const auto bytes = c2w::artifact::from_hex(raw_tx_hex);
    if (!bytes || bytes->size() < 10) return {};
    const std::vector<uint8_t>& b = *bytes;
    size_t p = 4; // version
    if (b[p] == 0x00 && b[p + 1] == 0x01) p += 2; // BIP144 marker + flag
    uint64_t nin = 0;
    if (!read_compact(b, p, nin) || nin > b.size()) return {};
    std::vector<Outpoint> out;
    for (uint64_t i = 0; i < nin; ++i) {
        if (p + 36 > b.size()) return {};
        std::vector<uint8_t> txid(b.begin() + static_cast<long>(p), b.begin() + static_cast<long>(p) + 32);
        std::reverse(txid.begin(), txid.end()); // internal -> display order
        p += 32;
        uint32_t vout = 0;
        for (int k = 0; k < 4; ++k) vout |= static_cast<uint32_t>(b[p + static_cast<size_t>(k)]) << (8 * k);
        p += 4;
        uint64_t slen = 0;
        if (!read_compact(b, p, slen) || p + slen + 4 > b.size()) return {};
        p += slen + 4; // scriptSig + sequence
        out.push_back({c2w::artifact::to_hex(txid), vout});
    }
    return out;
}

std::map<Outpoint, std::string> queued_outpoints(const sched::Queue& q)
{
    std::map<Outpoint, std::string> m;
    for (const sched::Item& it : q.items) {
        if (sched::is_terminal(it)) continue;
        for (const Outpoint& o : tx_prevouts(it.tx.raw_tx)) m.emplace(o, it.id);
    }
    return m;
}

Classification classify(const UtxoImport& imp, const std::vector<Outpoint>& mempool_spent,
                        const std::map<Outpoint, std::string>& queued, const ClassifyParams& params)
{
    Classification c;
    c.address = imp.address;
    c.testnet = imp.testnet;
    c.tip_height = imp.tip_height;
    c.tip_hash = imp.tip_hash;
    c.params = params;
    c.target_height = params.target_height ? params.target_height : imp.tip_height + 2;
    c.params.target_height = c.target_height;
    c.mempool_spent = mempool_spent;

    c.exportable = imp;
    c.exportable.utxos.clear();
    c.exportable.total = 0;
    for (const Utxo& u : imp.utxos) {
        const auto q = queued.find({u.txid, u.vout});
        if (q != queued.end()) {
            c.queued.push_back({u, q->second});
            continue;
        }
        c.exportable.utxos.push_back(u);
        c.exportable.total += u.satoshis;
    }

    // Parameter refusals get their own names before the screen runs, so a
    // scan-foreign-script below always means a row that pays another script.
    if (c.target_height <= imp.tip_height)
        throw ScanRefusal(cause::kBadTarget, "target height " + std::to_string(c.target_height) +
                                                 " is not above the scan tip " + std::to_string(imp.tip_height) +
                                                 ": a tx can only land in a later block");
    if (params.min_confirmations < 1 || params.dust_floor < 0)
        throw ScanRefusal(cause::kBadParams, "min_confirmations must be >= 1 and dust_floor >= 0");

    c2w::dash::TargetScreen ts;
    try {
        ts = c2w::dash::rescreen_at_height(c.exportable.utxos, c2w::dash::addr_to_h160(imp.address, imp.testnet),
                                           imp.tip_height, c.target_height, params.min_confirmations,
                                           params.dust_floor, true);
    } catch (const c2w::dash::DashAbort& e) {
        throw ScanRefusal(cause::kForeignScript, e.what());
    }
    c.mature = ts.screen.spendable;
    c.dust = ts.screen.dust;
    for (const Utxo& p : ts.screen.immature) {
        ImmatureRow r;
        r.utxo = p;
        r.utxo.confirmations = imp.tip_height - p.height + 1; // as of the scan tip, as exported
        r.matures_in = c2w::dash::matures_in(p, imp.tip_height, c.target_height, params.min_confirmations);
        const bool cb_or_unknown = !(p.coinbase.has_value() && !*p.coinbase);
        r.spendable_from_height = c2w::dash::maturity::spendable_from_height(p.height, cb_or_unknown);
        r.eta = sched::format_eta_blocks(r.matures_in);
        c.immature.push_back(std::move(r));
    }
    if (params.fee_mode == c2w::dash::FeeMode::Relay) {
        const int64_t per_input = static_cast<int64_t>(c2w::dash::signed_input_bytes(params.key_encoding));
        for (const Utxo& u : c.mature)
            if (u.satoshis < params.fee_rate_per_byte * per_input) c.uneconomic.push_back(u);
    }
    return c;
}

} // namespace c2w::companion::scan
