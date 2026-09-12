// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
#include "MoneroScanner.hpp"

#include <cstring>

#include "MoneroScanOps.hpp"
#include "family/monero/addr/MoneroAddress.hpp"   // derive_subaddress (reused)

namespace c2wallet::monero {

namespace {
const Bytes32 kZeroScalar{};   // subaddress secret m for the primary index (0,0)
}

// ── SubaddressTable ────────────────────────────────────────────────────────

std::string SubaddressTable::keyof(const Bytes32& b) {
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

void SubaddressTable::build(const Bytes32& view_priv, const Bytes32& spend_pub,
                            std::uint32_t major_count, std::uint32_t minor_count) {
    table_.clear();
    for (std::uint32_t i = 0; i < major_count; ++i) {
        for (std::uint32_t j = 0; j < minor_count; ++j) {
            SubaddressResult s = derive_subaddress(view_priv, spend_pub, i, j);
            if (!s.ok)
                continue;
            Entry e;
            e.index = SubaddressIndex{i, j};
            e.m     = (i == 0 && j == 0) ? kZeroScalar : s.m;
            // First writer wins on a collision (the lowest index), matching how a
            // wallet reports the canonical index for a reused spend key.
            table_.emplace(keyof(s.sub_spend_pub), e);
        }
    }
}

bool SubaddressTable::lookup(const Bytes32& spend_pub_candidate, Entry& out) const {
    auto it = table_.find(keyof(spend_pub_candidate));
    if (it == table_.end())
        return false;
    out = it->second;
    return true;
}

// ── MoneroScanner ──────────────────────────────────────────────────────────

MoneroScanner::MoneroScanner(const MoneroKeys& keys) : keys_(keys) {
    // A usable table always contains at least the primary index.
    build_subaddress_table(1, 1);
}

void MoneroScanner::build_subaddress_table(std::uint32_t major_count,
                                           std::uint32_t minor_count) {
    if (major_count == 0) major_count = 1;
    if (minor_count == 0) minor_count = 1;
    subs_.build(keys_.view_priv, keys_.spend_pub, major_count, minor_count);
}

ScanResult MoneroScanner::scan_transaction(const TxToScan& tx) {
    ScanResult res;
    if (tx.tx_pubkeys.empty())
        return res;

    const bool have_additional =
        tx.additional_pubkeys.size() == tx.outputs.size() && !tx.outputs.empty();

    for (std::size_t i = 0; i < tx.outputs.size(); ++i) {
        ++res.scanned;
        const EnoteToScan& o = tx.outputs[i];

        // The tx pubkey for this output: per-output additional key (subaddress
        // send) if present, otherwise the single main tx pubkey.
        const Bytes32& R = have_additional ? tx.additional_pubkeys[i] : tx.tx_pubkeys[0];

        // D = 8 * k_v * R
        Bytes32 D{};
        if (!scanops::key_derivation(R, keys_.view_priv, D))
            continue;

        // View-tag fast reject (HF15+): cheap Keccak byte compare before the
        // point subtraction / table lookup.
        if (o.has_view_tag && scanops::view_tag(D, i) != o.view_tag) {
            ++res.view_tag_rejected;
            continue;
        }

        // Subaddress-aware ownership: candidate = P_i - H_s(D||i)*G, matched
        // against the precomputed spend table. For (0,0) this reduces exactly to
        // derive_public_key(D,i,K_s) == P_i.
        Bytes32 candidate{};
        if (!scanops::derive_subaddress_public_key(o.one_time_pub, D, i, candidate))
            continue;

        SubaddressTable::Entry entry;
        if (!subs_.lookup(candidate, entry))
            continue;   // not ours

        OwnedOutput owned;
        owned.output_index = i;
        owned.one_time_pub = o.one_time_pub;
        owned.subaddr      = entry.index;

        // Amount + commitment mask via the RingCT v2 short ecdh (two Keccak + xor).
        if (o.is_rct) {
            Bytes32 shared = scanops::derivation_to_scalar(D, i);
            owned.amount      = scanops::ecdh_decode_amount(o.ecdh_amount, shared);
            owned.amount_mask = scanops::commitment_mask(shared);
        } else {
            owned.amount = o.clear_amount;   // pre-RCT / coinbase clear amount
        }

        // Key image -- FULL WALLET ONLY. Needs the spend secret via
        // x_i = H_s(D||i) + k_s (+ m for a subaddress). A view-only account has
        // no k_s, so this whole block is skipped and has_key_image stays false:
        // that is the air-gap split, enforced by construction, not by a flag.
        if (keys_.can_sign()) {
            Bytes32 x = scanops::derive_secret_key(D, i, keys_.spend_priv);
            if (!(entry.index.major == 0 && entry.index.minor == 0))
                x = mcrypto::scalar_add(x, entry.m);   // + subaddress secret
            Bytes32 ki{};
            if (scanops::generate_key_image(o.one_time_pub, x, ki)) {
                owned.key_image     = ki;
                owned.has_key_image = true;
            }
        }

        wallet_.push_back(owned);
        wallet_tx_pubkey_.push_back(R);
        res.owned.push_back(owned);
    }
    return res;
}

std::uint64_t MoneroScanner::balance() const {
    std::uint64_t sum = 0;
    for (const auto& o : wallet_)
        sum += o.amount;
    return sum;
}

std::vector<ExportedOutput> MoneroScanner::export_outputs() const {
    std::vector<ExportedOutput> out;
    out.reserve(wallet_.size());
    for (std::size_t i = 0; i < wallet_.size(); ++i) {
        const OwnedOutput& o = wallet_[i];
        ExportedOutput e;
        e.one_time_pub = o.one_time_pub;
        e.tx_pubkey    = (i < wallet_tx_pubkey_.size()) ? wallet_tx_pubkey_[i] : Bytes32{};
        e.output_index = o.output_index;
        e.subaddr      = o.subaddr;
        e.amount       = o.amount;
        e.amount_mask  = o.amount_mask;
        // Deliberately NO key image and NO one-time secret in the export artifact.
        out.push_back(e);
    }
    return out;
}

} // namespace c2wallet::monero
