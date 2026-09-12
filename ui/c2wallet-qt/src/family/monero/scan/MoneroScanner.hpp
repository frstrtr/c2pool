// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// ui/c2wallet-qt/src/family/monero/scan/MoneroScanner.hpp
//
// Family B (Monero) output scanning -- the READ-ONLY wallet path (design §4.2).
// No signing, no money movement: it decides which on-chain outputs (enotes) an
// account owns, decrypts their amounts, tracks the owned-output set and balance,
// and -- in a FULL wallet only -- computes key images. It is the online, air-gap
// SOURCE side (design §5.4 Family B): a view-only account scans and produces the
// "export outputs" artifact (own outputs, NO secrets) that crosses to the
// offline full wallet.
//
// The air-gap split, enforced structurally:
//   * view-only account (no spend secret) -> ownership + amount + mask, but the
//     key image is UNCOMPUTABLE (x_i needs k_s). can_produce_key_images()==false.
//   * full account (spend secret present)  -> everything, incl. the key image.
//
// Qt-free: builds and KAT-runs against the vendored Monero crypto without Qt.
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "family/monero/MoneroCrypto.hpp"   // Bytes32
#include "family/monero/MoneroKey.hpp"      // MoneroKeys

namespace c2wallet::monero {

// (major, minor) subaddress index. (0,0) is the primary/standard address.
struct SubaddressIndex {
    std::uint32_t major{0};
    std::uint32_t minor{0};
    bool operator==(const SubaddressIndex& o) const {
        return major == o.major && minor == o.minor;
    }
};

// One on-chain output ("enote") as presented to the scanner.
struct EnoteToScan {
    Bytes32                    one_time_pub{};   // P_i (target one-time public key)
    bool                       has_view_tag{false};
    std::uint8_t               view_tag{0};      // HF15+ fast-reject tag
    bool                       is_rct{true};     // RingCT (encrypted 8-byte amount)
    std::array<std::uint8_t,8> ecdh_amount{};    // rct v2 short masked amount
    std::uint64_t              clear_amount{0};  // used iff !is_rct (pre-RCT/coinbase)
};

// A transaction to scan. `tx_pubkeys[0]` is the main tx pubkey R (tx_extra 0x01).
// `additional_pubkeys`, if non-empty, holds one per output (tx_extra 0x04) for
// subaddress sends; then output i uses additional_pubkeys[i], else the main R.
struct TxToScan {
    std::vector<Bytes32>     tx_pubkeys;
    std::vector<Bytes32>     additional_pubkeys;
    std::vector<EnoteToScan> outputs;
};

// A detected owned output. `key_image`/`one_time_sec` are populated ONLY by a
// full wallet; a view-only scan leaves has_key_image=false.
struct OwnedOutput {
    std::size_t     output_index{0};   // i within the tx
    Bytes32         one_time_pub{};    // P_i
    SubaddressIndex subaddr{};
    std::uint64_t   amount{0};
    Bytes32         amount_mask{};     // commitment (blinding) mask, for a later spend
    bool            has_key_image{false};
    Bytes32         key_image{};       // I_i -- full wallet only
};

struct ScanResult {
    std::vector<OwnedOutput> owned;
    std::size_t              scanned{0};
    std::size_t              view_tag_rejected{0};
};

// The online->offline "export outputs" artifact (design §5.4). Own outputs, and
// NO secret: no view/spend key, no one-time secret x_i, no key image. Amount and
// mask are recomputed by the online view-only wallet, so they are public to the
// owner and safe to carry to the offline signer, which recomputes x_i (needs k_s)
// and the key image. The full transfer/serialization wiring is M5; this is the
// structure.
struct ExportedOutput {
    Bytes32         one_time_pub{};    // P_i
    Bytes32         tx_pubkey{};       // R used for this output (main or additional)
    std::uint64_t   output_index{0};   // i (for the offline x_i = H_s(D||i)+k_s[+m])
    SubaddressIndex subaddr{};
    std::uint64_t   amount{0};
    Bytes32         amount_mask{};
};

// Precomputed subaddress spend-public-key table (design §4.2 "subaddress scan
// uses a precomputed spend-key table"). Maps K_s^(i,j) -> (index, m) where
// m is the subaddress secret scalar (0 for the primary index). (0,0) maps to K_s.
class SubaddressTable {
public:
    struct Entry { SubaddressIndex index; Bytes32 m{}; };

    // Build the major x minor grid from a view secret + the account spend pubkey.
    void build(const Bytes32& view_priv, const Bytes32& spend_pub,
               std::uint32_t major_count, std::uint32_t minor_count);

    bool lookup(const Bytes32& spend_pub_candidate, Entry& out) const;
    std::size_t size() const { return table_.size(); }

private:
    static std::string keyof(const Bytes32& b);
    std::unordered_map<std::string, Entry> table_;
};

// The scanner. Holds an account key set + the subaddress table + the accumulated
// owned-output set (balance state). Never signs, never touches the network.
class MoneroScanner {
public:
    explicit MoneroScanner(const MoneroKeys& keys);

    // (Re)build the subaddress table over [0,major_count) x [0,minor_count).
    // Always includes the primary index (0,0). Requires a private view key.
    void build_subaddress_table(std::uint32_t major_count, std::uint32_t minor_count);

    // Scan one transaction; matched outputs are appended to the owned set and
    // also returned. View-tag mismatches are fast-rejected and counted.
    ScanResult scan_transaction(const TxToScan& tx);

    // Accumulated owned-output-set state.
    const std::vector<OwnedOutput>& owned_outputs() const { return wallet_; }
    std::uint64_t balance() const;

    // Structural air-gap guarantee: true only for a full (spend-secret) wallet.
    bool can_produce_key_images() const { return keys_.can_sign(); }

    // The online->offline artifact (own outputs, no secrets).
    std::vector<ExportedOutput> export_outputs() const;

private:
    MoneroKeys                keys_;
    SubaddressTable           subs_;
    std::vector<OwnedOutput>  wallet_;
    // Parallel to wallet_: the R used per owned output (for export_outputs).
    std::vector<Bytes32>      wallet_tx_pubkey_;
};

} // namespace c2wallet::monero
