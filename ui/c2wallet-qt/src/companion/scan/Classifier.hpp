// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — per-UTXO classification (design §3.3), at the scan
// tip and a target landing height T (default tip + 2, the signer's default):
//
//   mature          clears the signer's gate at T (rescreen_at_height with the
//                   signer's own rule: coinbase needs max(min_conf, 100)
//                   confirmations, a known non-coinbase output one)   planned
//   immature        otherwise: blocks until it clears the gate at a landing
//                   height, an ETA at 156 s/block, and spendable_from_height
//                   = h0 + 100 (coinbase) / h0 + 1 under consensus  the next plan's
//   dust            value < dust_floor (default 1000: the 1-duff donation
//                   outputs)                                         counted, never spent
//   uneconomic      relay mode only: value < fee rate x one signed input  warning
//   queued          the outpoint is an input of a queue item that is not
//                   terminal                                         skipped, item id named
//   mempool-spent   the source said so                               listed, excluded
//   foreign script  refused (the strict screen)
//
// `exportable` is what <name>.utxos.json carries: the scan's rows minus the
// queued ones (the signer re-plans from the export and cannot see the queue,
// so a queued outpoint must not be offered to it). Dust and immature rows stay
// in the export; the signer screens them itself.

#include "ScanTypes.hpp"

#include "../sched/InjectQueue.hpp"

#include "../../family/bitcoin/dash/InjectCaps.hpp"

#include <map>
#include <string>
#include <vector>

namespace c2w::companion::scan {

struct ClassifyParams {
    int64_t target_height = 0; // 0 => tip + 2
    int64_t min_confirmations = c2w::dash::kDefaultMinConf;
    int64_t dust_floor = 1000;
    c2w::dash::FeeMode fee_mode = c2w::dash::FeeMode::InjectOnlyZeroFee;
    int64_t fee_rate_per_byte = 0; // relay only (the uneconomic class)
    c2w::dash::PubkeyEncoding key_encoding = c2w::dash::PubkeyEncoding::Unknown;
};

struct ImmatureRow {
    c2w::dash::Utxo utxo;              // confirmations as of the scan tip
    int64_t matures_in = 0;            // blocks until it clears the gate at a landing height
    int64_t spendable_from_height = 0; // consensus: h0 + 100 (coinbase) / h0 + 1
    std::string eta;                   // "~4 h 20 m"
};

struct QueuedRow {
    c2w::dash::Utxo utxo;
    std::string item_id;
};

struct Classification {
    std::string address;
    bool testnet = false;
    int64_t tip_height = 0;
    std::string tip_hash;
    int64_t target_height = 0;
    ClassifyParams params;             // resolved (target filled in)
    std::vector<c2w::dash::Utxo> mature;
    std::vector<ImmatureRow> immature; // oldest-maturing first
    std::vector<c2w::dash::Utxo> dust;
    std::vector<c2w::dash::Utxo> uneconomic; // relay only, subset of mature
    std::vector<QueuedRow> queued;
    std::vector<Outpoint> mempool_spent;
    c2w::dash::UtxoImport exportable;  // the scan's rows minus the queued ones
};

// Outpoint -> item id for every input of every queue item that is not
// terminal (its raw tx is parsed; a tx that does not parse names no input).
std::map<Outpoint, std::string> queued_outpoints(const sched::Queue& q);

// The prevouts of a raw legacy or segwit tx (display txids). Empty on a parse
// failure.
std::vector<Outpoint> tx_prevouts(const std::string& raw_tx_hex);

// Throws ScanRefusal: kBadTarget for a target at or below the tip, kBadParams
// for min_confirmations < 1 or dust_floor < 0, kForeignScript when a row does
// not pay the address's P2PKH (the strict screen).
Classification classify(const c2w::dash::UtxoImport& imp, const std::vector<Outpoint>& mempool_spent,
                        const std::map<Outpoint, std::string>& queued, const ClassifyParams& params);

} // namespace c2w::companion::scan
