// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// The KEY-FREE half of the DASH builders: the shared UTXO / fee-mode / signed-tx
// types and the zero-fee SWEEP planner (plan_sweep, the unsigned serializer,
// the size estimate and the loader-file emit). It is the public face of the
// c2wallet-dash-plan library, which the online, key-free companion links to
// plan exactly what the offline signer plans from the same UTXO export.
//
// RULE: no header of c2wallet-dash-plan declares or includes a key type. This
// header, DashAddress.hpp, UtxoIntake.hpp, InjectManifest.hpp,
// GovCollateral.hpp, InjectCaps.hpp, InjectMaturity.hpp and DashError.hpp are
// std-only and never include KeyScan.hpp (FoundKey) or the signer. The signing
// declarations (sign_sweep, sign_external_unsigned, verify_signed_funding_tx)
// stay in SweepTx.hpp, which includes this header plus KeyScan.hpp; the
// collateral builder stays in CollateralTx.hpp. ci/check_key_free.sh runs over
// the built archive and the companion binaries that link it.
//
// Every planning refusal throws DashAbort and builds nothing.

#include "InjectCaps.hpp"
#include "InjectMaturity.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace c2w::dash {

// duffs per DASH; the governance fee is 1 DASH (governance/object.h:30).
inline constexpr int64_t kCoin = 100000000;
inline constexpr int64_t kGovernanceProposalFee = 1 * kCoin;
inline constexpr int64_t kMaxMoney = 21000000 * kCoin; // Dash Core amount.h MAX_MONEY
inline constexpr int64_t kDustDuffs = 5460;
inline constexpr int64_t kDefaultFeeRate = 1000; // duffs/kB (Dash min relay)
inline constexpr int64_t kDefaultMinConf = 101;  // funding UTXOs are often coinbase
inline constexpr int64_t kCoinbaseMaturity = maturity::kCoinbaseMaturity; // consensus COINBASE_MATURITY

// Relay: a relayable tx paying fee_rate. InjectOnlyZeroFee: fee exactly 0, for
// the c2pool inject / pin lane only (Dash Core peers will not relay it).
enum class FeeMode : uint8_t { Relay, InjectOnlyZeroFee };

struct Utxo {
    std::string txid;                // display-order hex
    uint32_t vout = 0;
    int64_t satoshis = 0;
    int64_t confirmations = 0;
    std::string script_pubkey_hex;   // validated against the funding script when present;
                                     // REQUIRED in inject mode, with sweep_all, and for SweepTx
    // true or nullopt (unknown, treated as coinbase) => max(min_confirmations,
    // kCoinbaseMaturity) confirmations; false => one confirmation is enough.
    std::optional<bool> coinbase = std::nullopt;
    // Block height that created the output; 0 = unknown. The target-height
    // re-screen (rescreen_at_height) projects confirmations from it.
    int64_t height = 0;
};

struct SignedTx {
    std::string hex;   // raw signed transaction hex — the only secret-free artifact
    std::string txid;  // display-order txid
    size_t size = 0;
};

// ── the sweep planner ────────────────────────────────────────────────────────
//
// Zero-fee SWEEP / consolidation for c2pool tx injection — the C++ port of the
// reference c2wallet.py sign / sign-batch flow plus the planning half it left
// to hand-built unsigned hex. Every mature UTXO of one P2PKH funding address is
// spent to one destination (the funding address by default) with a fee of
// exactly 0, split greedily into as few txs as the node's inject caps allow
// (InjectCaps.hpp). Dash Core peers do not relay a zero-fee tx; the output file
// is for --embedded-tx-inject-hex / --pin-local-tx-hex on a c2pool node, whose
// own block carries it.

// FeeMode::Relay for a sweep (slice 2): a FEE-PAYING consolidation for plain
// relay through dashd `sendrawtransaction`, for when no node can resolve the
// inputs of a zero-fee pin. The rate is explicit, in duffs per byte, and must
// lie in [kMinRelayFeePerByte, kMaxRelayFeePerByte]: 1 duff/B is Dash Core's
// default minimum relay fee (1000 duffs/kB), 100 duffs/B the same ceiling the
// collateral builder applies (100000 duffs/kB). Each tx pays rate x its
// worst-case signed size, so the real rate is never below the one asked for.
inline constexpr int64_t kMinRelayFeePerByte = 1;
inline constexpr int64_t kMaxRelayFeePerByte = 100;
// Dash Core's dust threshold for a P2PKH output: (34 + 148) B at the 3000
// duffs/kB dust relay fee. No sweep output is built below it, in either mode.
inline constexpr int64_t kP2pkhDustDuffs = 546;

struct SweepRequest {
    std::string funding_address;
    std::string destination_address;    // empty => the funding address
    std::vector<Utxo> utxos;            // every one must carry its scriptPubKey
    int64_t min_confirmations = kDefaultMinConf;
    int64_t dust_floor = 0;             // UTXOs below this many duffs are left out
    bool testnet = false;
    bool preserve_input_order = false;  // default sorts by (display txid, vout)
    size_t max_inputs_per_tx = caps::kMaxInjectInputs;  // may only tighten the cap
    size_t max_tx_bytes = caps::kMaxInjectTxBytes;      // may only tighten the cap
    PubkeyEncoding key_encoding = PubkeyEncoding::Unknown;
    // InjectOnlyZeroFee (default): fee exactly 0, fee_rate_per_byte must be 0.
    // Relay: fee = fee_rate_per_byte x est signed bytes, rate in [1, 100].
    FeeMode fee_mode = FeeMode::InjectOnlyZeroFee;
    int64_t fee_rate_per_byte = 0;
};

struct SweepTxPlan {
    std::vector<Utxo> inputs;
    int64_t value_out = 0;               // inject: == sum of inputs (fee 0 by construction);
                                         // relay: sum of inputs - fee
    int64_t fee = 0;                     // inject: 0; relay: rate x est_signed_bytes
    std::vector<uint8_t> dest_spk;
    std::vector<uint8_t> unsigned_tx;    // the exact bytes sign_sweep signs
    size_t est_signed_bytes = 0;
};

struct SweepBatchPlan {
    std::vector<SweepTxPlan> txs;
    int64_t total_in = 0;
    size_t skipped_immature = 0;
    size_t skipped_dust = 0;
    std::string funding_address;
    std::string destination_address;
    bool testnet = false;
    std::string summary;                 // dry-run summary (public data only)
    FeeMode fee_mode = FeeMode::InjectOnlyZeroFee;
    int64_t fee_rate_per_byte = 0;       // Relay only
    int64_t total_fee = 0;               // sum of the txs' fees (0 for inject)
};

// Screen the UTXOs (strict: scriptPubKey required and must pay the funding
// address; no outpoint twice), drop dust and immature ones (listed in the
// summary), order them, and split greedily so every tx stays within
// min(max_inputs_per_tx, kMaxInjectInputs) inputs and min(max_tx_bytes,
// kMaxInjectTxBytes) estimated signed bytes. More txs than one node's inject
// pool holds at once is a WARNING in the summary, not a refusal. Relay mode
// refuses a rate outside [1, 100] duffs/B, and a tx whose output after the fee
// would be below kP2pkhDustDuffs or below its own fee; inject mode refuses a
// non-zero rate. No mode builds an output below kP2pkhDustDuffs.
SweepBatchPlan plan_sweep(const SweepRequest& req);

// The c2pool loader file (== artifact::SignedContainer::emit): one lowercase raw
// tx hex per line, each '\n'-terminated, no header. Refuses an empty list or a
// line that is not lowercase even-length hex.
std::string emit_inject_file(const std::vector<SignedTx>& txs);

// Serialize the unsigned (blank scriptSig) legacy tx every DASH builder signs:
// version 2, every input at sequence kSequenceFinal, locktime 0.
std::vector<uint8_t> serialize_unsigned_legacy_tx(
    const std::vector<Utxo>& inputs,
    const std::vector<std::pair<int64_t, std::vector<uint8_t>>>& outputs);

// Worst-case signed size of an unsigned P2PKH-input tx (see InjectCaps.hpp).
size_t est_signed_size(size_t unsigned_bytes, size_t n_inputs, PubkeyEncoding encoding);

} // namespace c2w::dash
