// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/settle/xmr_coinbase.hpp  --  W5-XMR coinbase settlement rule
//                                           (Family B: Monero / RandomX lane)
//
// AUTHORED for c2pool (AGPL-3.0). NOT a port. This is the settlement executor
// for the XMR lane: it turns the finality-gated OWED ledger for one Monero
// parent into the canonical Monero coinbase (miner_tx) that every v37 node
// re-derives byte-for-byte. It is the Family-B analogue of the Bitcoin-family
// W5 coinbase builder, and its shape is dictated by five Monero facts the
// scoping note pins (docs of record: v37-monero-randomx-lane-
// scoping.md §2.1, §2.2, §2.3, §14.2, OQ-X4, OQ-X8):
//
//   (1) NO SCRIPT. A Monero coinbase output is a *derived* one-time (stealth)
//       key P_i, never the payout-descriptor bytes. Spendability is ECDH key
//       derivation from a tx secret key r. So the coinbase cannot be built
//       statelessly from descriptor bytes; it needs r.
//   (2) DETERMINISTIC r. For "every node computes the same coinbase" to hold, r
//       must be a pure function of consensus data, not random. We derive
//       r = H_s(domain || major || chain_id || lane_commitment || prev_id ||
//               height) and publish R = r*G in tx_extra tag 0x01. (p2pool's
//       load-bearing trick; provenance in xmr_coinbase.cpp.)
//   (3) EXACT-SUM, NO BURN. Since Monero HF_VERSION_EXACT_COINBASE (=13),
//       validate_miner_transaction requires  Sum(vout.amount) == base_reward +
//       fees  EXACTLY ("coinbase transaction doesn't use full amount of block
//       reward"). Bitcoin's burn-the-remainder is a consensus failure here, so
//       W5's "coinbase may underpay / remainder burnable" assumption breaks:
//       a mandated RESIDUAL SINK absorbs every piconero the K_fair owed outputs
//       do not, plus any conversion rounding. See allocate_exact_sum().
//   (4) WEIGHT-PRICED BYTES. Each output costs block weight and, above the
//       100-block median, a quadratic reward penalty. The output count is
//       bounded by a weight-aware cap C (~2000-2700 on mainnet), not by an
//       ASIC/extranonce limit. See weight_aware_output_cap().
//   (5) MM-TREE COMMITMENT. There is no OP_RETURN. The owed_digest / lane
//       commitment rides in the miner_tx tx_extra as a leaf under the 0x03
//       merge-mining tag (OQ-X4 recommendation: forward-compatible with real
//       merge mining), NOT in the 0x02 extra-nonce.
//
// Everything ABOVE the coinbase seam is coin-agnostic and unchanged: the OWED
// KEYED_CRDT ledger, owed_digest, K_fair oldest-owed-first ordering + carry,
// D_conf floor, cut tokens. This file changes only WHERE and HOW the settlement
// is emitted for the XMR lane.
//
// ===========================================================================
//   FCMP++ / CARROT FENCE  (OQ-X10)  --  READ BEFORE TOUCHING DERIVATION
// ===========================================================================
//   The coinbase-OUTPUT derivation below --
//        R          = r * G                              (tx pubkey)
//        D_i        = 8 * r * A_i                         (ECDH shared secret)
//        P_i        = H_s(D_i || i) * G + B_i             (one-time key)
//        view_tag_i = H("view_tag" || D_i || i)[0]        (since HF15)
//        txout_to_tagged_key{ key = P_i, view_tag }       (output type)
//   -- is the PRE-CARROT Monero recipe. FCMP++/CARROT is expected to rewrite
//   address/key derivation (the view-tag scheme, the one-time-key formula, and
//   possibly the output type). Whether it changes COINBASE derivation is [?]
//   (scoping OQ-X10) and MUST NOT be guessed here. Therefore every entry point
//   that produces output keys is GUARDED on the Monero hard-fork major_version
//   (build_coinbase / derive_tx_secret_key / derive_output). A block whose
//   major_version exceeds W5_PRECARROT_MAX_MAJOR_VERSION returns ok=false with
//   a CARROT_FENCE error -- it does NOT silently build a possibly-wrong
//   coinbase. When Monero pins CARROT in a release, add a NEW derivation path
//   keyed on the new major_version; do not edit the pre-CARROT path in place.
//   `monero/master` hardforks.cpp tops at v16 as of 2026-09-05.
// ===========================================================================
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

// --- coin-layer primitives (sibling leg src/impl/xmr/coin/, AGPL-3 wrappers
//     over vendored monero-project crypto-ops + keccak, BSD-3) ---------------
#include "impl/xmr/coin/xmr_crypto_types.hpp"   // Bytes32, PublicKey, SecretKey, ...
#include "impl/xmr/coin/xmr_derivation.hpp"     // generate_key_derivation, derive_*
#include "impl/xmr/coin/xmr_blob.hpp"           // BlobWriter, tx hashes, tree_root

// --- PayoutDescriptor canon + the XMR kind extension (descriptor-kinds leg) --
#include "sharechain/v37/v37_descriptor_xmr.hpp" // v37::xmr::XMR_STD/XMR_SUB, fences

// The coin-layer surface W5 depends on is declared in the leg headers included
// above: r*G (the tx pubkey R = r*G) is xmr::coin::secret_key_to_public_key in
// xmr_derivation.hpp; ECDH derivation (generate_key_derivation / derive_public_
// key / derive_view_tag / hash_to_scalar) is the rest of that header; the blob
// serializer + consensus hashes are in xmr_blob.hpp.

namespace v37 {
namespace xmr {
namespace settle {

using ::xmr::coin::Bytes32;
using ::xmr::coin::PublicKey;
using ::xmr::coin::SecretKey;
using ::xmr::coin::EcScalar;
using ::xmr::coin::KeyDerivation;
using ::xmr::coin::Hash256;
using ::xmr::coin::ViewTag;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// FCMP++/CARROT fence key. Pins the derivation recipe to pre-CARROT Monero.
inline constexpr std::uint8_t W5_PRECARROT_MAX_MAJOR_VERSION =
    ::v37::xmr::XMR_PRECARROT_MAX_MAJOR_VERSION;  // 16 (mainnet v16, 2026-09-05)

// Coinbase maturity => D_conf floor. unlock_time = height + 60 blocks (2 h).
// (monero-project CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW; scoping §2.1.)
inline constexpr std::uint64_t XMR_COINBASE_MATURITY = 60;

// Bytes per coinbase output, worst case (varint amount 1..8 B collapsed to the
// fixed 42-B budget already used by the descriptor h_min row).
inline constexpr std::uint32_t XMR_OUTPUT_SIZE_BYTES = ::v37::xmr::XMR_OUTPUT_SIZE_BYTES; // 42

// Domain-separation tag for the deterministic tx secret key (see .cpp).
inline constexpr char TXKEY_DOMAIN[] = "c2pool-v37-xmr-txkey-v1";
// Domain-separation tag for the merge-mining commitment leaf (see .cpp).
inline constexpr char MM_LEAF_DOMAIN[] = "c2pool-v37-xmr-mm-leaf-v1";

// ---------------------------------------------------------------------------
// Inputs / outputs
// ---------------------------------------------------------------------------

// One finality-gated OWED entry to settle. `pay` MUST be an XMR kind
// (XMR_STD / XMR_SUB); `owed` is EffectiveOwed in piconero. `first_eligible`
// (bin/height at which this identity first became owed) and `identity`
// (its identity_key) are the K_fair sort keys (oldest-owed-first, then identity).
struct OwedEntry {
    ::v37::ScriptRef pay;                 // payout target (torsion-checked upstream)
    std::uint64_t    owed = 0;            // EffectiveOwed, piconero
    std::uint64_t    first_eligible = 0;  // K_fair primary key (age)
    ::v37::bytes32   identity{};          // K_fair tiebreak (identity_key)
};

// A mandated fixed output (dev / donation / finder). Its amount is deducted
// from the budget BEFORE the owed pass; on Monero each of these costs one real
// coinbase output (scoping OQ-X8). Optional; usually empty.
struct FixedOutput {
    ::v37::ScriptRef pay;                 // XMR kind
    std::uint64_t    amount = 0;          // piconero
    ::v37::bytes32   identity{};          // for provenance in the output list
};

// Everything W5 needs, all consensus-derived so the coinbase is a pure function
// of these bytes. budget := base_reward + fees (the exact-sum target).
// SAME-BLOCK PAY-NOW (operator ruling 09-25). One payee whose work THIS block
// credits at its on-chain credit cut, with its E_b at the block's exact-sum
// budget (the same fold_eb split every node books at finalization). The
// provider hands X6 the list per budget (paynow_at), sorted by identity ASC,
// eb > 0 only -- exactly the key order of the fold's credit map.
struct PayNowEntry {
    ::v37::ScriptRef pay;                 // payout target (XMR kind)
    ::v37::bytes32   identity{};          // ledger identity_key (== fold_eb key)
    std::uint64_t    eb = 0;              // E_b at this block's budget, piconero
};

// The pay-now split: `pool` over the entries in proportion to eb, exact-sum
// (Σ result == min(pool, Σ eb)), each result <= its own eb. floor(pool*eb/Σeb)
// per entry, then the leftover (< n) one piconero each by LARGEST remainder,
// ties by entry order (identity ASC). A pure function of (pool, eb vector):
// the receive side re-derives it from the on-chain cut and the committed
// V37N base (see c2pool/v37/xmr/xmr_paynow.hpp).
std::vector<std::uint64_t> paynow_split(std::uint64_t pool,
                                        const std::vector<std::uint64_t>& eb);

struct CoinbaseInputs {
    // --- FENCE key ---
    std::uint8_t   monero_major_version = 0;

    // --- Monero parent context ---
    std::uint64_t  height = 0;            // Monero block height; unlock = height + 60
    Hash256        prev_id{};             // Monero parent block id (== bin origin)
    std::uint64_t  base_reward = 0;       // consensus subsidy, piconero
    std::uint64_t  fees = 0;              // total included tx fees, piconero

    // --- v37 lane context ---
    std::uint32_t  chain_id = 0;          // v37 ChainId of the XMR lane
    ::v37::bytes32 lane_commitment{};     // owed_digest / lane digest (also MM leaf)

    // --- the ledger to settle ---
    std::vector<OwedEntry>   owed;        // eligible set (any order; sorted here)
    std::vector<FixedOutput> fixed;       // mandated dev/donation/finder (optional)
    ::v37::ScriptRef         residual_sink; // mandated absorber (XMR kind, required)
    ::v37::bytes32           residual_sink_identity{}; // its identity_key (provenance)

    // --- policy knobs (all consensus / lane params) ---
    std::uint64_t  h_min = 0;             // min owed to emit an output (piconero); dust=0
    std::uint32_t  output_cap = 0;        // weight-aware cap C (TOTAL outputs)

    // --- SAME-BLOCK PAY-NOW (empty => off; master behaviour) ---
    // When set, whatever the owed pass leaves above the folded donation
    // minimum (or, with a separate sink, the whole residual) pays the entries
    // paynow_at(budget()) returns via paynow_split, each merged into its owed
    // output when it has one, else a new output after the owed outputs
    // (identity ASC). The residual-sink identity's share stays in the
    // residual (it lands in the sink / folded donation output). paynow_n is an
    // upper bound on the entry count (the assembler's weight reserve).
    std::function<std::vector<PayNowEntry>(std::uint64_t budget)> paynow_at;
    std::size_t    paynow_n = 0;

    // --- tx_extra ---
    std::vector<unsigned char> extra_nonce; // 0x02 padded per-worker extranonce

    std::uint64_t budget() const { return base_reward + fees; }
};

// One resolved coinbase output. `identity` records whose owed this settles
// (or the sink/fixed identity) for auditing the CONS-2 delta.
struct CoinbaseOutput {
    // PayNow: a SAME-BLOCK PAY-NOW output for a payee with no owed output in
    // this coinbase (a payee that has one gets its pay-now merged there, Owed).
    enum class Role : std::uint8_t { Owed = 0, Fixed = 1, Sink = 2, PayNow = 3 };
    ::v37::ScriptRef pay;
    ::v37::bytes32   identity{};
    std::uint64_t    amount = 0;     // piconero
    Role             role = Role::Owed;
    // Only on the folded (last) fixed output when the residual folds into it
    // (residual_folds_into_fixed): the part of `amount` that settles OWED to
    // its identity (a ledger deduction); amount - owed_part is the minimum +
    // residual (coverage). 0 everywhere else. See allocate_exact_sum.
    std::uint64_t    owed_part = 0;
    // filled by the crypto pass:
    PublicKey        one_time_key{}; // P_i
    ViewTag          view_tag{};     // vt_i
};

enum class BuildError : std::uint8_t {
    None = 0,
    CarrotFence,        // major_version > W5_PRECARROT_MAX_MAJOR_VERSION
    ZeroBudget,         // base_reward + fees == 0 (impossible on XMR tail emission)
    FixedExceedsBudget, // Sum(fixed) > budget
    CapTooSmall,        // output_cap < fixed.size() + 1 (no room for the sink; + 0 when it folds, S1)
    BadSinkDescriptor,  // residual_sink is not a valid XMR ref
    BadPayeeDescriptor, // an owed/fixed pay is not a valid XMR ref
    DerivationFailed,   // r*G or an ECDH derivation failed (bad point)
};

const char* to_string(BuildError e);

// The canonical W5-XMR coinbase.
struct BuiltCoinbase {
    bool        ok = false;
    BuildError  error = BuildError::None;
    std::string detail;

    std::uint64_t budget = 0;

    SecretKey  r{};   // deterministic tx secret key
    PublicKey  R{};   // r*G  -> tx_extra 0x01

    std::vector<CoinbaseOutput> outputs;    // CANONICAL order (see allocate_exact_sum)

    std::vector<unsigned char>  tx_extra;   // 0x01 pubkey || 0x02 nonce || 0x03 MM tag
    std::vector<unsigned char>  prefix;     // full serialized tx prefix (head || extra)
    Hash256    prefix_hash{};               // keccak256(prefix)
    Hash256    coinbase_tx_hash{};          // v2 RCTTypeNull leaf-0 hash
    Hash256    mm_root{};                    // the 0x03 merge-mining root (single leaf)
};

// A received coinbase as parsed off the wire / out of a peer's block, for the
// ACCEPT re-derivation check.
struct ReceivedCoinbase {
    PublicKey R{};                                   // tx_extra 0x01
    std::vector<std::uint64_t> amounts;              // vout amounts, in order
    std::vector<PublicKey>     keys;                 // vout one-time keys, in order
    std::vector<ViewTag>       view_tags;            // vout view tags, in order
    std::vector<unsigned char> tx_extra;             // whole tx_extra bytes
};

// ---------------------------------------------------------------------------
// Pure selection: K_fair oldest-owed-first + exact-sum + residual sink.
// NO crypto -- piconero integer arithmetic only, so it is cheaply unit-testable
// and its exact-sum invariant is provable by inspection. Deterministic in the
// input bytes: `owed` is sorted internally by (first_eligible asc, identity asc).
//
// Canonical output order (consensus):
//     [ K_fair owed outputs ]  ++  [ fixed outputs ]  ++  [ residual sink? ]
// The sink is present iff the residual is > 0 -- EXCEPT when the LAST fixed
// output IS the residual sink (same ref + identity: residual_folds_into_fixed(), the fee model's
// single donation output, rulings S1/S2): then there is never a separate sink
// output and no sink slot is reserved; that last fixed output pays
// max(declared amount, residual), i.e. it absorbs the whole residual, and its
// declared amount is a MINIMUM taken from the residual first and, only when
// the owed pass exhausted the budget, from the LARGEST owed output (ties: the
// earliest in K_fair order; the shortfall stays owed).
//
// MERGE (one output per fold identity, operator ruling 09-23): when the fold
// identity is ALSO in the owed set (the donation holding give-author credit),
// it is paid in the K_fair pass at its own age position exactly like any other
// payee (budget, h_min, the S2 dust candidates), but it takes NO output slot
// of its own: its payout is added into the folded output, which is then
//     amount    = owed_paid + minimum + residual        (ONE output, last)
//     owed_part = min(owed_in, amount - minimum)
// where owed_in is fold_identity_owed(in). owed_part is the K_fair payout
// plus, when the pass left residual, the rest of owed_in out of that residual
// (the output pays the fold identity either way; this books what it
// receives against what it is owed first). The rule depends only on owed_in
// and the on-chain amount, so a receiver that knows owed_in (committed in the
// coinbase by the fee model) re-derives owed_part without the ledger.
// Invariant on success:
//     Sum(result.amount) == in.budget()      (exact-sum, no burn)
// and every result.amount > 0, and result.size() >= 1, and result.size() <=
// in.output_cap.
//
// Returns an empty vector and sets *err (if non-null) on ZeroBudget /
// FixedExceedsBudget / CapTooSmall.
// ---------------------------------------------------------------------------
std::vector<CoinbaseOutput> allocate_exact_sum(const CoinbaseInputs& in,
                                               BuildError* err = nullptr);

// S1: true iff the last fixed output IS the residual sink -- it pays
// `residual_sink` (ScriptRef equality) under `residual_sink_identity` -- i.e.
// the residual folds into it and no separate sink output / slot exists.
// Callers that pre-check the output cap must use the same slot rule.
bool residual_folds_into_fixed(const CoinbaseInputs& in);

// The owed the input set holds for the fold identity (sum over owed entries
// with that identity and ref; 0 when the residual does not fold or the
// identity holds no owed). This is the owed_in of the MERGE rule above.
std::uint64_t fold_identity_owed(const CoinbaseInputs& in);

// ---------------------------------------------------------------------------
// Deterministic tx secret key r = H_s(domain || major || chain_id ||
// lane_commitment || prev_id || varint(height)). FENCED: returns false if
// major_version > W5_PRECARROT_MAX_MAJOR_VERSION.
// ---------------------------------------------------------------------------
bool derive_tx_secret_key(const CoinbaseInputs& in, SecretKey& r_out);

// Per-output one-time key + view tag for payout-target `pay` at vout index `i`,
// given the tx secret key r. FENCED at build_coinbase; kept here for KATs.
//   spend B := pay.payload[0..32),  view A := pay.payload[32..64)
// Returns false on a bad point.
bool derive_output(const SecretKey& r, const ::v37::ScriptRef& pay,
                   std::size_t vout_index, PublicKey& P_out, ViewTag& vt_out);

// The merge-mining commitment root for a single v37 leaf:
//   mm_root = keccak256(MM_LEAF_DOMAIN || chain_id_le32 || lane_commitment)
// For a multi-aux tree (Tari coexistence) this is one leaf under a real Merkle
// root; that generalization is the template/aux leg's concern (OQ-X4).
Hash256 mm_commitment_root(std::uint32_t chain_id, const ::v37::bytes32& lane_commitment);

// Assemble tx_extra: 0x01 pubkey R || 0x02 nonce(extra_nonce) || 0x03 MM tag(mm_root).
std::vector<unsigned char> assemble_tx_extra(const PublicKey& R,
                                             const std::vector<unsigned char>& extra_nonce,
                                             const Hash256& mm_root);

// ---------------------------------------------------------------------------
// Build the whole canonical coinbase from consensus inputs. FENCED.
// ---------------------------------------------------------------------------
BuiltCoinbase build_coinbase(const CoinbaseInputs& in);

// ---------------------------------------------------------------------------
// Every-node ACCEPT check (W3): rebuild the canonical coinbase from `in` and
// byte-compare it against `got`. This is p2pool's SideChain::verify discipline
// ("pays out to a wrong wallet at index i") applied to the OWED settlement list.
//   matches == true, first_bad_index == -1        : identical.
//   first_bad_index >= 0                           : first divergent vout index.
//   first_bad_index == IDX_R / IDX_EXTRA / IDX_COUNT: structural mismatch codes.
// ---------------------------------------------------------------------------
struct MatchResult {
    bool        matches = false;
    int         first_bad_index = -1;
    std::string reason;
};
inline constexpr int IDX_R     = -2;  // tx pubkey R mismatch
inline constexpr int IDX_EXTRA = -3;  // tx_extra (commitment/nonce) mismatch
inline constexpr int IDX_COUNT = -4;  // output count mismatch
inline constexpr int IDX_BUILD = -5;  // our own rebuild failed (fence/inputs)

MatchResult canonical_coinbase_matches(const CoinbaseInputs& in,
                                       const ReceivedCoinbase& got);

// ---------------------------------------------------------------------------
// Weight-aware output cap C. A Monero coinbase output costs block weight; above
// the 100-block median the block pays a quadratic reward penalty, so paying too
// many owed outputs shrinks the reward -- self-limiting. C is the min of:
//   * penalty headroom: floor((median + median/8 - reserved) / 42), the count
//     that keeps the block inside the penalty-free zone given the non-coinbase
//     tx budget already reserved; and
//   * wire_cap: the per-carrier receipt/message ceiling (R_MAX-derived).
// Mainnet median ~ tens of KB, penalty-free floor 300000 B => C ~ 2000-2700
// (scoping §2.3). Both terms are lane parameters; this is the derivation.
// ---------------------------------------------------------------------------
std::uint32_t weight_aware_output_cap(std::uint64_t median_block_weight,
                                      std::uint64_t reserved_nonminer_weight,
                                      std::uint32_t wire_cap);

} // namespace settle
} // namespace xmr
} // namespace v37
