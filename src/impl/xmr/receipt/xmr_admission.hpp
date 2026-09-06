// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/receipt/xmr_admission.hpp
//   V37 W2 admission-order change for pow_verify_class = keyed_heavy (RandomX).
//
// X4 (real impl): keeps the ratified INVERTED order and its reason strings, and
// adds one behaviour the verifier needs on a memory-pressured host / in CI: a
// CI-GATED RandomX. When the heavy hasher is not wired (h.rx_check is null), the
// pipeline runs stages 1-4 for real and reports stage 5 as SKIPPED rather than
// forcing a 256-MiB, ~15 ms RandomX evaluation. That is exactly the
// "verify() end-to-end EXCEPT the RandomX hash (CI-gated)" contract.
//
// Design of record:
//   docs/c2pool-v37-share-format.md §3 (Family-A per-receipt order), §8 (pipeline);
//   v37-monero-randomx-lane-scoping.md §1.4 item 2, §2.4 item 1, §3.2;
//   share-format-addendum §B1 (pow_verify_class), §B3 (this order), §B4 (T_origin).
//
// THE CHANGE. Family-A §3 validates a receipt PoW-FIRST:
//   1 PoW(header.hash <= T_origin) -> 2 R-1 pin -> 3 bindings -> 4 context -> 5 dedup.
// Correct only when the PoW hash is the cheapest step. On a keyed_heavy lane the
// RandomX hash is the MOST expensive step (~10-15 ms light, 256 MiB cache) and
// every other check is microseconds, so PoW-first lets an unauthenticated peer
// force a 15 ms RandomX evaluation with a replayed or expired receipt (~65 bogus
// carriers/s saturate one light-mode core). keyed_heavy INVERTS the order so
// RandomX is reached only by a receipt that already passed every cheap check:
//
//   1 dedup  ->  2 expiry/context  ->  3 structural + binding  ->  4 R-1 target  ->  5 RandomX LAST
//
// This is exactly p2pool's order in SideChain::add_external_block:
//   min-difficulty -> expected sidechain difficulty -> known mainchain parent
//   (m_prevId) -> seed lookup for m_txinGenHeight -> get_pow_hash -> check_pow,
// with RandomX_Hasher::calculate (VM_LANE_P2P) strictly last.
//
// Two keyed_heavy-specific subtleties, both load-bearing:
//   (D) DEDUP KEY. Family-A dedups on header.hash (its PoW hash) -- free there.
//       Here the PoW hash is the expensive thing we are deferring, so dedup MUST
//       key on a CHEAP identifier: receipt_id = cheap_digest(hashing_blob). Sound
//       because prev_id, nonce and tree_root are all inside the blob and every
//       commitment is bound under tree_root, so distinct receipts => distinct
//       blobs. Deduping on the RandomX hash would defeat the whole inversion.
//   (T) T_origin ORDER. R-1 pinning compares T_origin to the consensus share
//       difficulty for bin(receipt). T_origin has no Monero header home (§B4): it
//       is OPENED (via the bound side data) during the structural step. So
//       structural/binding (3) MUST precede R-1 (4): only after opening tx_extra
//       is the committed T_origin trustworthy, and it is that opened value --
//       never the relayed preimage taken on faith -- that gates RandomX in (5).
// ---------------------------------------------------------------------------
#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "xmr_receipt.hpp"

namespace v37 {
namespace xmr {

// -----------------------------------------------------------------------------
// §B1: pow_verify_class, a new digest-committed LaneParams attribute (like n_ctx).
// Integration: add to v37::LaneParams (src/sharechain/v37/v37_lane.hpp), right
// after `u64 n_ctx`:
//     PowVerifyClass pow_verify_class = PowVerifyClass::stateless_cheap; // digest-committed
//     LaneKeyedHeavy keyed_heavy{};   // meaningful iff pow_verify_class == keyed_heavy
// and fold pow_verify_class (u8) + the keyed_heavy block into the lane digest
// preimage exactly where n_ctx is folded, so a lane cannot silently switch class.
// Family-A lanes keep the default (stateless_cheap) and are byte-identical.
// -----------------------------------------------------------------------------
enum class PowVerifyClass : u8 {
    stateless_cheap = 0,   // SHA256d / X11 -- PoW is the cheapest step (Family-A §3)
    memory_light    = 1,   // Scrypt -- light memory, PoW still cheap-ish; Family-A order OK
    keyed_heavy     = 2,   // RandomX -- PoW is the most expensive step; INVERTED order
};

// keyed_heavy consensus parameters. All digest-committed. Values are the OQ-X2
// recommendation; operator-ratified at wiring.
struct LaneKeyedHeavy {
    u64           r_max               = budget::R_MAX_XMR;          // 2 (vs Family-A 4)
    u64           per_receipt_budget  = budget::PER_RECEIPT_BUDGET; // 768 B
    u64           per_lane_budget     = budget::PER_LANE_BUDGET;    // r_max * per_receipt_budget
    u64           n_ctx               = 2;   // XMR bins; 2 * 120-s blocks ~ 4 min context
    SeedRefPolicy seed_ref_policy     = SeedRefPolicy::DerivedFromBin;  // 0 B on wire
    // Index-retention horizon (NON-derived, must be stated): the mainchain index
    // must reach >= max(n_ctx + 2, SEED_EPOCH + SEED_LAG) blocks back so
    // seed_height(bin) resolves. The seed lag DOMINATES: 2048 + 64 = 2112 blocks
    // (vs n_ctx + 2 = 4 for the Family-A dedup horizon). p2pool holds two caches
    // for exactly this reason.
    u64 index_retention_blocks = 2112;
    static constexpr u64 SEED_EPOCH = 2048;  // RandomX seed rotates every 2048 blocks
    static constexpr u64 SEED_LAG   = 64;    // ...with a 64-block lag
};

// -----------------------------------------------------------------------------
// The five admission stages, in keyed_heavy consensus order. The stage a receipt
// fails at is reported so the W3 relay layer prices griefing correctly: a receipt
// rejected before RandomX (stages 1-4) cost only microseconds; only a stage-5
// reject actually spent ~15 ms of RandomX.
// -----------------------------------------------------------------------------
enum class AdmitStage : u8 {
    Dedup      = 1,   // cheap: receipt_id in recent-event set?           (~ns)
    Expiry     = 2,   // cheap: bin(carrier) - bin(receipt) <= n_ctx      (~ns)
    Structural = 3,   // cheap: open coinbase, tree branch, bindings      (~us, a few Keccak)
    R1Target   = 4,   // cheap: opened T_origin == consensus target(bin)  (~ns, 128-bit cmp)
    RandomX    = 5,   // HEAVY: rx_light_hash(seed, blob) <= T_origin      (~10-15 ms)
    Accepted   = 0,
};

// Whether the heavy stage actually ran.
enum class RandomXStatus : u8 {
    NotReached   = 0,   // rejected at stages 1-4; RandomX never touched
    Ran          = 1,   // rx_check invoked and returned (pass or fail)
    SkippedCIGated = 2, // rx_check not wired (null): stages 1-4 passed, 5 deferred
};

struct AdmitOutcome {
    bool          ok    = false;
    AdmitStage    stage = AdmitStage::Dedup;   // where it stopped (or Accepted)
    std::string   reason;                      // human-readable; empty on accept
    RandomXStatus randomx = RandomXStatus::NotReached;

    bool spent_randomx() const { return randomx == RandomXStatus::Ran; }

    static AdmitOutcome accept(RandomXStatus rx) {
        return AdmitOutcome{true, AdmitStage::Accepted, {}, rx};
    }
    static AdmitOutcome reject(AdmitStage s, std::string why, RandomXStatus rx) {
        return AdmitOutcome{false, s, std::move(why), rx};
    }
};

// What the structural/binding open recovers from the receipt once it is proven
// against the blob's tree_root. Everything here is bound: tamper with any of it
// and the tree_root (hence the RandomX-signed blob) changes.
struct OpenedCommitment {
    Difficulty t_origin;          // §B4: committed share difficulty, opened via side data
    bytes32    payout_identity{}; // payout-descriptor identity_key() bound in side data
    u32        chain_id = 0;      // lane chain id (must equal this lane's)
    bytes32    tree_root{};       // the recomputed root (== the one inside the blob)
    bytes32    miner_tx_hash{};   // leaf-0 hash the branch was verified against
    // prev_own_share is intentionally NOT surfaced: display-only per §4 round-2 #1.
};

// Verifier hooks. The header owns the ORDER; the crypto/index/RandomX bodies are
// injected (see xmr_receipt_verify.{hpp,cpp} for the REAL bodies over X1's
// primitives; the node index and the randomx-vendor leg supply the rest). This
// keeps the admission order self-contained, unit-testable, and free of the heavy
// RandomX dependency.
struct AdmissionHooks {
    // (D) cheap dedup identity of a receipt -- a plain digest of the hashing blob,
    // NOT the RandomX hash. Deterministic; matches the §5 dedup-store key class.
    std::function<bytes32(const HashingBlob&)> cheap_digest;

    // recent-event dedup-store membership (§5). True => already accounted.
    std::function<bool(const bytes32& receipt_id)> seen;

    // bin(receipt) = height(prev_id), resolved against the committed index; false
    // if prev_id is unknown / outside index_retention_blocks (== p2pool's "unknown
    // mainchain parent" reject in add_external_block).
    std::function<bool(const HashingBlob&, u64& out_bin)> bin_of;

    // Structural + binding open (§B3 step 3): resume the Keccak midstate over
    // tail||tx_extra, finalize H(prefix), form the RCTTypeNull tx hash, walk the
    // tree_branch, require the recomputed root == the tree_root inside the blob,
    // then recompute the v37 0x03 MM leaf from the bound side data and read
    // T_origin / identity / chain_id out of it. Also checks self-carriage
    // (payout_identity == carrier's) and chain_id. A few Keccak-256 over <~1 KB.
    std::function<bool(const MoneroReceipt&, const bytes32& carrier_identity,
                       u32 lane_chain_id, OpenedCommitment& out)> open_and_bind;

    // R-1 pinning oracle: the consensus share difficulty pinned for this bin.
    std::function<bool(u64 bin, Difficulty& out)> consensus_difficulty;

    // Seed hash for bin's seed_height, per the chosen SeedRefPolicy. For
    // DerivedFromBin the carried arg is ignored; for CarriedSeedHash the derived
    // value MUST equal the carried one (else reject -- index wins, never the wire).
    std::function<bool(u64 bin, const SeedRef&, bytes32& out_seed)> seed_for_bin;

    // (5) THE ONLY heavy call: rx light-verify. Computes rx_slow_hash(seed, blob)
    // and returns whether it satisfies difficulty d (monero check_pow). Injected by
    // the randomx-vendor leg. Reached only if stages 1-4 all passed.
    //
    // CI GATE: if this std::function is EMPTY (default on a light host / CI without
    // the 256-MiB cache), stage 5 is SKIPPED and the outcome is accept() with
    // RandomXStatus::SkippedCIGated -- the receipt passed every cheap structural
    // and binding check, and only the heavy hash is deferred.
    std::function<bool(const bytes32& seed, const HashingBlob&, const Difficulty& d,
                       bytes32& out_pow)> rx_check;
};

// Per-receipt admission for a keyed_heavy lane. Pure control flow; the order IS
// the deliverable. On accept, the CALLER inserts receipt_id into the dedup store
// and performs the §4 push: push(miner, work(T_origin), flags|L0F_RECEIPT,
// bin(receipt)).
inline AdmitOutcome admit_receipt_keyed_heavy(
        const MoneroReceipt&  r,
        const bytes32&        carrier_identity,
        u64                   carrier_bin,
        u32                   lane_chain_id,
        const LaneKeyedHeavy& lp,
        const AdmissionHooks& h)
{
    // ---- pre-gate: size cap (cheapest possible, no crypto) --------------------
    if (r.wire_size() > lp.per_receipt_budget)
        return AdmitOutcome::reject(AdmitStage::Structural,
                                    "receipt exceeds per-receipt byte budget",
                                    RandomXStatus::NotReached);

    // ---- stage 1: DEDUP (cheap digest, never the RandomX hash) ----------------
    const bytes32 receipt_id = h.cheap_digest(r.hashing_blob);
    if (h.seen(receipt_id))
        return AdmitOutcome::reject(AdmitStage::Dedup, "replayed receipt (dedup hit)",
                                    RandomXStatus::NotReached);

    // ---- stage 2: EXPIRY / CONTEXT --------------------------------------------
    u64 bin = 0;
    if (!h.bin_of(r.hashing_blob, bin))
        return AdmitOutcome::reject(AdmitStage::Expiry,
                                    "prev_id unknown or outside index horizon",
                                    RandomXStatus::NotReached);
    if (bin > carrier_bin)   // a receipt bin may never exceed its carrier's (§4)
        return AdmitOutcome::reject(AdmitStage::Expiry, "receipt bin ahead of carrier",
                                    RandomXStatus::NotReached);
    if (carrier_bin - bin > lp.n_ctx)
        return AdmitOutcome::reject(AdmitStage::Expiry, "receipt expired (> N_CTX bins)",
                                    RandomXStatus::NotReached);

    // ---- stage 3: STRUCTURAL + BINDING (opens the coinbase -> committed T_origin)
    OpenedCommitment oc;
    if (!h.open_and_bind(r, carrier_identity, lane_chain_id, oc))
        return AdmitOutcome::reject(AdmitStage::Structural,
                                    "coinbase opening / tree branch / binding failed",
                                    RandomXStatus::NotReached);

    // ---- stage 4: R-1 TARGET PINNING (uses the OPENED T_origin, not a preimage) -
    Difficulty pinned;
    if (!h.consensus_difficulty(bin, pinned))
        return AdmitOutcome::reject(AdmitStage::R1Target, "no consensus target for bin",
                                    RandomXStatus::NotReached);
    if (oc.t_origin != pinned || oc.t_origin.is_zero())
        return AdmitOutcome::reject(AdmitStage::R1Target,
                                    "T_origin not pinned to consensus share target",
                                    RandomXStatus::NotReached);

    // ---- stage 5: RANDOMX, LAST -- the only step that can cost ~15 ms ----------
    bytes32 seed{};
    if (!h.seed_for_bin(bin, r.seed_ref, seed))
        return AdmitOutcome::reject(AdmitStage::RandomX,
                                    "seed unresolved / carried!=derived",
                                    RandomXStatus::NotReached);

    if (!h.rx_check) {
        // CI GATE: heavy hasher not wired. Everything cheap passed; defer RandomX.
        return AdmitOutcome::accept(RandomXStatus::SkippedCIGated);
    }
    bytes32 pow{};
    if (!h.rx_check(seed, r.hashing_blob, oc.t_origin, pow))
        return AdmitOutcome::reject(AdmitStage::RandomX, "RandomX PoW below T_origin",
                                    RandomXStatus::Ran);

    return AdmitOutcome::accept(RandomXStatus::Ran);
}

// Dispatch by lane verify class. stateless_cheap / memory_light keep the Family-A
// §3 PoW-first order (handled by the Family-A path -- not reimplemented here); only
// keyed_heavy takes the inverted pipeline above.
enum class VerifyPath : u8 { FamilyA_PoWFirst = 0, FamilyB_RandomXLast = 1 };

inline VerifyPath verify_path_for(PowVerifyClass c) {
    return c == PowVerifyClass::keyed_heavy ? VerifyPath::FamilyB_RandomXLast
                                            : VerifyPath::FamilyA_PoWFirst;
}

} // namespace xmr
} // namespace v37
