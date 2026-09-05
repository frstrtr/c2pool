// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/receipt/xmr_receipt.hpp
//   V37 Family-B (Monero / RandomX) work-receipt envelope -- the MoneroReceipt.
//
// X4 (receipt envelope, real impl): this REPLACES the foundation's declaration-
// only scaffold. It keeps the ratified field shape (§1.5 / share-format-addendum
// §B2) so the wire leg (xmr_carrier_wire.hpp) stays byte-compatible, and adds the
// one piece the scaffold only *referred* to -- the ReceiptSideData PREIMAGE that
// makes T_origin / payout_identity / chain_id RECOVERABLE and BOUND (the scaffold
// carried a bare `bytes32 info_digest` and a comment "preimage relayed
// alongside"; here that preimage is a concrete, hashed, tx_extra-committed type).
//
// Design of record:
//   docs/c2pool-v37-share-format.md §3 (Family-A RDWR envelope this extends),
//     §7 (consensus parameters), §8 (whole-share pipeline);
//   v37-monero-randomx-lane-scoping.md §1.4/§1.5, §2.4/§2.5, §16.
//
// This header is ABOVE the sharechain seam and MUST NOT be included from
// src/sharechain/v37/* consensus-digest code. It reuses the Family-A wire idioms
// (fixed field order, little-endian, one-canon) but carries a Monero-shaped
// proof: a RandomX PoW living inside the ~77-B hashing blob, plus a Keccak-256
// midstate "opening" of the miner_tx prefix at the tx_extra boundary (Tari
// MoneroPowData / RFC-0132 pow_data.rs is the working precedent).
//
// Monero symbols mirrored (SChernykh/p2pool + monero-project/monero, read
// 2026-09-05): get_block_hashing_blob, get_block_longhash / rx_slow_hash,
// tree_hash / tree_branch (tree-hash.c), TransactionPrefix{version, unlock_time,
// vin(TXIN_GEN 0xFF), vout(TXOUT_TO_TAGGED_KEY 3), extra}, RCTTypeNull coinbase
// tx-hash triple Keccak(H(prefix)||H(rct_base)||H(prunable=null_hash)),
// tx_extra tags 0x01 pubkey / 0x02 extra-nonce / 0x03 merge-mining, RX_BLOCK_VERSION.
//
// FCMP++/CARROT FENCE: nothing in THIS file derives coinbase OUTPUTS, so the
// header is fork-major-version-agnostic. Deterministic-r one-time-key derivation
// lives in the settle leg (xmr_coinbase.cpp) behind a pre-CARROT guard. The
// receipt only *opens* an already-built coinbase's prefix, which CARROT does not
// change (the tx-prefix serialization + Keccak tree-hash are stable across the
// fork; only the OUTPUT key derivation moves).
// ---------------------------------------------------------------------------
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace v37 {
namespace xmr {

using u8  = std::uint8_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// Structurally identical to v37::bytes32 (src/sharechain/v37/v37_hash.hpp); kept
// local so this above-the-seam header pulls in no consensus-digest header. When
// integrated, `using v37::bytes32;` is ABI-compatible.
using bytes32 = std::array<u8, 32>;

// Monero difficulty is 128-bit (monero difficulty_type, p2pool difficulty_type).
// T_origin is a difficulty, not a compact "bits" target, because a Monero header
// has no bits field (§B4). check_pow semantics (monero check_hash_128): a hash h
// passes at difficulty d iff the 512-bit product (h as 256-bit LE) * d has its
// high 256 bits zero, i.e. h <= floor(2^256 / d).
struct Difficulty {
    u64 lo = 0;
    u64 hi = 0;
    friend bool operator==(const Difficulty& a, const Difficulty& b) {
        return a.lo == b.lo && a.hi == b.hi;
    }
    friend bool operator!=(const Difficulty& a, const Difficulty& b) {
        return !(a == b);
    }
    bool is_zero() const { return lo == 0 && hi == 0; }
};

// -----------------------------------------------------------------------------
// Component 1: the hashing blob (RandomX PoW input). NOT the block header alone.
//   get_block_hashing_blob := serialize(block_header) || tree_root(32) || varint(n_tx)
//   block_header := varint(major) varint(minor) varint(timestamp) prev_id[32] nonce[4 LE]
// ~76-77 B. `prev_id` supplies the origin bin: bin(receipt) = height(prev_id),
// resolved against the committed mainchain index (never carried in the receipt).
// -----------------------------------------------------------------------------
struct HashingBlob {
    // Carried verbatim (varint-encoded, so variable length ~76-77 B): the exact
    // byte string fed to rx_slow_hash, and whose embedded tree_root the coinbase
    // opening must reconcile to. Parsed lazily; never rebuilt.
    std::vector<u8> bytes;

    bool empty() const { return bytes.empty(); }
    std::size_t size() const { return bytes.size(); }
};

// -----------------------------------------------------------------------------
// Component 2: seed reference. RandomX key = the Monero block hash at
// seed_height(bin) (rotates every 2048 blocks, 64-block lag). Two policies (OQ-X2):
//   DerivedFromBin (0 B, RECOMMENDED): verifier derives the seed from the committed
//     index and cannot disagree with it; nothing on the wire.
//   CarriedSeedHash (32 B, Tari style): 32-B seed hash on the wire, cross-checked
//     against the index (a disagreement is a hard reject, never trusted over index).
// -----------------------------------------------------------------------------
enum class SeedRefPolicy : u8 {
    DerivedFromBin  = 0,   // 0 B on the wire
    CarriedSeedHash = 1,   // 32 B on the wire
};

struct SeedRef {
    SeedRefPolicy policy = SeedRefPolicy::DerivedFromBin;
    std::optional<bytes32> carried;   // present iff policy == CarriedSeedHash

    std::size_t wire_size() const {
        return policy == SeedRefPolicy::CarriedSeedHash ? sizeof(bytes32) : 0;
    }
};

// -----------------------------------------------------------------------------
// Component 3: coinbase opening -- a Keccak-256 sponge midstate of the miner_tx
// TransactionPrefix absorbed up to the tx_extra boundary, plus the not-yet-
// absorbed tail bytes and the tx_extra bytes in the clear. `extra` is the LAST
// prefix field, so opening it while proving H(prefix) needs only:
//   (a) the 200-B Keccak state (25 lanes) after absorbing every COMPLETE 136-B
//       rate block of the prefix bytes preceding the opened region (this
//       compresses the ~40 B/payee vout list -- a full coinbase is ~90 KB -- into
//       200 B, unrevealed);
//   (b) the partial tail (< 136 B) of those preceding bytes not yet absorbed;
//   (c) the tx_extra bytes themselves (tag 0x01 pubkey 33 + 0x02 nonce 6-16 +
//       0x03 merge-mining tag ~36), where the v37 side-data commitment lives.
// The verifier resumes the sponge from (a), absorbs (b)||(c), pads and squeezes
// to get H(prefix). Keccak-256 as Monero uses it: rate r = 136 B, capacity 64 B,
// state 200 B -- ORIGINAL Keccak, mdlen 32 (monero keccak.c), NOT SHA3 padding.
//
// This decomposition maps 1:1 onto X1's KeccakMidstate (xmr_keccak_midstate.hpp,
// KECCAK_CTX): midstate == ctx.hash[25] as LE bytes; prefix_tail == ctx.message
// [0..rest]; rest == prefix_tail.size(). The verify leg (xmr_receipt_verify.cpp)
// converts between the two byte-exactly. [X0-KAT / U3] the resume at the `extra`
// boundary is byte-identical against monerod keccak.c on mainnet block 3000000.
// -----------------------------------------------------------------------------
struct CoinbaseOpening {
    static constexpr std::size_t KECCAK_STATE_BYTES = 200;  // 1600-bit state (25 lanes)
    static constexpr std::size_t KECCAK_RATE_BYTES  = 136;  // r for 256-bit output

    std::array<u8, KECCAK_STATE_BYTES> midstate{};  // (a) resumable sponge lanes, LE
    std::vector<u8> prefix_tail;                     // (b) < KECCAK_RATE_BYTES
    std::vector<u8> tx_extra;                        // (c) parsed for the commitment

    std::size_t wire_size() const {
        // midstate + varint(len(tail)) + tail + varint(len(extra)) + extra.
        // Length prefixes modelled as 1 B each (tail < 136, extra < ~90).
        return KECCAK_STATE_BYTES + 1 + prefix_tail.size() + 1 + tx_extra.size();
    }
};

// -----------------------------------------------------------------------------
// Component 4: tree branch -- the O(log n) merkle path from the miner_tx (leaf 0)
// to the tree_root inside the hashing blob (monero tree-hash.c tree_branch /
// tree_path; non-power-of-two counts pass leading leaves through and pair the
// tail). ceil(log2(n_tx)) * 32 B + a small path descriptor. Typical block 10-60
// txs => depth 4-6 => 128-192 B.
// -----------------------------------------------------------------------------
struct TreeBranch {
    std::vector<bytes32> path;   // sibling hashes, root-ward (== monerod branch[])
    u8   depth  = 0;             // = path.size(); pinned so the decoder is total
    u32  path_bits = 0;          // monerod tree_branch `path` (left/right per level).
    // For a canonical Monero block the miner_tx is leaf 0 and every step is a LEFT
    // operand (path_bits == 0), but we carry monerod's path word verbatim so the
    // opening stays valid if the coinbase is ever not leaf 0 (it always is here).

    std::size_t wire_size() const {
        // depth(1) + siblings + path_bits(4). Family-A pins depth; path_bits is a
        // fixed u32 (matches monerod's uint32_t path).
        return 1 + path.size() * sizeof(bytes32) + sizeof(u32);
    }
};

// -----------------------------------------------------------------------------
// Component 5: info_digest + ReceiptSideData (the ref-side binding, §3 / §B4).
//
// The scaffold carried only `bytes32 info_digest` and a note that its preimage is
// "relayed alongside". X4 makes that preimage concrete: ReceiptSideData is the
// side-data struct whose Keccak digest IS info_digest, and whose digest is what
// the coinbase tx_extra 0x03 merge-mining leaf commits to. That closes the bind:
//
//   T_origin, payout_identity, chain_id           (fields, readable directly)
//        |  keccak256(canonical side data)
//        v
//   info_digest  ===  the value the tx_extra 0x03 MM leaf commits
//        |  keccak256(MM_LEAF_DOMAIN || chain_id_le32 || info_digest)   == mm_root
//        v
//   tx_extra 0x03 tag  ->  H(prefix)  ->  coinbase tx hash  ->  tree_root
//        v
//   tree_root  ===  the root inside the RandomX-signed hashing blob.
//
// So tampering with T_origin (or identity, or chain_id) changes info_digest,
// changes mm_root, changes the tx_extra bytes, changes H(prefix), changes the
// tx hash, changes the tree_root, and no longer matches the RandomX-signed blob:
// the receipt is rejected at the STRUCTURAL stage, before RandomX is ever run.
//
// This is byte-identical to how the settle leg emits the commitment
// (xmr_coinbase.cpp mm_commitment_root: keccak256(domain || chain_id_le32 ||
// lane_commitment)); here `info_digest` plays the lane_commitment role for the
// receipt's own side data. prev_own_share is present but DISPLAY-ONLY per
// share-format §4 round-2 correction #1 -- never an ordering constraint, and it
// is folded into info_digest only so it cannot be silently swapped.
// -----------------------------------------------------------------------------
struct ReceiptSideData {
    Difficulty t_origin{};            // R-1: the committed share difficulty (§B4)
    bytes32    payout_identity{};     // payout-descriptor identity_key() (S-3)
    u32        chain_id = 0;          // lane ChainId (must equal this lane's)
    bytes32    prev_own_share{};      // DISPLAY-ONLY (share-format §4 r2 #1)
};

// Domain-separation tag for the v37 merge-mining commitment leaf. MUST equal the
// settle leg's MM_LEAF_DOMAIN (xmr_coinbase.hpp) byte-for-byte so a receipt opens
// what a v37 coinbase emits. The receipt reuses the settle leg's identical leaf
// construction -- mm_leaf = keccak256(MM_LEAF_DOMAIN || chain_id_le32 || C) -- with
// C := the receipt's info_digest (the receipt's side-data commitment), where the
// settle coinbase uses C := its owed_digest / lane_commitment.
inline constexpr char MM_LEAF_DOMAIN[] = "c2pool-v37-xmr-mm-leaf-v1";
inline constexpr std::size_t MM_LEAF_DOMAIN_LEN = sizeof(MM_LEAF_DOMAIN) - 1; // no NUL

// =============================================================================
// The Family-B receipt.
// =============================================================================
struct MoneroReceipt {
    HashingBlob     hashing_blob;     // ~77 B  -- RandomX input; prev_id -> bin
    SeedRef         seed_ref;         // 0 or 32 B (OQ-X2; default derived = 0)
    CoinbaseOpening coinbase_opening; // ~250-420 B -- Keccak midstate + tail + extra
    TreeBranch      tree_branch;      // ~128-192 B -- leaf-0 path to blob's root
    bytes32         info_digest{};    // 32 B  -- keccak256(side_data), bound via 0x03

    // The side-data preimage, relayed alongside. NOT part of the hashed blob; it
    // is validated by (info_digest == keccak256(side_data)) AND by the tx_extra
    // 0x03 leaf recomputation. Present on a v37-produced receipt; absent when the
    // receipt wraps a raw mainnet block (crypto-opening-only verification).
    std::optional<ReceiptSideData> side_data;

    // Total serialized size on the wire, for the per-lane byte budget (§B6 / §7).
    // side_data is NOT counted: it is a preimage bound by info_digest, and on a
    // DerivedFromBin lane its fields are all recoverable/checkable without extra
    // bytes beyond info_digest (which IS counted). Deterministic.
    std::size_t wire_size() const {
        return hashing_blob.size()
             + seed_ref.wire_size()
             + coinbase_opening.wire_size()
             + tree_branch.wire_size()
             + sizeof(info_digest);
    }
};

// Byte-budget envelope for the XMR lane (§B6). See the FINDING below.
namespace budget {
    constexpr std::size_t BLOB_BYTES          = 77;   // header(43) + root(32) + varint(~2)
    constexpr std::size_t SEED_DERIVED        = 0;
    constexpr std::size_t SEED_CARRIED        = 32;
    constexpr std::size_t OPENING_MIN         = 200 + 1 + 0   + 1 + 55;   // ~257
    constexpr std::size_t OPENING_TYP         = 200 + 1 + 68  + 1 + 75;   // ~345
    constexpr std::size_t OPENING_MAX         = 200 + 1 + 135 + 1 + 85;   // ~422
    constexpr std::size_t BRANCH_MIN          = 1 + 4 * 32 + 4;           // 133
    constexpr std::size_t BRANCH_TYP          = 1 + 5 * 32 + 4;           // 165
    constexpr std::size_t BRANCH_MAX          = 1 + 6 * 32 + 4;           // 197
    constexpr std::size_t INFO                = 32;

    constexpr std::size_t RECEIPT_MIN = BLOB_BYTES + SEED_DERIVED + OPENING_MIN + BRANCH_MIN + INFO;
    constexpr std::size_t RECEIPT_TYP = BLOB_BYTES + SEED_DERIVED + OPENING_TYP + BRANCH_TYP + INFO;
    constexpr std::size_t RECEIPT_MAX = BLOB_BYTES + SEED_CARRIED + OPENING_MAX + BRANCH_MAX + INFO;

    // FINDING (carried from the scaffold, adjusted for the 4-B path_bits field):
    // the scoping "R_MAX * ~700 B" figure is the TYPICAL size. The honest WORST
    // case -- carried seed (+32) AND a maximal Keccak prefix tail (135 B) AND a
    // depth-6 branch -- overshoots 700. The per-receipt cap is 768 B (3*256) so
    // no honest maximal receipt is dropped while a griefed one still is.
    constexpr std::size_t R_MAX_XMR          = 2;
    constexpr std::size_t PER_RECEIPT_BUDGET = 768;   // hard wire cap; admits RECEIPT_MAX
    constexpr std::size_t PER_LANE_BUDGET    = R_MAX_XMR * PER_RECEIPT_BUDGET;  // 1536 B/carrier
}

static_assert(budget::RECEIPT_TYP >= 600 && budget::RECEIPT_TYP <= 660,
              "typical MoneroReceipt must match the scoping-note 600-660 B estimate");
static_assert(budget::RECEIPT_MAX <= budget::PER_RECEIPT_BUDGET,
              "per-receipt byte budget must admit the worst realistic receipt");

} // namespace xmr
} // namespace v37
