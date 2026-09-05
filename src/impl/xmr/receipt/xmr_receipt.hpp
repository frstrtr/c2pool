#pragma once
// V37 Family-B (Monero / RandomX) work-receipt envelope — the MoneroReceipt.
//
// Design of record:
//   docs/c2pool-v37-share-format.md §3 (the Family-A RDWR receipt envelope this
//     extends), §7 (consensus parameters), §8 (whole-share validation pipeline);
//   share-format-addendum family-b-receipt-envelope-addendum.md §B2/§B3 (this
//     struct and its keyed_heavy admission order);
//   v37-monero-randomx-lane-scoping.md §1.4/§1.5, §2.4/§2.5, §16.
//
// This is a NEW src/impl/xmr/ header. It is ABOVE the sharechain seam and MUST
// NOT be included from src/sharechain/v37/* consensus-digest code. It reuses the
// Family-A wire idioms (fixed field order, little-endian, one-canon) but carries
// a Monero-shaped proof: a RandomX PoW that lives inside the ~77-B hashing blob
// plus a Keccak-256 midstate "opening" of the miner_tx prefix at the tx_extra
// boundary (Tari `MoneroPowData` / RFC-0132 `pow_data.rs` is the working
// precedent: header + RandomX key + tx count + tree root + coinbase merkle proof
// + coinbase Keccak midstate + coinbase tx_extra).
//
// Monero symbols this mirrors (SChernykh/p2pool + monero-project/monero, read
// 2026-09-05): get_block_hashing_blob, get_block_longhash / rx_slow_hash,
// tree_hash / tree_branch (tree-hash.c), TransactionPrefix{version, unlock_time,
// vin(TXIN_GEN 0xFF), vout(TXOUT_TO_TAGGED_KEY 3), extra}, RCTTypeNull coinbase
// tx-hash triple Keccak(H(prefix)||H(rct_base)||H(prunable=null_hash)),
// tx_extra tags 0x01 pubkey / 0x02 extra-nonce / 0x03 merge-mining, RX_BLOCK_VERSION.
//
// FCMP++/CARROT FENCE: nothing in THIS file derives coinbase outputs, so this
// header is fork-major-version-agnostic. The coinbase-output derivation (deterministic
// r, one-time keys) lives in the payout/coinbase leg and MUST be pinned per Monero
// hard-fork major_version behind a pre-CARROT guard. The receipt only *opens* an
// already-built coinbase's prefix, which CARROT does not change.

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

// Monero difficulty is 128-bit (monero `difficulty_type`, p2pool `difficulty_type`).
// T_origin is expressed as a difficulty, not a compact "bits" target, because a
// Monero header has no bits field (§B4). check_pow semantics: a hash h passes at
// difficulty d iff the 512-bit product (h as 256-bit LE) * d has its high 256 bits
// zero, i.e. h <= floor(2^256 / d) (monero `check_hash_128`).
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
    // The blob is carried verbatim (varint-encoded, so variable length ~76-77 B):
    // it is the exact byte string fed to rx_slow_hash, and the tree_root inside it
    // is what the coinbase opening must reconcile to. Parsed lazily; never rebuilt.
    std::vector<u8> bytes;

    // Cheap accessors parsed out of `bytes` by the primitives leg
    // (share-format-addendum sibling: monero-primitives varint/blob decode).
    // Offsets are recovered by the varint decoder; declarations only here to keep
    // this header dependency-free. See xmr_receipt_parse.hpp (monero-primitives).
    static constexpr std::size_t PREV_ID_OFFSET_FROM_VARINTS = 0;  // resolved at parse

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
// Component 3: coinbase opening — a Keccak-256 sponge midstate of the miner_tx
// TransactionPrefix absorbed up to the tx_extra boundary, plus the tail bytes and
// the tx_extra bytes in the clear. `extra` is the LAST prefix field, so opening it
// while proving H(prefix) needs only:
//   (a) the 200-B Keccak state after absorbing every COMPLETE 136-B rate block of
//       the prefix bytes that precede the opened region (this compresses the
//       ~40 B/payee vout list — a full coinbase is ~90 KB — into 200 B, unrevealed);
//   (b) the partial tail (< 136 B) of those preceding bytes not yet absorbed;
//   (c) the tx_extra bytes themselves (tag 0x01 pubkey 33 + 0x02 nonce 6-16 +
//       0x03 merge-mining tag ~36), where the v37 side-data commitment lives.
// The verifier resumes the sponge from (a), absorbs (b)||(c), pads and squeezes to
// get H(prefix). Keccak-256 as Monero uses it: rate r = 136 B (1088 bits), capacity
// c = 64 B (512 bits), state = 200 B (1600 bits) — original Keccak, mdlen 32
// (monero keccak.c), NOT SHA3 padding. [?] the midstate resume at the `extra`
// boundary is standard sponge behaviour but is X0-KAT-gated (sibling x0-feasibility).
// -----------------------------------------------------------------------------
struct CoinbaseOpening {
    static constexpr std::size_t KECCAK_STATE_BYTES = 200;  // 1600-bit state
    static constexpr std::size_t KECCAK_RATE_BYTES  = 136;  // r for 256-bit output

    std::array<u8, KECCAK_STATE_BYTES> midstate{};  // (a) resumable sponge state
    std::vector<u8> prefix_tail;                     // (b) < KECCAK_RATE_BYTES
    std::vector<u8> tx_extra;                        // (c) parsed for the commitment

    std::size_t wire_size() const {
        // midstate + varint(len(tail)) + tail + varint(len(extra)) + extra.
        // Length prefixes modelled as 1 B each (both < 136 and < ~90 respectively).
        return KECCAK_STATE_BYTES + 1 + prefix_tail.size() + 1 + tx_extra.size();
    }
};

// -----------------------------------------------------------------------------
// Component 4: tree branch — the O(log n) merkle path from the miner_tx (leaf 0)
// to the tree_root inside the hashing blob (monero tree-hash.c tree_branch /
// tree_path; non-power-of-two counts pass leading leaves through and pair the
// tail). ceil(log2(n_tx)) * 32 B + a small path descriptor. Typical Monero block
// 10-60 txs ⇒ depth 4-6 ⇒ 128-192 B.
// -----------------------------------------------------------------------------
struct TreeBranch {
    std::vector<bytes32> path;   // sibling hashes, root-ward
    u8 depth = 0;                // = path.size(); pinned so the decoder is total
    // Monero's tree_branch is a pure left-spine proof for leaf 0 (miner_tx), so no
    // per-level direction bitfield is needed — leaf 0 is always the left operand.
    // A 1-B depth prefix keeps the wire self-describing.

    std::size_t wire_size() const {
        return 1 /*depth*/ + path.size() * sizeof(bytes32);
    }
};

// -----------------------------------------------------------------------------
// Component 5: info_digest — as Family-A §3: a 32-B digest of the ref-side fields
// the verifier binds against (payout-descriptor identity key; T_origin bits;
// prev_own_share is present but, per share-format §4 round-2 correction #1, is
// DISPLAY-ONLY and never an ordering constraint). Preimage relayed alongside; the
// R-1 T_origin that gates RandomX is the one OPENED from committed side data
// (§B4), not this preimage — this preimage only has to match it.
// -----------------------------------------------------------------------------

// =============================================================================
// The Family-B receipt.
// =============================================================================
struct MoneroReceipt {
    HashingBlob     hashing_blob;     // ~77 B  — RandomX input; prev_id -> bin
    SeedRef         seed_ref;         // 0 or 32 B (OQ-X2; default derived = 0)
    CoinbaseOpening coinbase_opening; // ~250-420 B  — Keccak midstate + tail + extra
    TreeBranch      tree_branch;      // ~128-192 B — leaf-0 path to blob's root
    bytes32         info_digest{};    // 32 B  — ref-side binding digest (§3)

    // Total serialized size of THIS receipt on the wire, for the per-lane byte
    // budget check (§B6 / §7 "receipt byte budget" row). Deterministic.
    std::size_t wire_size() const {
        return hashing_blob.size()
             + seed_ref.wire_size()
             + coinbase_opening.wire_size()
             + tree_branch.wire_size()
             + sizeof(info_digest);
    }
};

// Byte-budget envelope for the XMR lane (§B6). MIN/TYP/MAX bound MoneroReceipt::
// wire_size() across realistic blocks; PER_LANE_BUDGET is the digest-committed
// per-lane override of the Family-A "receipt byte budget = R_MAX * 256 B" row.
namespace budget {
    constexpr std::size_t BLOB_BYTES          = 77;   // header(43) + root(32) + varint(~2)
    constexpr std::size_t SEED_DERIVED        = 0;
    constexpr std::size_t SEED_CARRIED        = 32;
    constexpr std::size_t OPENING_MIN         = 200 + 1 + 0   + 1 + 55;   // ~257
    constexpr std::size_t OPENING_TYP         = 200 + 1 + 68  + 1 + 75;   // ~345
    constexpr std::size_t OPENING_MAX         = 200 + 1 + 135 + 1 + 85;   // ~422
    constexpr std::size_t BRANCH_MIN          = 1 + 4 * 32;               // 129
    constexpr std::size_t BRANCH_TYP          = 1 + 5 * 32;               // 161
    constexpr std::size_t BRANCH_MAX          = 1 + 6 * 32;               // 193
    constexpr std::size_t INFO                = 32;

    constexpr std::size_t RECEIPT_MIN = BLOB_BYTES + SEED_DERIVED + OPENING_MIN + BRANCH_MIN + INFO; // ~495
    constexpr std::size_t RECEIPT_TYP = BLOB_BYTES + SEED_DERIVED + OPENING_TYP + BRANCH_TYP + INFO; // ~615
    constexpr std::size_t RECEIPT_MAX = BLOB_BYTES + SEED_CARRIED + OPENING_MAX + BRANCH_MAX + INFO; // ~676

    // Per-lane byte budget: R_MAX_XMR * PER_RECEIPT_BUDGET (digest-committed).
    // Recommendation (OQ-X2): R_MAX_XMR = 2.
    //
    // FINDING (refines the scoping note): the scoping "R_MAX * ~700 B" figure is a
    // TYPICAL-case size (RECEIPT_TYP = 615 B). The honest WORST case — carried seed
    // (+32) AND a maximal Keccak prefix tail (135 B) AND a depth-6 tree branch — is
    // RECEIPT_MAX = 756 B, which OVERSHOOTS 700. A 700-B cap would reject legitimate
    // maximal receipts. The enforced per-receipt cap is therefore set to 768 B (3*256,
    // ~12 B margin over 756) so no honest receipt is dropped while a griefed one still
    // is. With DerivedFromBin (the default, 0-B seed) the max drops to 724 B.
    constexpr std::size_t R_MAX_XMR         = 2;
    constexpr std::size_t PER_RECEIPT_BUDGET = 768;   // hard wire cap; admits RECEIPT_MAX
    constexpr std::size_t PER_LANE_BUDGET    = R_MAX_XMR * PER_RECEIPT_BUDGET;  // 1536 B/carrier
}

// The scoping estimate (§1.5: "~600-660 B [est]") is the TYPICAL receipt; the cap
// must admit the worst realistic one (see FINDING above).
static_assert(budget::RECEIPT_TYP >= 600 && budget::RECEIPT_TYP <= 660,
              "typical MoneroReceipt must match the scoping-note 600-660 B estimate");
static_assert(budget::RECEIPT_MAX <= budget::PER_RECEIPT_BUDGET,
              "per-receipt byte budget must admit the worst realistic receipt");

} // namespace xmr
} // namespace v37
