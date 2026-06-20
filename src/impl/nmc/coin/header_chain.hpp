#pragma once

/// NMC (Namecoin) Header Chain — P0 STRUCTURAL LEAF
///
/// Validated header-only chain skeleton for embedded merge-mined Namecoin.
///
/// Namecoin is a SHA256d Bitcoin fork. Its *plain* block header is byte-
/// identical to Bitcoin's (see block.hpp) and its difficulty retarget is the
/// classic Bitcoin 2016-block window. What makes Namecoin different from a
/// straight Bitcoin clone is MERGE-MINING: from the auxpow-activation height
/// onward, a Namecoin block may carry an AuxPow proof — a parent (BTC)
/// coinbase transaction plus the merkle branches that bind it to the parent
/// block header — instead of doing its own proof-of-work. The Namecoin block
/// hash still has to be < target, but the proof-of-work is *demonstrated on
/// the parent chain* via the AuxPow.
///
/// Mirror of src/impl/btc/coin/header_chain.hpp (class shape, namespace
/// conventions, include style). Re-homed into namespace nmc::coin so the NMC
/// coin tree is self-contained. Only core/* PUBLIC headers and the NMC-local
/// block.hpp are consumed. The btc tree is consumed READ-ONLY and is NOT
/// modified.
///
/// ============================ P0 FENCE ====================================
/// This is a STRUCTURE-ONLY leaf: correct types + class skeleton, NOT a
/// working consensus validator. In particular:
///   * AuxPow::check_proof() is a P0-DEFER STUB (see below). It does NOT walk
///     the coinbase merkle branch, does NOT verify the chain-merkle-root, and
///     does NOT verify the parent block's proof-of-work. NMC MUST NOT be used
///     to block-validate off this P0 leaf.
///   * Consensus constants (auxpow activation height, chain id, parent powhash
///     path) are NOT baked as compiled constants. They are left as
///     // TO-CONFIRM: placeholders with sentinel values, pending pinning
///     against Namecoin chainparams + namecoind.
/// ==========================================================================

#include "block.hpp"
#include "transaction.hpp"

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/target_utils.hpp>  // chain::bits_to_target (parent-PoW, step 4)
#include <core/leveldb_store.hpp>  // P1f: core::LevelDBStore persistence
#include <core/coin/utxo.hpp>      // P1 PC: core::coin::DEFAULT_MAX_TIP_AGE (is_synced)

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <functional>
#include <mutex>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <span>
#include <stdexcept>
#include <vector>

namespace nmc {
namespace coin {

// uint256 hasher for unordered containers (low-64 bits is already a uniform
// distribution over a cryptographic hash, no further mixing needed).
struct Uint256Hasher {
    size_t operator()(const uint256& h) const { return h.GetLow64(); }
};

// ─── PoW / identity hashes ───────────────────────────────────────────────────

/// Compute SHA256d hash of the plain NMC block header (block identification).
/// Namecoin uses SHA256d for both identity and (own-chain) proof-of-work, so
/// — as on BTC — the identity hash and the own-PoW hash are the same value.
inline uint256 block_hash(const BlockHeaderType& header) {
    auto packed = pack(header);
    return Hash(packed.get_span());
}

/// Own-chain proof-of-work hash. Identical to block_hash() on a SHA256d chain;
/// kept as a distinct function for call-site symmetry across coins (LTC splits
/// these: scrypt for PoW, SHA256d for identity).
inline uint256 pow_hash(const BlockHeaderType& header) {
    auto packed = pack(header);
    return Hash(packed.get_span());
}

// ─── Merkle-branch walk (P1: AuxPow merkle-proof primitive) ────────────────

/// Walk a merkle BRANCH up to its root, starting from `leaf`.
///
/// The core primitive of AuxPow verification: BOTH legs of the proof are
/// merkle-branch walks — the chain-merkle leg (aux block hash → merged-mining
/// root, AuxPow::check_proof step 1) and the parent-coinbase leg (coinbase
/// txid → parent block tx-merkle-root, step 3). At level i, bit i of `index`
/// selects the side: if set, branch[i] is the LEFT sibling (running hash on the
/// right); else branch[i] is on the right. Each pair is SHA256d'd (the
/// Bitcoin/Namecoin merkle convention).
///
/// Byte-faithful port of legacy libcoind/data.cpp check_merkle_link() — the
/// same SSOT btc/ltc use — kept NMC-LOCAL per the coin fence (no btc/ltc
/// include; only core/* primitives: Hash, PackStream).
inline uint256 aux_merkle_root(const uint256& leaf,
                               const std::vector<uint256>& branch,
                               uint32_t index) {
    if (!branch.empty() && index >= (1u << branch.size()))
        throw std::invalid_argument("aux_merkle_root: index too large for branch depth");

    uint256 cur = leaf;
    for (size_t i = 0; i < branch.size(); ++i) {
        PackStream ps;
        if ((index >> i) & 1u) {
            ps << branch[i];   // sibling on the left
            ps << cur;
        } else {
            ps << cur;
            ps << branch[i];   // sibling on the right
        }
        auto sp = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
        cur = Hash(sp);        // SHA256d of the 64-byte concatenation
    }
    return cur;
}

// ─── Parent-coinbase txid (P1c: AuxPow step-3 leaf identity) ───────

/// Witness-stripped transaction id of the parent (BTC) coinbase.
///
/// AuxPow step 3 proves the parent coinbase is committed in the parent
/// block's transaction merkle root. That tree commits *txids*, NOT wtxids —
/// so the coinbase id MUST be hashed over the LEGACY (no-witness, no segwit
/// marker/flag) serialization even though a real BTC coinbase carries a
/// witness (the BIP141 segwit-commitment reserved value). Byte-for-byte
/// identical to the btc tree's compute_txid() (mempool.hpp) but kept
/// NMC-LOCAL per the coin fence: consumes only the nmc::coin transaction
/// serializer (TX_NO_WITNESS) + core::Hash, no btc include.
inline uint256 parent_coinbase_txid(const MutableTransaction& tx) {
    auto packed = pack(TX_NO_WITNESS(tx));
    return Hash(packed.get_span());
}

// ─── Merged-mining commitment scan (P1c-step2: AuxPow step-2 binding) ──

/// pchMergedMiningHeader — the 4-byte magic tag that precedes the merged-mining
/// commitment inside the parent coinbase scriptSig. Byte-faithful with
/// Namecoin/Bitcoin auxpow.cpp (the same SSOT btc/doge consume); kept NMC-LOCAL
/// per the coin fence (only std + core types, no btc include).
inline constexpr unsigned char MM_HEADER_MAGIC[4] = {0xfa, 0xbe, 'm', 'm'};

/// Read a little-endian uint32 from 4 bytes WITHOUT a host-endian memcpy: the
/// on-wire MM size/nonce fields are always little-endian.
inline uint32_t read_le32(const unsigned char* p) {
    return  static_cast<uint32_t>(p[0])
         | (static_cast<uint32_t>(p[1]) << 8)
         | (static_cast<uint32_t>(p[2]) << 16)
         | (static_cast<uint32_t>(p[3]) << 24);
}

/// Deterministic chain-merkle slot for a (nonce, chain_id, height) triple.
/// Byte-faithful port of Namecoin/Bitcoin CAuxPow::getExpectedIndex: pins each
/// aux chain to a pseudo-random-but-fixed slot so the same parent work cannot be
/// replayed for two chains and inter-chain slot clashes are minimised. The
/// arithmetic is intentionally wrap-around uint32 (LCG constants 1103515245 /
/// 12345) to match the reference bit-for-bit.
inline uint32_t aux_expected_index(uint32_t nonce, int32_t chain_id, unsigned height) {
    uint32_t rnd = nonce;
    rnd = rnd * 1103515245u + 12345u;
    rnd += static_cast<uint32_t>(chain_id);
    rnd = rnd * 1103515245u + 12345u;
    return rnd % (1u << height);
}

/// Result of scanning a parent coinbase scriptSig for the merged-mining
/// commitment of a given chain-merkle root.
enum class MMScan {
    ABSENT,    //!< no MM magic in the scriptSig — nothing to assert (staged leg)
    MATCH,     //!< magic found and root/size/nonce/slot all bind correctly
    MISMATCH,  //!< magic found but the commitment is malformed or inconsistent
};

/// Step 2 of AuxPow verification: confirm the reconstructed chain-merkle root is
/// the one committed inside the parent coinbase's merged-mining marker, and that
/// this chain occupies the slot the (nonce, chain_id) binding demands.
///
/// Byte-faithful port of the coinbase scan in Namecoin/Bitcoin auxpow.cpp
/// (CAuxPow::check), kept NMC-LOCAL per the coin fence (only std + core types):
///   * the 4-byte MM magic must appear exactly once;
///   * the chain-merkle root must follow the magic immediately, stored in the
///     REVERSED (big-endian display) byte order auxpow.cpp uses;
///   * the next 4 LE bytes are the tree size and MUST equal 2^height;
///   * the following 4 LE bytes are the nonce, and chain_index MUST equal
///     aux_expected_index(nonce, chain_id, height).
/// Returns ABSENT when the magic is absent entirely — the staged-leg posture
/// (mirrors the null-parent-header gate in step 3): step 2 cannot be asserted off
/// a fixture carrying no marker, and the proof never upgrades to VALID regardless.
/// NOTE (constant-pinning): the legacy no-magic "root in the first 20 bytes"
/// back-compat branch of the reference is intentionally NOT honoured — post-
/// activation Namecoin merge-mining always carries the magic; the final
/// endianness/layout cross-check happens against a live namecoind at pinning.
/// chain_merkle_root is taken by value (base_uint::begin() is non-const).
inline MMScan scan_mm_commitment(const std::vector<unsigned char>& script,
                                 uint256 chain_merkle_root,
                                 unsigned chain_height,
                                 int32_t expected_chain_id,
                                 uint32_t chain_index) {
    const unsigned char* magic = MM_HEADER_MAGIC;
    auto magic_it = std::search(script.begin(), script.end(), magic, magic + 4);
    if (magic_it == script.end())
        return MMScan::ABSENT;  // staged: no commitment to bind against yet

    // Replay guard: exactly one MM header may appear (the reference rejects a
    // second so one parent block cannot smuggle two commitments for one chain).
    if (std::search(magic_it + 4, script.end(), magic, magic + 4) != script.end())
        return MMScan::MISMATCH;

    // The chain-merkle root is committed reversed (big-endian display order).
    const unsigned char* rb =
        reinterpret_cast<const unsigned char*>(chain_merkle_root.begin());
    std::vector<unsigned char> root_be(rb, rb + uint256::BYTES);
    std::reverse(root_be.begin(), root_be.end());

    auto root_pos = magic_it + 4;
    if (static_cast<size_t>(script.end() - root_pos) < root_be.size())
        return MMScan::MISMATCH;  // truncated before the root
    if (!std::equal(root_be.begin(), root_be.end(), root_pos))
        return MMScan::MISMATCH;  // magic present but commits a different root

    auto pc = root_pos + static_cast<std::ptrdiff_t>(root_be.size());
    if (script.end() - pc < 8)
        return MMScan::MISMATCH;  // missing the 4-byte size + 4-byte nonce
    uint32_t n_size  = read_le32(&*pc);
    uint32_t n_nonce = read_le32(&*(pc + 4));
    if (n_size != (1u << chain_height))
        return MMScan::MISMATCH;  // tree size disagrees with the branch depth
    if (chain_index != aux_expected_index(n_nonce, expected_chain_id, chain_height))
        return MMScan::MISMATCH;  // chain sits in the wrong deterministic slot

    return MMScan::MATCH;
}

// ─── AuxPow (merge-mining proof) ─────────────────────────────────────────────

/// One aux-chain slot inside a parent coinbase's merged-mining merkle tree.
///
/// Kept NMC-LOCAL on purpose (P0 fence #4): do NOT lift this into
/// bitcoin_family/ or src/core/. A parent block can merge-mine several aux
/// chains at once; each occupies a deterministic slot in the chain-merkle-tree
/// keyed by (chain_id, merkle size, nonce). For NMC under a BTC parent the
/// list is normally length 1, but the type models the general case.
struct AuxChain {
    // TO-CONFIRM: Namecoin mainnet chain id. Namecoin historically uses
    // chain_id = 1 for mainnet merge-mining, but this MUST be pinned against
    // Namecoin chainparams (CChainParams::nAuxpowChainId) + namecoind before
    // it is treated as consensus. Sentinel below is a placeholder, NOT a
    // committed constant.
    int32_t  chain_id{-1};        // TO-CONFIRM: sentinel (-1 = unpinned)
    uint256  aux_block_hash;      // the aux (NMC) block hash being committed
    uint32_t merkle_index{0};     // slot index within the chain merkle tree
};

/// AuxPow — the merge-mining proof attached to a Namecoin header once
/// merge-mining is active.
///
/// Field layout mirrors Namecoin's CAuxPow / Bitcoin's classic auxpow:
///   * the PARENT (BTC) coinbase transaction, which embeds the merged-mining
///     commitment in its scriptSig / an output script;
///   * the coinbase merkle BRANCH proving that coinbase is in the parent
///     block (parent_coinbase_branch + index);
///   * the CHAIN merkle BRANCH proving this aux chain's hash is in the
///     merged-mining merkle tree committed by the parent coinbase
///     (chain_merkle_branch + chain_index);
///   * the PARENT block header, whose proof-of-work is what actually backs
///     this Namecoin block.
///
/// The parent coinbase is modelled with the NMC-local MutableTransaction type
/// (Bitcoin-format tx; Namecoin's parent is BTC, same serialization). We do
/// NOT pull btc::coin::MutableTransaction here — the nmc tree stays
/// self-contained per the fence.
struct AuxPow {
    /// Parent (BTC) coinbase transaction carrying the MM commitment.
    MutableTransaction parent_coinbase;

    /// Hash of the parent block (redundant with parent_header, kept for the
    /// classic auxpow wire layout / quick checks).
    uint256 parent_block_hash;

    /// Merkle branch + index linking parent_coinbase into the parent block's
    /// transaction merkle root.
    std::vector<uint256> parent_coinbase_branch;
    int32_t              parent_coinbase_index{0};

    /// Merkle branch + index linking this aux chain's blockhash into the
    /// merged-mining merkle root committed inside the parent coinbase.
    std::vector<uint256> chain_merkle_branch;
    int32_t              chain_merkle_index{0};

    /// The parent (BTC) block header. Its SHA256d PoW is the work that backs
    /// the Namecoin block. We reuse the NMC-local BlockHeaderType because a
    /// BTC parent header is byte-identical in layout.
    BlockHeaderType parent_header;

    void SetNull() {
        parent_coinbase = MutableTransaction{};
        parent_block_hash.SetNull();
        parent_coinbase_branch.clear();
        parent_coinbase_index = 0;
        chain_merkle_branch.clear();
        chain_merkle_index = 0;
        parent_header.SetNull();
    }

    bool IsNull() const { return parent_header.IsNull(); }

    /// Canonical Namecoin CAuxPow wire layout, fenced to the NMC tree (only
    /// core/* + nmc::coin types -- no btc/ or bitcoin_family/ include). A
    /// byte-faithful port of Namecoin CAuxPow / classic Bitcoin auxpow: the
    /// CMerkleTx coinbase leg, then the chain-merkle leg, then the parent
    /// header, in daemon field order:
    ///   1. parent_coinbase        -- parent (BTC) coinbase CTransaction,
    ///      serialized WITNESS-STRIPPED (TX_NO_WITNESS) so the bytes match the
    ///      txid the parent tx-merkle tree commits (see parent_coinbase_txid)
    ///      and the daemon auxpow encoding -- NOT the wtxid form;
    ///   2. parent_block_hash      -- CMerkleTx::hashBlock;
    ///   3. parent_coinbase_branch -- CMerkleTx::vMerkleBranch;
    ///   4. parent_coinbase_index  -- CMerkleTx::nIndex (int32 LE);
    ///   5. chain_merkle_branch    -- CAuxPow::vChainMerkleBranch;
    ///   6. chain_merkle_index     -- CAuxPow::nChainIndex (int32 LE);
    ///   7. parent_header          -- CAuxPow::parentBlock (80-byte header).
    /// Hand-written (not C2POOL_SERIALIZE_METHODS) because the parent coinbase
    /// needs the explicit TX_NO_WITNESS param wrapper. Backs the P1f on-disk
    /// auxpow blob and is reused by PD dual-target wire path.
    template<typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, TX_NO_WITNESS(parent_coinbase));
        ::Serialize(s, parent_block_hash);
        ::Serialize(s, parent_coinbase_branch);
        ::Serialize(s, parent_coinbase_index);
        ::Serialize(s, chain_merkle_branch);
        ::Serialize(s, chain_merkle_index);
        ::Serialize(s, parent_header);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, TX_NO_WITNESS(parent_coinbase));
        ::Unserialize(s, parent_block_hash);
        ::Unserialize(s, parent_coinbase_branch);
        ::Unserialize(s, parent_coinbase_index);
        ::Unserialize(s, chain_merkle_branch);
        ::Unserialize(s, chain_merkle_index);
        ::Unserialize(s, parent_header);
    }

    /// Result of a (future) AuxPow verification.
    enum class CheckResult {
        NOT_IMPLEMENTED_P0,   //!< P0 leaf — verification path not built yet
        INCOMPLETE,           //!< P1b — merkle leg(s) wired; steps 2/3/4 pending
        VALID,
        INVALID,
    };

    /// Verify that this AuxPow actually proves work for `aux_block_hash`
    /// against the given expected aux chain id.
    ///
    /// P1b: step 1 (chain-merkle leg) is wired below via aux_merkle_root().
    /// The FULL implementation must, against
    /// a properly-pinned Namecoin chainparams:
    ///   1. recompute the merged-mining merkle root from `chain_merkle_branch`
    ///      + `chain_merkle_index` starting at `aux_block_hash`, and confirm
    ///      the slot derivation matches (chain_id, nonce) — i.e. consume the
    ///      btc tree's parent merkle-branch helper READ-ONLY;
    ///   2. confirm that root is committed in `parent_coinbase`'s MM marker;
    ///   3. recompute the parent tx-merkle-root from `parent_coinbase_branch`
    ///      + `parent_coinbase_index` and confirm it == parent_header merkle
    ///      root;
    ///   4. verify the PARENT block's proof-of-work (SHA256d(parent_header) <
    ///      target) — this is the parent-powhash verification path, consumed
    ///      from the btc tree READ-ONLY (e.g. btc::coin pow check).
    /// Until all four steps exist, NMC MUST NOT block-validate off this leaf.
    CheckResult check_proof(const uint256& aux_block_hash,
                            int32_t expected_chain_id,
                            uint32_t aux_bits = 0) const {
        // P1b+P1c — three merkle legs wired. Step 1 (chain-merkle) walks the
        // aux (NMC) block hash through chain_merkle_branch/index to reconstruct
        // the merged-mining root; step 2 (MM-marker) confirms that root is the
        // one committed inside the parent coinbase's merged-mining marker, with
        // the (nonce, chain_id) slot binding; step 3 (parent-coinbase tx-merkle)
        // walks the witness-stripped parent coinbase txid through
        // parent_coinbase_branch/index and, when a parent header is present,
        // requires it to reproduce that header's tx-merkle-root; step 4 (parent
        // PoW) verifies the parent block's SHA256d hash clears the AUX block's
        // target. A structurally-complete proof — all four legs, a matched MM
        // marker, a real parent header, and an aux_bits that the parent PoW
        // satisfies — is VALID. Absent any of those (a leg-only fixture: null
        // parent, no marker, or aux_bits unset) the proof stays INCOMPLETE, so
        // NMC never block-validates off a partial proof. Any malformed leg (negative slot index, an
        // index wider than its branch depth, a parent-coinbase leg that does not
        // reconstruct the parent header's tx-merkle-root, or an MM marker that
        // commits a different root / wrong tree-size / wrong slot) is INVALID.

        // ── step 1 (P1b): chain-merkle leg ──
        if (chain_merkle_index < 0)
            return CheckResult::INVALID;  // negative slot index is malformed
        uint256 reconstructed_mm_root;
        try {
            // Reconstruct the merged-mining merkle root; step 2 binds it to the
            // parent coinbase commitment.
            reconstructed_mm_root = aux_merkle_root(
                aux_block_hash, chain_merkle_branch,
                static_cast<uint32_t>(chain_merkle_index));
        } catch (const std::invalid_argument&) {
            return CheckResult::INVALID;  // branch index out of range for depth
        }

        // ── step 2 (P1c-step2): MM-marker commitment + chain_id/slot binding ──
        // Confirm the reconstructed MM root is the one committed inside the
        // parent coinbase's merged-mining marker, with the (nonce, chain_id)
        // slot binding. When the coinbase carries no marker (a leg-only
        // structural fixture, or an empty parent coinbase) there is nothing to
        // assert yet — staged posture, mirrors the null-parent-header gate in
        // step 3. A marker present but committing a different root / wrong size /
        // wrong slot is INVALID.
        bool mm_marker_matched = false;
        if (!parent_coinbase.vin.empty()) {
            MMScan scan = scan_mm_commitment(
                parent_coinbase.vin[0].scriptSig.m_data,
                reconstructed_mm_root,
                static_cast<unsigned>(chain_merkle_branch.size()),
                expected_chain_id,
                static_cast<uint32_t>(chain_merkle_index));
            if (scan == MMScan::MISMATCH)
                return CheckResult::INVALID;
            mm_marker_matched = (scan == MMScan::MATCH);
        }

        // ── step 3 (P1c): parent-coinbase tx-merkle leg ──
        if (parent_coinbase_index < 0)
            return CheckResult::INVALID;  // negative slot index is malformed
        uint256 reconstructed_parent_merkle;
        try {
            // The parent tx-merkle tree commits the WITNESS-STRIPPED txid.
            reconstructed_parent_merkle = aux_merkle_root(
                parent_coinbase_txid(parent_coinbase), parent_coinbase_branch,
                static_cast<uint32_t>(parent_coinbase_index));
        } catch (const std::invalid_argument&) {
            return CheckResult::INVALID;  // branch index out of range for depth
        }
        // The equality gate only fires once a parent header is present: a real
        // proof always carries one, but a leg-only structural fixture leaves it
        // null and has nothing to match against yet (step 2 may also pend).
        if (!parent_header.IsNull() &&
            reconstructed_parent_merkle != parent_header.m_merkle_root)
            return CheckResult::INVALID;

        // ── step 4 (P1c-step4): parent proof-of-work vs the AUX target ──
        // The parent (BTC) block's SHA256d PoW hash is the work backing this
        // Namecoin block. Per Namecoin's CheckAuxPowProofOfWork the parent PoW
        // hash must satisfy the AUX (NMC) block's difficulty target — aux_bits,
        // the NMC header's nBits — NOT the parent header's own nBits. Target is
        // expanded with the shared core helper chain::bits_to_target(); the hash
        // is the nmc-local pow_hash(parent_header). No btc-tree dependency: both
        // helpers live outside src/impl/btc (core + nmc-local).
        //
        // aux_bits == 0 is the leg-only-fixture sentinel (caller has not supplied
        // the aux header's difficulty): step 4 is skipped and the proof stays
        // INCOMPLETE, mirroring the null-parent / no-marker gates above.
        bool parent_pow_ok = false;
        if (!parent_header.IsNull() && aux_bits != 0) {
            uint256 parent_powhash = pow_hash(parent_header);
            uint256 aux_target     = chain::bits_to_target(aux_bits);
            // Valid PoW means hash <= target, i.e. NOT (hash > target) — same
            // ordering convention as the btc work_source block/share gate.
            if (parent_powhash > aux_target)
                return CheckResult::INVALID;  // parent has insufficient work
            parent_pow_ok = true;
        }

        // Only a structurally-complete proof is VALID: all four legs satisfied
        // against a real parent header, a matched MM-marker commitment, and a
        // parent PoW that clears the aux target. Anything short stays INCOMPLETE.
        if (parent_pow_ok && mm_marker_matched && !parent_header.IsNull())
            return CheckResult::VALID;

        return CheckResult::INCOMPLETE;
    }
};

// ─── Chain parameters ────────────────────────────────────────────────────────

/// NMC chain parameters. Mirror of btc::coin::BTCChainParams shape; Namecoin
/// shares Bitcoin's retarget window/spacing (SHA256d, 2016-block window,
/// 10-minute target).
struct NMCChainParams {
    // Namecoin shares Bitcoin's retarget window/spacing.
    static constexpr int64_t MAINNET_TARGET_TIMESPAN = 1209600;   // 2 weeks
    static constexpr int64_t MAINNET_TARGET_SPACING  = 600;       // 10 minutes
    static constexpr bool    MAINNET_ALLOW_MIN_DIFF  = false;

    static constexpr int64_t TESTNET_TARGET_TIMESPAN = 1209600;   // 2 weeks
    static constexpr int64_t TESTNET_TARGET_SPACING  = 600;       // 10 minutes
    static constexpr bool    TESTNET_ALLOW_MIN_DIFF  = true;

    static constexpr int64_t difficulty_adjustment_interval(int64_t timespan, int64_t spacing) {
        return timespan / spacing;
    }

    int64_t target_timespan{MAINNET_TARGET_TIMESPAN};
    int64_t target_spacing{MAINNET_TARGET_SPACING};
    bool    allow_min_difficulty{false};
    bool    no_retargeting{false};
    uint256 pow_limit;
    uint256 genesis_hash;
    // P2P network magic (Namecoin Core pchMessageStart). The 4-byte frame
    // prefix every parent-NMC P2P message carries; the embedded won-block
    // broadcaster (PE) needs it to talk the NMC wire protocol. SSOT for the
    // host get_chain_p2p_prefix table (a follow-on host slice references this).
    // Sourced from namecoin-core src/kernel/chainparams.cpp, NOT from memory.
    std::array<unsigned char, 4> p2p_magic{};

    // ── Merge-mining consensus parameters ──
    //
    // TO-CONFIRM: NONE of the following are committed constants. They are
    // placeholder sentinels pending pinning against Namecoin chainparams
    // (CChainParams) + a live namecoind. Do NOT promote to consensus until
    // verified.
    //
    // auxpow_activation_height: the height at/after which a Namecoin block MAY
    //   (and on mainnet, MUST) carry an AuxPow. Historically cited as 19200 on
    //   Namecoin mainnet — but this is left UNBAKED on purpose; -1 = unpinned.
    // PINNED per-network in mainnet()/testnet() factories below against
    // namecoin-core src/kernel/chainparams.cpp (consensus.nAuxpowStartHeight):
    // mainnet=19200, testnet=0, regtest/signet=0. Default -1 = unpinned so a
    // hand-built Params never claims merge-mining is active off a placeholder.
    int32_t auxpow_activation_height{-1};   // -1 = unpinned default; pinned per-net in factory
    // aux_chain_id: the chain id this NMC instance claims in the parent's
    //   merged-mining tree. -1 = unpinned sentinel.
    int32_t aux_chain_id{1};                // Namecoin nAuxpowChainId = 0x0001 (both nets); see chainparams.cpp

    int64_t difficulty_adjustment_interval() const {
        return target_timespan / target_spacing;
    }

    /// Whether merge-mining is required at `height`. Returns false while the
    /// activation height is unpinned (sentinel -1) so the P0 leaf never claims
    /// merge-mining is active off a placeholder.
    bool is_auxpow_active(int32_t height) const {
        if (auxpow_activation_height < 0) return false; // TO-CONFIRM unpinned
        return height >= auxpow_activation_height;
    }

    /// NMC mainnet params skeleton.
    /// TO-CONFIRM: pow_limit + genesis_hash below are placeholders copied from
    /// the Bitcoin-family default; they MUST be replaced with Namecoin's actual
    /// chainparams values before any validation use.
    static NMCChainParams mainnet() {
        NMCChainParams p;
        p.target_timespan = MAINNET_TARGET_TIMESPAN;
        p.target_spacing  = MAINNET_TARGET_SPACING;
        p.allow_min_difficulty = MAINNET_ALLOW_MIN_DIFF;
        p.no_retargeting = false;
        // TO-CONFIRM: Namecoin mainnet powLimit (placeholder = BTC default).
        p.pow_limit.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
        // TO-CONFIRM: Namecoin mainnet genesis hash (placeholder = null).
        p.genesis_hash.SetNull();
        // P2P magic PINNED: namecoin-core kernel/chainparams.cpp CMainParams
        // pchMessageStart = { 0xf9, 0xbe, 0xb4, 0xfe }. (Magic is a published
        // network constant, distinct from the genesis hash which stays
        // TO-CONFIRM pending a mainnet namecoind.)
        p.p2p_magic = {{ 0xf9, 0xbe, 0xb4, 0xfe }};
        // PINNED: namecoin-core CMainParams consensus.nAuxpowStartHeight = 19200
        // (src/kernel/chainparams.cpp). AuxPoW MAY appear at/after height 19200;
        // chain_id stays 1 (field default, nAuxpowChainId = 0x0001).
        p.auxpow_activation_height = 19200;
        return p;
    }

    /// NMC testnet params skeleton (same TO-CONFIRM caveats as mainnet()).
    static NMCChainParams testnet() {
        NMCChainParams p;
        p.target_timespan = TESTNET_TARGET_TIMESPAN;
        p.target_spacing  = TESTNET_TARGET_SPACING;
        p.allow_min_difficulty = TESTNET_ALLOW_MIN_DIFF;
        p.no_retargeting = false;
        // Namecoin testnet powLimit = Bitcoin default (chainparams.cpp CTestNetParams).
        p.pow_limit.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
        // Genesis PINNED against a live namecoind on namecoin testnet
        // (getblockhash 0 / getblockheader, 2026-06-19). block_hash(genesis_header)
        // re-derives this value (nmc_auxpow_wire_test GenesisTestnet KAT).
        p.genesis_hash.SetHex("00000007199508e34a9ff81e6ec0c477a4cccff2a4767a8eee39c11db367b008");
        // P2P magic PINNED: namecoin-core kernel/chainparams.cpp CTestNetParams
        // pchMessageStart = { 0xfa, 0xbf, 0xb5, 0xfe } (testnet3 -- matches the
        // pinned testnet3 genesis time=1296688602 above; testnet4 differs).
        p.p2p_magic = {{ 0xfa, 0xbf, 0xb5, 0xfe }};
        // PINNED: namecoin-core CTestNetParams consensus.nAuxpowStartHeight = 0
        // (fStrictChainId=false). AuxPoW is active from genesis on testnet, so
        // is_auxpow_active(0) must be true.
        p.auxpow_activation_height = 0;
        return p;
    }

    /// Namecoin testnet genesis header (the 80-byte parent the HeaderChain seeds
    /// at height 0). Fields PINNED against a live namecoind getblockheader on
    /// namecoin testnet, 2026-06-19:
    ///   version=1  time=1296688602  bits=0x1d07fff8  nonce=384568319
    ///   merkleroot=4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
    /// SHA256d(header) == genesis_hash() above (verified locally + by KAT).
    static BlockHeaderType testnet_genesis_header() {
        BlockHeaderType g;
        g.m_previous_block.SetNull();
        g.m_version = 1;
        g.m_merkle_root.SetHex("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
        g.m_timestamp = 1296688602;
        g.m_bits      = 0x1d07fff8;
        g.m_nonce     = 384568319;
        return g;
    }
};

// ─── Index Entry ─────────────────────────────────────────────────────────────

/// Status flags for header validation state (mirror of btc::coin shape).
enum HeaderStatus : uint32_t {
    HEADER_VALID_UNKNOWN  = 0,
    HEADER_VALID_HEADER   = 1,  // Header parsed and (own) PoW valid
    HEADER_VALID_TREE     = 2,  // Connected to genesis via prev_hash chain
    HEADER_VALID_CHAIN    = 3,  // Difficulty validated
};

/// A validated header with chain metadata (in-memory representation).
///
/// Mirror of btc::coin::IndexEntry, with an OPTIONAL AuxPow attachment: once
/// merge-mining is active a Namecoin header carries its parent-chain proof.
/// In P0 the AuxPow is stored structurally but NOT verified.
struct IndexEntry {
    BlockHeaderType        header;
    uint256                block_hash;   // SHA256d(header)
    uint32_t               height{0};
    uint256                chain_work;   // cumulative work up to this header
    HeaderStatus           status{HEADER_VALID_UNKNOWN};
    std::optional<AuxPow>  auxpow;       // merge-mining proof (P0: stored, unverified)
};

/// P1f on-disk layout for an IndexEntry (mirror of btc::coin::IndexEntryDiskV1,
/// adapted to NMC). Serialize order: header, block_hash, height, chain_work,
/// status (as uint32_t), then the AuxPow presence flag (uint8_t: 1 if the entry
/// carried a merge-mining proof, else 0).
///
/// P1f(a): the AuxPow proof blob is persisted behind has_auxpow using the
/// canonical Namecoin CAuxPow wire layout (AuxPow::Serialize, fenced to
/// src/impl/nmc/). When has_auxpow == 1 the blob trails the flag and is
/// restored verbatim on load; when 0, nothing follows. The entry's status
/// (HEADER_VALID_CHAIN for a merge-mined header) is preserved either way, so
/// the restored chain's validation state is never lost.
struct IndexEntryDiskV1 {
    BlockHeaderType header;
    uint256         block_hash;   // SHA256d(header)
    uint32_t        height{0};
    uint256         chain_work;   // cumulative work up to this header
    HeaderStatus    status{HEADER_VALID_UNKNOWN};
    uint8_t         has_auxpow{0};  // presence flag for the trailing blob
    std::optional<AuxPow> auxpow;   // P1f(a): proof blob, present iff has_auxpow

    template<typename Stream>
    void Serialize(Stream& s) const {
        ::Serialize(s, header);
        ::Serialize(s, block_hash);
        ::Serialize(s, height);
        ::Serialize(s, chain_work);
        ::Serialize(s, static_cast<uint32_t>(status));
        ::Serialize(s, has_auxpow);
        // P1f(a): the canonical CAuxPow blob trails the flag iff present.
        if (has_auxpow)
            ::Serialize(s, *auxpow);
    }
    template<typename Stream>
    void Unserialize(Stream& s) {
        ::Unserialize(s, header);
        ::Unserialize(s, block_hash);
        ::Unserialize(s, height);
        ::Unserialize(s, chain_work);
        uint32_t st;
        ::Unserialize(s, st);
        status = static_cast<HeaderStatus>(st);
        ::Unserialize(s, has_auxpow);
        // P1f(a): read the canonical CAuxPow blob iff the flag says it is there.
        if (has_auxpow) {
            AuxPow ap;
            ::Unserialize(s, ap);
            auxpow = std::move(ap);
        } else {
            auxpow = std::nullopt;
        }
    }

    /// Materialize the slim in-memory form. auxpow is reconstructed as nullopt
    /// in this leg (blob deferred); status carries the merge-mined verdict.
    IndexEntry to_entry() const {
        IndexEntry e;
        e.header     = header;
        e.block_hash = block_hash;
        e.height     = height;
        e.chain_work = chain_work;
        e.status     = status;
        e.auxpow     = auxpow;         // P1f(a): blob restored behind has_auxpow
        return e;
    }

    /// Build the on-disk form from a slim entry.
    static IndexEntryDiskV1 from_entry(const IndexEntry& e) {
        IndexEntryDiskV1 d;
        d.header      = e.header;
        d.block_hash  = e.block_hash;
        d.height      = e.height;
        d.chain_work  = e.chain_work;
        d.status      = e.status;
        d.has_auxpow  = e.auxpow.has_value() ? 1 : 0;
        d.auxpow      = e.auxpow;      // P1f(a): carry the proof blob too
        return d;
    }
};

/// Work represented by a compact target. Mirror of btc::coin::get_block_proof
/// (src/impl/btc/coin/header_chain.hpp) — NMC is a SHA256d Bitcoin fork, so the
/// work metric is identical. Kept local to the NMC lane (btc tree is read-only;
/// core/ is an exceptional SSOT) rather than cross-including the btc header.
///   work = 2^256 / (target + 1) = ~target / (target + 1) + 1
inline uint256 get_block_proof(uint32_t bits) {
    bool negative, overflow;
    uint256 target;
    target.SetCompact(bits, &negative, &overflow);
    if (negative || target.IsNull() || overflow)
        return uint256::ZERO;
    return (~target / (target + uint256::ONE)) + uint256::ONE;
}

// NMC Difficulty Retarget
// Mirror of btc::coin::calculate_next_work_required / get_next_work_required
// (src/impl/btc/coin/header_chain.hpp). Namecoin is a SHA256d Bitcoin fork and
// shares Bitcoin's 2016-block retarget window / 10-minute spacing, so the
// retarget algorithm is identical. Kept local to the NMC lane (the btc tree is
// read-only; core/ is the exceptional SSOT) rather than cross-including the btc
// header. Adapted from Bitcoin Core pow.cpp (MIT license).

/// Core retarget calculation: adjust difficulty based on actual vs target
/// timespan.
inline uint32_t calculate_next_work_required(
    uint32_t tip_bits,
    int64_t tip_time,
    int64_t first_block_time,
    const NMCChainParams& params)
{
    if (params.no_retargeting)
        return tip_bits;

    int64_t actual_timespan = tip_time - first_block_time;

    // Clamp to [timespan/4, timespan*4].
    if (actual_timespan < params.target_timespan / 4)
        actual_timespan = params.target_timespan / 4;
    if (actual_timespan > params.target_timespan * 4)
        actual_timespan = params.target_timespan * 4;

    // Retarget.
    uint256 bn_new;
    bn_new.SetCompact(tip_bits);
    const uint256 bn_pow_limit = params.pow_limit;

    // Intermediate uint256 can overflow by 1 bit (same guard as btc/ltc).
    bool shift = bn_new.bits() > bn_pow_limit.bits() - 1;
    if (shift)
        bn_new >>= 1;
    bn_new *= static_cast<uint32_t>(actual_timespan);
    bn_new /= uint256(static_cast<uint64_t>(params.target_timespan));
    if (shift)
        bn_new <<= 1;

    if (bn_new > bn_pow_limit)
        bn_new = bn_pow_limit;

    return bn_new.GetCompact();
}

/// Calculate next work required at a given height.
/// @param get_ancestor  Function to look up ancestor header by height.
/// @param tip_height    Height of the current tip (the block we're building on).
/// @param tip_bits      nBits of the current tip.
/// @param tip_time      Timestamp of the current tip.
/// @param new_time      Timestamp of the new block being validated.
/// @param params        Chain parameters.
inline uint32_t get_next_work_required(
    std::function<std::optional<IndexEntry>(uint32_t)> get_ancestor,
    uint32_t tip_height,
    uint32_t tip_bits,
    uint32_t tip_time,
    uint32_t new_time,
    const NMCChainParams& params)
{
    uint256 pow_limit_compact;
    pow_limit_compact = params.pow_limit;
    uint32_t pow_limit_bits = pow_limit_compact.GetCompact();

    // Next block height.
    uint32_t new_height = tip_height + 1;
    int64_t interval = params.difficulty_adjustment_interval();

    // Only change once per difficulty adjustment interval.
    if (new_height % interval != 0) {
        if (params.allow_min_difficulty) {
            // Testnet special rule: if >2x target spacing since last block,
            // allow a min-difficulty block.
            if (static_cast<int64_t>(new_time) > static_cast<int64_t>(tip_time) + params.target_spacing * 2)
                return pow_limit_bits;

            // Return the last non-special-min-difficulty-rules block.
            uint32_t h = tip_height;
            uint32_t last_bits = tip_bits;
            while (h > 0 && (h % interval) != 0 && last_bits == pow_limit_bits) {
                auto ancestor = get_ancestor(h - 1);
                if (!ancestor) break;
                last_bits = ancestor->header.m_bits;
                h--;
            }
            return last_bits;
        }
        return tip_bits;
    }

    if (params.no_retargeting)
        return tip_bits;

    // Bitcoin (and Namecoin) always go back `interval - 1` blocks (= 2015 for
    // the 2016-block retarget window). The Litecoin "Art Forz" off-by-one is
    // not part of Namecoin's history.
    int64_t blocks_to_go_back = interval - 1;

    uint32_t first_height = static_cast<uint32_t>(tip_height - blocks_to_go_back);
    auto first_entry = get_ancestor(first_height);
    if (!first_entry)
        return tip_bits; // shouldn't happen for a connected chain

    int64_t first_time = first_entry->header.m_timestamp;

    return calculate_next_work_required(tip_bits, tip_time, first_time, params);
}

// ─── HeaderChain ─────────────────────────────────────────────────────────────

/// Header-only chain skeleton for embedded NMC. Mirrors the public surface of
/// btc::coin::HeaderChain. P0: the validation internals (difficulty checks,
/// AuxPow checks, LevelDB persistence) are intentionally NOT implemented — the
/// methods below are structural skeletons so call sites compile.
class HeaderChain {
public:
    explicit HeaderChain(const NMCChainParams& params, const std::string& db_path = "")
        : m_params(params)
        , m_db_path(db_path)
    {
    }

    ~HeaderChain() = default;

    // Disable copy (mirror of btc).
    HeaderChain(const HeaderChain&) = delete;
    HeaderChain& operator=(const HeaderChain&) = delete;

    /// Initialize the chain.
    /// P0-DEFER: no LevelDB open, no persisted-state load, no checkpoint seed.
    /// Returns true (structural success) so wiring smoke-tests pass.
    bool init() {
        LOG_INFO << "[EMB-NMC] HeaderChain::init() db_path="
                 << (m_db_path.empty() ? "(in-memory)" : m_db_path);
        if (m_db_path.empty())
            return true;                        // pure in-memory mode

        core::LevelDBOptions opts;
        opts.write_buffer_size = 2 * 1024 * 1024;   // 2MB
        opts.block_cache_size  = 4 * 1024 * 1024;   // 4MB
        m_db = std::make_unique<core::LevelDBStore>(m_db_path, opts);
        if (!m_db->open()) {
            // Non-fatal (mirror of btc): degrade to in-memory and keep running.
            LOG_WARNING << "[EMB-NMC] HeaderChain LevelDB open FAILED at "
                        << m_db_path << " -- continuing in-memory";
            m_db.reset();
            return true;
        }
        LOG_INFO << "[EMB-NMC] HeaderChain LevelDB opened at " << m_db_path;
        load_from_db();
        return true;
    }

    /// Current chain tip (best header). P0: empty until add path is built.
    std::optional<IndexEntry> tip() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_tip.IsNull()) return std::nullopt;
        auto it = m_index.find(m_tip);
        if (it == m_index.end()) return std::nullopt;
        return it->second;
    }

    /// Current chain tip height (0 if empty).
    uint32_t height() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_tip_height;
    }

    /// Cumulative work at the tip.
    uint256 cumulative_work() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_best_work;
    }

    /// Number of headers tracked.
    size_t size() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_index.size();
    }

    /// Whether a header with `block_hash` is known.
    bool has_header(const uint256& block_hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_index.find(block_hash) != m_index.end();
    }

    /// Look up a header by its block hash.
    std::optional<IndexEntry> get_header(const uint256& block_hash) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_index.find(block_hash);
        if (it == m_index.end()) return std::nullopt;
        return it->second;
    }

    /// P1f: build a block locator for getheaders (BIP 31-style exponential
    /// backoff) by walking the tip's ancestry through m_previous_block. Walking
    /// parent links always follows the BEST chain we just fork-chose, so the
    /// locator stays correct across reorgs without a separate height index.
    /// Returns hashes tip..root: dense near the tip, doubling the stride after
    /// the first 10 entries, with the chain root always anchoring the list.
    std::vector<uint256> get_locator() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        std::vector<uint256> locator;
        if (m_tip.IsNull()) return locator;

        // Materialise the tip's ancestry (tip..root) via parent links.
        std::vector<uint256> ancestry;
        uint256 cursor = m_tip;
        while (true) {
            auto it = m_index.find(cursor);
            if (it == m_index.end()) break;        // dangling link -- stop cleanly
            ancestry.push_back(cursor);
            if (it->second.height == 0) break;     // reached chain root
            cursor = it->second.header.m_previous_block;
        }

        // BIP 31-style exponential backoff over the ancestry.
        int64_t step = 1;
        for (size_t i = 0; i < ancestry.size(); i += static_cast<size_t>(step)) {
            locator.push_back(ancestry[i]);
            if (locator.size() > 10)
                step *= 2;
        }
        // Guarantee the chain root anchors the locator.
        if (locator.back() != ancestry.back())
            locator.push_back(ancestry.back());
        return locator;
    }

    /// Add a single plain header.
    /// P0-DEFER: NO difficulty validation, NO PoW check, NO connection check,
    /// NO persistence. Structural skeleton only — returns false.
    /// Add a single plain (non-merge-mined) header.
    /// P1e storage leg: in-memory connect path. On an empty chain the header
    /// seeds the chain root (height 0, checkpoint anchor); otherwise it must
    /// connect to a known parent via m_previous_block. The activation gate
    /// decides admissibility from the connected height (a plain header is
    /// admissible only BELOW activation). While the activation height is the
    /// -1 sentinel the gate returns REJECT_UNPINNED, so in production nothing
    /// connects -- the P1 leaf never builds chain off a placeholder constant.
    /// NO difficulty/PoW validation and NO cumulative-work summation yet (the
    /// next sub-leg); this leg pins connection topology + the activation gate.
    bool add_header(const BlockHeaderType& header) {
        std::lock_guard<std::mutex> lock(m_mutex);
        return connect_locked(header, std::nullopt);
    }

    /// Verify the AuxPow consensus GATE for an incoming merge-mined header.
    /// P1d: factored out so the gate is unit-testable independently of the
    /// (still-deferred) header-storage path. Runs the full four-leg
    /// AuxPow::check_proof against the AUX block hash (block_hash(header)), this
    /// chain's claimed aux_chain_id, and the header's own nBits as the aux PoW
    /// target (Namecoin checks the parent PoW against the AUX bits, not the
    /// parent's own). A header is admissible ONLY when this returns VALID.
    AuxPow::CheckResult verify_auxpow_header(const BlockHeaderType& header,
                                             const AuxPow& auxpow) const {
        return auxpow.check_proof(block_hash(header), m_params.aux_chain_id,
                                  header.m_bits);
    }

    /// P1e: verdict for the activation-height admission gate.
    enum class AdmitResult {
        ADMIT,                    // height / auxpow-presence consistent (proof checked separately)
        REJECT_PREMATURE_AUXPOW,  // header carries an AuxPow below the activation height
        REJECT_MISSING_AUXPOW,    // no AuxPow at/after activation height (mainnet requirement)
        REJECT_UNPINNED,          // activation height still the -1 sentinel - refuse to judge
    };

    /// P1e: the activation-height GATE, factored out for unit-testing
    /// independent of the (still-deferred) storage path - the same pattern as
    /// verify_auxpow_header(). Decides admissibility from the connected `height`
    /// and whether the header carries an AuxPow, BEFORE the four-leg proof is
    /// walked: below activation an AuxPow is premature, at/after activation
    /// (mainnet) one is mandatory. While auxpow_activation_height is the
    /// unpinned -1 sentinel it refuses to judge (REJECT_UNPINNED) so the P1 leaf
    /// never renders an activation verdict off a placeholder constant.
    AdmitResult check_activation_gate(int32_t height, bool has_auxpow) const {
        if (m_params.auxpow_activation_height < 0)
            return AdmitResult::REJECT_UNPINNED;          // TO-CONFIRM unpinned
        if (!m_params.is_auxpow_active(height))
            return has_auxpow ? AdmitResult::REJECT_PREMATURE_AUXPOW
                              : AdmitResult::ADMIT;
        return has_auxpow ? AdmitResult::ADMIT
                          : AdmitResult::REJECT_MISSING_AUXPOW;
    }

    /// Add a header that carries a merge-mining AuxPow proof.
    /// P1d: the AuxPow VERIFICATION GATE is now wired - check_proof() must
    /// return VALID or the header is rejected, so the (future) accept path can
    /// never admit an unproven merge-mined header. The header-storage /
    /// chain-connection path, and the height-derived is_auxpow_active()
    /// activation gate (which needs a connected parent), remain P0-DEFER - see
    /// add_header(). A header that passes the gate is therefore NOT persisted
    /// yet; P1d's contract is the rejection half: nothing unproven gets in.
    bool add_auxpow_header(const BlockHeaderType& header, const AuxPow& auxpow) {
        if (verify_auxpow_header(header, auxpow) != AuxPow::CheckResult::VALID) {
            LOG_WARNING << "[EMB-NMC] reject auxpow header "
                        << block_hash(header).ToString()
                        << ": AuxPow check_proof != VALID";
            return false;
        }
        // P1e storage leg: proof verified -- now connect into the in-memory
        // chain, with the height-derived activation gate enforced inside.
        std::lock_guard<std::mutex> lock(m_mutex);
        return connect_locked(header, auxpow);
    }

    /// Add a batch of plain headers. P0-DEFER: returns 0 (none accepted).
    int add_headers(const std::vector<BlockHeaderType>& headers) {
        (void)headers;
        // P0-DEFER: batch header path not implemented.
        return 0;
    }

    /// P1 PC: look up a header by absolute height by walking the tip's ancestry
    /// through m_previous_block. NMC keeps NO height index (mirror of
    /// get_locator()'s note) so a height lookup walks parent links down the
    /// BEST chain. Returns nullopt when the height is above the tip or the walk
    /// hits a dangling parent. The TemplateBuilder's difficulty retarget needs
    /// at most `interval` ancestors, so this O(depth) walk is bounded in
    /// practice. Caller must NOT hold m_mutex (this acquires it).
    std::optional<IndexEntry> get_header_by_height(uint32_t h) const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_tip.IsNull()) return std::nullopt;
        auto it = m_index.find(m_tip);
        if (it == m_index.end()) return std::nullopt;
        if (h > it->second.height) return std::nullopt;   // above the tip
        // Walk parent links from the tip down to height h.
        uint256 cursor = m_tip;
        while (true) {
            auto cit = m_index.find(cursor);
            if (cit == m_index.end()) return std::nullopt; // dangling link
            if (cit->second.height == h) return cit->second;
            if (cit->second.height == 0) return std::nullopt; // reached root, not found
            cursor = cit->second.header.m_previous_block;
        }
    }

    /// P1 PC: whether the chain tip is recent enough to be considered synced
    /// with the network (mirror of btc::coin::HeaderChain::is_synced). Uses the
    /// shared core::coin::DEFAULT_MAX_TIP_AGE (24h) gate: a chain whose tip is
    /// older than that is still in IBD. An empty chain is never synced.
    bool is_synced() const {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_tip.IsNull()) return false;
        auto it = m_index.find(m_tip);
        if (it == m_index.end()) return false;
        auto now = static_cast<uint32_t>(std::time(nullptr));
        uint32_t age = now - it->second.header.m_timestamp;
        return age < core::coin::DEFAULT_MAX_TIP_AGE;
    }

    const NMCChainParams& params() const { return m_params; }

private:
    // P1e storage leg: shared in-memory connect path for plain and merge-mined
    // headers. Caller holds m_mutex. Derives the connected height from the
    // parent (or 0 for the chain-root seed), runs the activation gate, and on
    // ADMIT inserts the IndexEntry and advances the tip by WORK-BASED fork
    // choice (most-cumulative-work wins, with an equal-work tie-break at the
    // tip height). Returns false -- nothing persisted -- on already-known /
    // orphan / activation-gate rejection.
    bool connect_locked(const BlockHeaderType& header,
                        const std::optional<AuxPow>& auxpow) {
        const uint256 bh = block_hash(header);
        if (m_index.find(bh) != m_index.end())
            return false;                       // already known -- idempotent reject

        int32_t height;
        uint256 parent_work;
        if (m_index.empty()) {
            height = 0;                         // chain-root seed (checkpoint anchor)
            parent_work.SetNull();
        } else {
            auto pit = m_index.find(header.m_previous_block);
            if (pit == m_index.end()) {
                LOG_WARNING << "[EMB-NMC] reject header " << bh.ToString()
                            << ": unknown parent "
                            << header.m_previous_block.ToString() << " (orphan)";
                return false;                   // no orphan headers
            }
            height      = static_cast<int32_t>(pit->second.height) + 1;
            parent_work = pit->second.chain_work;
        }

        const bool has_auxpow = auxpow.has_value();
        switch (check_activation_gate(height, has_auxpow)) {
            case AdmitResult::ADMIT:
                break;
            case AdmitResult::REJECT_PREMATURE_AUXPOW:
                LOG_WARNING << "[EMB-NMC] reject header " << bh.ToString()
                            << ": premature AuxPow below activation (height "
                            << height << ")";
                return false;
            case AdmitResult::REJECT_MISSING_AUXPOW:
                LOG_WARNING << "[EMB-NMC] reject header " << bh.ToString()
                            << ": AuxPow required at/after activation (height "
                            << height << ")";
                return false;
            case AdmitResult::REJECT_UNPINNED:
                return false;                   // activation unpinned: refuse to build
        }

        IndexEntry e;
        e.header     = header;
        e.block_hash = bh;
        e.height     = static_cast<uint32_t>(height);
        // cumulative-work summation: this header's chain_work is the parent's
        // running total plus its own block proof.
        e.chain_work = parent_work + get_block_proof(header.m_bits);
        e.status     = has_auxpow ? HEADER_VALID_CHAIN : HEADER_VALID_TREE;
        e.auxpow     = auxpow;
        const uint256 entry_work = e.chain_work;
        m_index.emplace(bh, std::move(e));

        // Work-based fork choice (mirror of btc::coin::HeaderChain): the best
        // chain is the one with the most CUMULATIVE work, not the greatest
        // height -- so a heavier competing branch reorgs the tip even when it
        // is shorter. An equal-work header at the tip height also switches the
        // tip: it represents network consensus on a tie, which matters on
        // min-difficulty testnet where every block carries identical work.
        // Re-receiving a stored header is the idempotent reject above, so the
        // switch cannot flip-flop.
        bool tip_changed        = false;
        const bool first        = m_tip.IsNull();
        const bool dominated    = entry_work > m_best_work;
        const bool equal_at_tip = entry_work == m_best_work
                               && height == static_cast<int32_t>(m_tip_height)
                               && bh != m_tip;
        if (first || dominated || equal_at_tip) {
            const uint32_t old_height = m_tip_height;
            const uint256  old_tip    = m_tip;
            m_tip        = bh;
            m_tip_height = static_cast<uint32_t>(height);
            m_best_work  = entry_work;          // cumulative work at the new tip
            tip_changed  = true;
            if (!first && (equal_at_tip
                           || height <= static_cast<int32_t>(old_height))) {
                LOG_WARNING << "[EMB-NMC] "
                            << (equal_at_tip ? "EQUAL-WORK REORG" : "REORG")
                            << " at height " << height
                            << ": old_tip=" << old_tip.ToString().substr(0, 16)
                            << " new_tip=" << bh.ToString().substr(0, 16);
            }
        }

        // P1f: persist the newly-accepted header (and, if the tip moved, the
        // tip/height pointers) atomically. Only on this success path -- the
        // idempotent / orphan / activation-gate early returns above never reach
        // here, so nothing is written for a rejected header.
        persist_entry_locked(bh, tip_changed);
        return true;
    }

    // P1f: write a single accepted entry to LevelDB in one synced batch. Caller
    // holds m_mutex and has already inserted the entry into m_index. No-op when
    // running in pure in-memory mode (m_db null / not open).
    void persist_entry_locked(const uint256& bh, bool tip_changed) {
        if (!m_db || !m_db->is_open()) return;
        auto eit = m_index.find(bh);
        if (eit == m_index.end()) return;       // defensive -- should never miss

        auto batch = m_db->create_batch();

        // "h" + block_hash(32 raw bytes) -> serialized IndexEntryDiskV1.
        auto disk   = IndexEntryDiskV1::from_entry(eit->second);
        auto packed = pack(disk);
        std::vector<uint8_t> data(
            reinterpret_cast<const uint8_t*>(packed.data()),
            reinterpret_cast<const uint8_t*>(packed.data()) + packed.size());
        std::string hkey = "h";
        hkey.append(reinterpret_cast<const char*>(bh.data()), 32);
        batch.put(hkey, data);

        if (tip_changed) {
            std::vector<uint8_t> tip_data(m_tip.data(), m_tip.data() + 32);
            batch.put("tip", tip_data);

            const uint32_t h = m_tip_height;
            std::vector<uint8_t> height_data(4);
            height_data[0] = static_cast<uint8_t>((h >> 24) & 0xFF);
            height_data[1] = static_cast<uint8_t>((h >> 16) & 0xFF);
            height_data[2] = static_cast<uint8_t>((h >>  8) & 0xFF);
            height_data[3] = static_cast<uint8_t>( h        & 0xFF);
            batch.put("height", height_data);
        }

        if (!batch.commit_sync())
            LOG_ERROR << "[EMB-NMC] persist_entry_locked: WriteBatch FAILED for "
                      << bh.ToString().substr(0, 16);
    }

    // P1f: restore m_index / m_tip / m_tip_height / m_best_work from LevelDB.
    // Schema (NMC has no height-index, so NO "i" key):
    //   "h" + block_hash(32 raw bytes) -> serialized IndexEntryDiskV1
    //   "tip"                          -> block_hash(32 raw bytes)
    //   "height"                       -> uint32_t, 4 bytes big-endian
    // Caller is init() before any concurrent access; no lock held / needed.
    void load_from_db() {
        if (!m_db || !m_db->is_open()) return;

        // Enumerate every stored header under the "h" prefix and rebuild m_index.
        auto h_keys = m_db->list_keys("h", 10000000);
        size_t loaded = 0;
        for (auto& k : h_keys) {
            if (k.size() != 33 || k[0] != 'h') continue;  // "h" + 32 raw bytes
            std::vector<uint8_t> data;
            if (!m_db->get(k, data)) continue;
            try {
                PackStream ps(data);
                IndexEntryDiskV1 disk;
                ps >> disk;
                IndexEntry e = disk.to_entry();
                const uint256 bh = e.block_hash;
                m_index.emplace(bh, std::move(e));
                ++loaded;
            } catch (const std::exception& ex) {
                LOG_WARNING << "[EMB-NMC] load_from_db: corrupt header entry, skipped: "
                            << ex.what();
            }
        }

        // Restore the tip pointer (32 raw bytes) and height (4 BE bytes).
        std::vector<uint8_t> tip_data;
        if (m_db->get("tip", tip_data) && tip_data.size() == 32) {
            std::memcpy(m_tip.data(), tip_data.data(), 32);
            auto tit = m_index.find(m_tip);
            if (tit == m_index.end()) {
                LOG_WARNING << "[EMB-NMC] load_from_db: tip hash not in index -- resetting";
                m_tip.SetNull();
            } else {
                m_best_work = tit->second.chain_work;   // recompute best-work from tip
            }
        }
        std::vector<uint8_t> height_data;
        if (!m_tip.IsNull() && m_db->get("height", height_data) && height_data.size() == 4) {
            m_tip_height = (static_cast<uint32_t>(height_data[0]) << 24)
                         | (static_cast<uint32_t>(height_data[1]) << 16)
                         | (static_cast<uint32_t>(height_data[2]) <<  8)
                         |  static_cast<uint32_t>(height_data[3]);
        }

        LOG_INFO << "[EMB-NMC] load_from_db: loaded " << loaded << " headers"
                 << " tip=" << (m_tip.IsNull() ? "(null)" : m_tip.ToString().substr(0, 16))
                 << " height=" << m_tip_height;
    }

    NMCChainParams m_params;
    std::string    m_db_path;
    std::unique_ptr<core::LevelDBStore> m_db;   // P1f: null in pure in-memory mode

    mutable std::mutex m_mutex;
    std::unordered_map<uint256, IndexEntry, Uint256Hasher> m_index;
    uint256        m_tip;            // null until first accepted header
    uint32_t       m_tip_height{0};
    uint256        m_best_work;

    // P0-DEFER: difficulty validation, AuxPow verification, LevelDB
    // persistence and height-index rebuild are deliberately absent in this
    // structural leaf (locator generation landed in P1f).
};

} // namespace coin
} // namespace nmc
