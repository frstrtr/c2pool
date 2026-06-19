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

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
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

    /// Result of a (future) AuxPow verification.
    enum class CheckResult {
        NOT_IMPLEMENTED_P0,   //!< P0 leaf — verification path not built yet
        VALID,
        INVALID,
    };

    /// Verify that this AuxPow actually proves work for `aux_block_hash`
    /// against the given expected aux chain id.
    ///
    /// P0-DEFER: NOT IMPLEMENTED in P0. The real implementation must, against
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
                            int32_t expected_chain_id) const {
        // P0-DEFER: structural stub. Deliberately performs NO verification.
        (void)aux_block_hash;
        (void)expected_chain_id;
        return CheckResult::NOT_IMPLEMENTED_P0;
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
    int32_t auxpow_activation_height{-1};   // TO-CONFIRM: mainnet ~19200 (unpinned sentinel)
    int32_t testnet_auxpow_activation_height{-1}; // TO-CONFIRM: testnet analog (unpinned sentinel)
    // aux_chain_id: the chain id this NMC instance claims in the parent's
    //   merged-mining tree. -1 = unpinned sentinel.
    int32_t aux_chain_id{-1};               // TO-CONFIRM: Namecoin mainnet chain id (unpinned)

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
        // TO-CONFIRM: activation height + chain id stay unpinned (-1).
        return p;
    }

    /// NMC testnet params skeleton (same TO-CONFIRM caveats as mainnet()).
    static NMCChainParams testnet() {
        NMCChainParams p;
        p.target_timespan = TESTNET_TARGET_TIMESPAN;
        p.target_spacing  = TESTNET_TARGET_SPACING;
        p.allow_min_difficulty = TESTNET_ALLOW_MIN_DIFF;
        p.no_retargeting = false;
        // TO-CONFIRM: Namecoin testnet powLimit (placeholder = BTC default).
        p.pow_limit.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
        // TO-CONFIRM: Namecoin testnet genesis hash (placeholder = null).
        p.genesis_hash.SetNull();
        return p;
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
        LOG_INFO << "[EMB-NMC] HeaderChain::init() (P0 structural stub) db_path="
                 << (m_db_path.empty() ? "(in-memory)" : m_db_path);
        // P0-DEFER: persistence + checkpoint-seed not implemented.
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

    /// Add a single plain header.
    /// P0-DEFER: NO difficulty validation, NO PoW check, NO connection check,
    /// NO persistence. Structural skeleton only — returns false.
    bool add_header(const BlockHeaderType& header) {
        (void)header;
        // P0-DEFER: header add/validate path not implemented.
        return false;
    }

    /// Add a header that carries a merge-mining AuxPow proof.
    /// P0-DEFER: stores nothing and verifies nothing. The real path must call
    /// AuxPow::check_proof() (itself a P0 stub) before accepting.
    bool add_auxpow_header(const BlockHeaderType& header, const AuxPow& auxpow) {
        (void)header;
        (void)auxpow;
        // P0-DEFER: auxpow header add/validate path not implemented.
        // NOTE: even when built, must reject unless params.is_auxpow_active(h)
        //       and auxpow.check_proof(block_hash(header), params.aux_chain_id)
        //       == AuxPow::CheckResult::VALID.
        return false;
    }

    /// Add a batch of plain headers. P0-DEFER: returns 0 (none accepted).
    int add_headers(const std::vector<BlockHeaderType>& headers) {
        (void)headers;
        // P0-DEFER: batch header path not implemented.
        return 0;
    }

    const NMCChainParams& params() const { return m_params; }

private:
    NMCChainParams m_params;
    std::string    m_db_path;

    mutable std::mutex m_mutex;
    std::unordered_map<uint256, IndexEntry, Uint256Hasher> m_index;
    uint256        m_tip;            // null until first accepted header
    uint32_t       m_tip_height{0};
    uint256        m_best_work;

    // P0-DEFER: difficulty validation, AuxPow verification, LevelDB
    // persistence, height-index rebuild, and locator generation are all
    // deliberately absent in this structural leaf.
};

} // namespace coin
} // namespace nmc
