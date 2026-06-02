#pragma once

/// DOGE AuxPoW data structures — Phase 5.8 M2 (C++ class skeletons)
///
/// 1:1 C++ mapping of the merged-mining AuxPoW type hierarchy defined in the
/// pinned reference p2pool-merged-v36 (HEAD 847af661), p2pool/bitcoin/data.py.
/// These skeletons declare the struct hierarchy and the serialization surface;
/// the structured variable-length parser and proof validation land in M3.
///
/// Reference §1 hierarchy (p2pool/bitcoin/data.py):
///   merkle_link_type  (data.py:226)  -> CMerkleLink
///   merkle_tx_type    (data.py:231)  -> CMerkleTx
///   block_header_type (data.py:237)  -> CPureBlockHeader (== bitcoin_family BlockHeaderType)
///   aux_pow_type      (data.py:258)  -> CAuxPow
///
/// Wire layout of an AuxPoW-extended DOGE header (P2P / getblock):
///   CPureBlockHeader (80B)      child block header
///   + CAuxPow (variable)        merge-mining proof, present iff IsAuxpow(version)
///   + tx_count (CompactSize)    0 in a 'headers' message
///
/// §12-Q1 RESOLVED (M2): the parent (LTC) coinbase carried in CAuxPow.merkle_tx.tx
/// is the pool's OWN generated coinbase (gentx), NOT a getblock RPC result.
/// Reference: p2pool/work.py:3043-3047
///     ltc_coinbase_hash          = bitcoin_data.get_txid(new_gentx)
///     packed_coinbase_for_auxpow = bitcoin_data.tx_id_type.pack(new_gentx)
/// i.e. the coinbase is serialized via tx_id_type (witness-stripped) from new_gentx.
/// No divergence from the reference -> no decisions@ escalation required.

#include <impl/ltc/coin/transaction.hpp>            // MutableTransaction, TX_NO_WITNESS
#include <impl/bitcoin_family/coin/base_block.hpp>   // BlockHeaderType

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>

#include <vector>
#include <cstdint>

namespace doge {
namespace coin {

/// CPureBlockHeader == the standard 80-byte Bitcoin-family block header
/// (block_header_type, data.py:237). Reused from bitcoin_family to preserve
/// per-coin isolation: no new header type, no src/core or bitcoin_family edit.
using CPureBlockHeader = bitcoin_family::coin::BlockHeaderType;

/// merkle_link_type (data.py:226-229)
///     ('branch', ListType(IntType(256)))   -> m_branch
///     ('index',  IntType(32))              -> m_index
struct CMerkleLink
{
    std::vector<uint256> m_branch;
    uint32_t             m_index{0};

    SERIALIZE_METHODS(CMerkleLink) { READWRITE(obj.m_branch, obj.m_index); }

    void SetNull() { m_branch.clear(); m_index = 0; }
    bool IsNull() const { return m_branch.empty() && m_index == 0; }
};

/// merkle_tx_type (data.py:231-235)
///     ('tx',          tx_id_type)        -> m_tx  (witness-stripped; see §12-Q1)
///     ('block_hash',  IntType(256))      -> m_block_hash
///     ('merkle_link', merkle_link_type)  -> m_merkle_link
struct CMerkleTx
{
    ltc::coin::MutableTransaction m_tx;          // parent-chain (LTC) coinbase == gentx
    uint256                       m_block_hash;
    CMerkleLink                   m_merkle_link;

    SERIALIZE_METHODS(CMerkleTx) {
        // tx_id_type == witness-stripped tx serialization (data.py:232)
        READWRITE(TX_NO_WITNESS(obj.m_tx), obj.m_block_hash, obj.m_merkle_link);
    }

    void SetNull() {
        m_tx = ltc::coin::MutableTransaction{};
        m_block_hash.SetNull();
        m_merkle_link.SetNull();
    }
};

/// aux_pow_type (data.py:258-262)
///     ('merkle_tx',           merkle_tx_type)    -> m_merkle_tx
///     ('merkle_link',         merkle_link_type)  -> m_chain_merkle_link
///     ('parent_block_header', block_header_type) -> m_parent_block_header
struct CAuxPow
{
    CMerkleTx        m_merkle_tx;            // parent coinbase + branch to parent merkle root
    CMerkleLink      m_chain_merkle_link;    // aux/chain merkle branch + slot index
    CPureBlockHeader m_parent_block_header;  // parent (LTC) 80-byte header

    SERIALIZE_METHODS(CAuxPow) {
        READWRITE(obj.m_merkle_tx, obj.m_chain_merkle_link, obj.m_parent_block_header);
    }

    void SetNull() {
        m_merkle_tx.SetNull();
        m_chain_merkle_link.SetNull();
        m_parent_block_header.SetNull();
    }

    /// M3: validate this proof against the child block hash + DOGE chain_id.
    /// Mirrors verify_merged_coinbase_commitment / check_merkle_link
    /// (data.py:348, 456). Returns true iff the merge-mining proof commits to
    /// `child_block_hash` under `chain_id`. Declared here; implemented in M3.
    bool check_proof(const uint256& child_block_hash, int32_t chain_id) const;
};

/// Version bit 0x100 marks an AuxPoW block (CPureBlockHeader::IsAuxpow()).
/// Matches dogecoin/src/primitives/pureheader.h.
inline bool is_auxpow_version(int32_t version) { return (version & 0x100) != 0; }

/// M3: structured parse of a (possibly AuxPoW-extended) DOGE header from `s`.
///   - reads CPureBlockHeader (80B)
///   - if is_auxpow_version(version): reads CAuxPow into `out_aux`, sets has_aux
/// Supersedes the skip-only parser in auxpow_header.hpp. Declared here; M3 impl.
template <typename Stream>
CPureBlockHeader parse_aux_header(Stream& s, CAuxPow& out_aux, bool& has_aux);

} // namespace coin
} // namespace doge
