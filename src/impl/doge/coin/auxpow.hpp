// SPDX-License-Identifier: AGPL-3.0-or-later
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
/// §12-Q1 (M2) is about what c2pool EMITS: the parent (LTC) coinbase in the
/// proofs c2pool builds is the pool's own gentx, serialized witness-stripped
/// (p2pool/work.py:3043-3047, tx_id_type.pack(new_gentx); here
/// merged_mining.cpp build_auxpow_proof, from hex). That is unchanged.
///
/// What c2pool ACCEPTS is whatever Dogecoin Core emits. Core (auxpow.h:81
/// READWRITE(tx) in CMerkleTx) serializes the parent coinbase with the
/// stream's default params: witness ALLOWED (primitives/transaction.h:212),
/// so a 'headers' message carries another pool's LTC coinbase with its
/// BIP144 marker, flag and witness-reserved value whenever the node stored it
/// that way (only a 'block' answering MSG_BLOCK, net_processing.cpp:1125, and
/// a compact block for a peer that wants no witnesses, :1161, are sent
/// stripped). Both encodings are legal; CMerkleTx reads and
/// writes with parent_coinbase_wire_params below, and the txid the merkle
/// branch commits to stays the witness-stripped hash (parent_coinbase_txid).

#include <impl/ltc/coin/transaction.hpp>            // MutableTransaction, TX_NO_WITNESS
#include <impl/bitcoin_family/coin/base_block.hpp>   // BlockHeaderType

#include <core/hash.hpp>
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

    // Hand-written to stay independent of which SERIALIZE_METHODS macro is
    // active in the TU: core/pack.hpp defines a 1-arg form, btclibs/serialize.h
    // a 2-arg one, and CMerkleTx::m_tx pulls btclibs into this header's TUs.
    template <typename Stream> void Serialize(Stream& s) const {
        ::Serialize(s, m_branch);
        ::Serialize(s, m_index);
    }
    template <typename Stream> void Unserialize(Stream& s) {
        ::Unserialize(s, m_branch);
        ::Unserialize(s, m_index);
    }

    void SetNull() { m_branch.clear(); m_index = 0; }
    bool IsNull() const { return m_branch.empty() && m_index == 0; }
};

/// Witness-strip params for the PARENT coinbase tx (tx_id_type, data.py:232):
/// the txid (parent_coinbase_txid), never the wire form (see
/// parent_coinbase_wire_params). Each parent chain owns its TxParams *type*: LTC/DASH reuse
/// bitcoin_family::coin::TxParams via a using-declaration, while DGB declares
/// its own dgb::coin::TxParams. The no-witness wrapper must therefore resolve
/// from the PARENT type instead of hardcoding bitcoin_family's -- a DGB parent
/// coinbase handed a bitcoin_family::coin::TxParams cannot serialize through
/// dgb's SerializeTransaction (distinct type -> hard compile error). LTC is
/// only spared today because it shares bitcoin_family's TxParams type.
///
/// Primary template -> bitcoin_family's TX_NO_WITNESS: byte-identical to the
/// pre-template hardcode for every parent that reuses bitcoin_family TxParams
/// (LTC, DASH). A parent with its OWN TxParams type specializes this in ITS
/// OWN tree (never here) to point at its namespace TX_NO_WITNESS, keeping this
/// shared module free of any per-parent (e.g. DGB) include.
template <typename ParentCoinbaseTx>
struct parent_coinbase_no_witness
{
    static constexpr auto value = bitcoin_family::coin::TX_NO_WITNESS;
};

/// Wire params of the PARENT coinbase inside CMerkleTx: Dogecoin Core
/// (auxpow.h:81 READWRITE(tx)) uses the stream's default, i.e. witness
/// ALLOWED (transaction.h:212) and no MWEB (flag 8 -> "Unknown transaction
/// optional data", transaction.h:238). A stripped coinbase (vin non-empty)
/// parses the same way, so both legal encodings are accepted; a witness-
/// carrying one round-trips byte-identical, and one without a witness
/// serializes exactly as before. One refusal is stricter than Dogecoin Core
/// 1.14.9: flag 1 with every witness stack empty ("Superfluous witness
/// record", the LTC transaction reader) - Core accepts it, but never emits
/// it (it writes flag 1 only for a non-empty stack, transaction.h:252-256).
/// Same per-parent rule as above: a parent with its own TxParams type
/// specializes this in its own tree.
template <typename ParentCoinbaseTx>
struct parent_coinbase_wire_params
{
    static constexpr bitcoin_family::coin::TxParams value{.allow_witness = true, .allow_mweb = false};
};

/// The parent coinbase's txid: SHA256d of its witness-stripped serialization
/// (CTransaction::GetHash), the leaf CMerkleTx's branch commits to in the
/// parent block's merkle root, whichever encoding the proof carried.
template <typename ParentCoinbaseTx>
uint256 parent_coinbase_txid(const ParentCoinbaseTx& tx)
{
    auto packed = pack(parent_coinbase_no_witness<ParentCoinbaseTx>::value(tx));
    return Hash(packed.get_span());
}

/// merkle_tx_type (data.py:231-235)
///     ('tx',          tx_id_type)        -> m_tx  (wire: parent_coinbase_wire_params)
///     ('block_hash',  IntType(256))      -> m_block_hash
///     ('merkle_link', merkle_link_type)  -> m_merkle_link
template <typename ParentCoinbaseTx = ltc::coin::MutableTransaction>
struct CMerkleTx
{
    ParentCoinbaseTx m_tx;          // parent-chain coinbase == gentx (default LTC; DGB binds dgb::coin::MutableTransaction)
    uint256                       m_block_hash;
    CMerkleLink                   m_merkle_link;

    // Core's CMerkleTx field order; the coinbase as Core reads and writes it.
    template <typename Stream> void Serialize(Stream& s) const {
        ::Serialize(s, parent_coinbase_wire_params<ParentCoinbaseTx>::value(m_tx));
        ::Serialize(s, m_block_hash);
        ::Serialize(s, m_merkle_link);
    }
    template <typename Stream> void Unserialize(Stream& s) {
        ::Unserialize(s, parent_coinbase_wire_params<ParentCoinbaseTx>::value(m_tx));
        ::Unserialize(s, m_block_hash);
        ::Unserialize(s, m_merkle_link);
    }

    void SetNull() {
        m_tx = ParentCoinbaseTx{};
        m_block_hash.SetNull();
        m_merkle_link.SetNull();
    }
};

/// aux_pow_type (data.py:258-262)
///     ('merkle_tx',           merkle_tx_type)    -> m_merkle_tx
///     ('merkle_link',         merkle_link_type)  -> m_chain_merkle_link
///     ('parent_block_header', block_header_type) -> m_parent_block_header
template <typename ParentCoinbaseTx = ltc::coin::MutableTransaction>
struct CAuxPow
{
    CMerkleTx<ParentCoinbaseTx> m_merkle_tx;  // parent coinbase + branch to parent merkle root
    CMerkleLink      m_chain_merkle_link;    // aux/chain merkle branch + slot index
    CPureBlockHeader m_parent_block_header;  // parent (LTC) 80-byte header

    template <typename Stream> void Serialize(Stream& s) const {
        ::Serialize(s, m_merkle_tx);
        ::Serialize(s, m_chain_merkle_link);
        ::Serialize(s, m_parent_block_header);
    }
    template <typename Stream> void Unserialize(Stream& s) {
        ::Unserialize(s, m_merkle_tx);
        ::Unserialize(s, m_chain_merkle_link);
        ::Unserialize(s, m_parent_block_header);
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
///   - if is_auxpow_version(version): deserializes CAuxPow into `out_aux`, has_aux=true
///   - else: clears `out_aux`, has_aux=false
/// Supersedes the byte-skip parser in auxpow_header.hpp: the AuxPoW proof is now
/// deserialized into the CAuxPow/CMerkleTx/CMerkleLink hierarchy via the standard
/// pack.hpp surface, not merely skipped. The 80-byte base header is what
/// HeaderChain consumes; `out_aux` carries the proof for validation
/// (CAuxPow::check_proof, future milestone). Throws on truncation/parse failure.
template <typename Stream, typename ParentCoinbaseTx = ltc::coin::MutableTransaction>
CPureBlockHeader parse_aux_header(Stream& s, CAuxPow<ParentCoinbaseTx>& out_aux, bool& has_aux)
{
    CPureBlockHeader hdr;
    ::Unserialize(s, hdr);                                  // 80-byte base header
    has_aux = is_auxpow_version(static_cast<int32_t>(hdr.m_version));
    if (has_aux) {
        ::Unserialize(s, out_aux);                          // structured CAuxPow proof
    } else {
        out_aux.SetNull();
    }
    return hdr;
}

} // namespace coin
} // namespace doge