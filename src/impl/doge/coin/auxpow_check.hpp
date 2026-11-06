// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// DOGE: a header's proof of work as Dogecoin Core 1.14.9 checks it
/// (dogecoin.cpp CheckAuxPowProofOfWork, auxpow.cpp CAuxPow::check), for the
/// headers and blocks the P2P parsers read (auxpow_header.hpp): the AuxPoW
/// proof is verified where it is parsed, before its 80-byte base header
/// reaches the header chain.
///   - a non-legacy header carries the DOGE chain id (strict chain id);
///   - the AuxPoW version flag and the proof go together;
///   - with a proof: the parent header's scrypt meets the header's nBits,
///     and CAuxPow::check: the parent coinbase is the parent block's first
///     tx (its branch from index 0 reaches the parent's merkle root), the
///     parent does not carry our chain id, the chain merkle branch (at most
///     30) from the header's hash gives the root the parent coinbase's first
///     input commits to (after the merged-mining magic, or within its first
///     20 bytes), followed by the tree size (2^branch length) and a nonce
///     whose expected index is the branch's;
///   - without one, the header's own scrypt is the header chain's check.

#include <impl/doge/coin/auxpow.hpp>
#include <impl/doge/coin/chain_params.hpp>

#include <btclibs/crypto/scrypt.h>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace doge {
namespace coin {

struct AuxPowRules {
    int32_t chain_id{DOGEChainParams::AUXPOW_CHAIN_ID};
    bool    strict_chain_id{true};
    uint256 pow_limit;
};

inline AuxPowRules auxpow_rules(const DOGEChainParams& p)
{
    AuxPowRules r;
    r.strict_chain_id = p.strict_chain_id;
    r.pow_limit = p.pow_limit;
    return r;
}

/// CAuxPow::CheckMerkleBranch.
inline uint256 aux_merkle_branch(uint256 hash, const std::vector<uint256>& branch, int64_t index)
{
    if (index == -1)
        return uint256();
    for (const auto& b : branch) {
        if (index & 1)
            hash = Hash(std::span<const uint8_t>(b.data(), 32), std::span<const uint8_t>(hash.data(), 32));
        else
            hash = Hash(std::span<const uint8_t>(hash.data(), 32), std::span<const uint8_t>(b.data(), 32));
        index >>= 1;
    }
    return hash;
}

/// CAuxPow::getExpectedIndex.
inline uint32_t aux_expected_index(uint32_t nonce, int32_t chain_id, unsigned h)
{
    uint32_t rand = nonce;
    rand = rand * 1103515245u + 12345u;
    rand += static_cast<uint32_t>(chain_id);
    rand = rand * 1103515245u + 12345u;
    return rand % (1u << h);
}

/// Dogecoin Core's CheckProofOfWork: nBits a valid target within the limit,
/// the hash at or below it.
inline bool aux_check_pow(const uint256& hash, uint32_t bits, const uint256& pow_limit)
{
    bool negative = false, overflow = false;
    uint256 target;
    target.SetCompact(bits, &negative, &overflow);
    if (negative || target.IsNull() || overflow || target > pow_limit)
        return false;
    return hash <= target;
}

inline uint256 aux_scrypt(const CPureBlockHeader& h)
{
    auto packed = pack(h);
    char out[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(packed.data()), out);
    uint256 r;
    std::memcpy(r.data(), out, 32);
    return r;
}

/// CAuxPow::check(hash_aux_block, chain_id): nullopt when valid, else why.
template <typename Tx>
std::optional<std::string> check_auxpow(const CAuxPow<Tx>& aux, const uint256& hash_aux_block, int32_t chain_id,
                                        bool strict_chain_id)
{
    const auto& mtx = aux.m_merkle_tx;
    if (mtx.m_merkle_link.m_index != 0)
        return "AuxPow is not a generate";
    if (strict_chain_id && (static_cast<int32_t>(aux.m_parent_block_header.m_version) >> 16) == chain_id)
        return "Aux POW parent has our chain ID";
    const auto& chain_branch = aux.m_chain_merkle_link.m_branch;
    if (chain_branch.size() > 30)
        return "Aux POW chain merkle branch too long";
    const uint256 root = aux_merkle_branch(hash_aux_block, chain_branch,
                                           static_cast<int32_t>(aux.m_chain_merkle_link.m_index));
    std::vector<unsigned char> root_bytes(root.data(), root.data() + 32);
    std::reverse(root_bytes.begin(), root_bytes.end());
    if (aux_merkle_branch(parent_coinbase_txid(mtx.m_tx), mtx.m_merkle_link.m_branch,
                          static_cast<int32_t>(mtx.m_merkle_link.m_index))
        != aux.m_parent_block_header.m_merkle_root)
        return "Aux POW merkle root incorrect";
    if (mtx.m_tx.vin.empty())
        return "Aux POW coinbase has no inputs";
    const auto& script = mtx.m_tx.vin[0].scriptSig.m_data;
    static const unsigned char kMagic[4] = {0xfa, 0xbe, 'm', 'm'};
    const auto head = std::search(script.begin(), script.end(), std::begin(kMagic), std::end(kMagic));
    auto pc = std::search(script.begin(), script.end(), root_bytes.begin(), root_bytes.end());
    if (pc == script.end())
        return "Aux POW missing chain merkle root in parent coinbase";
    if (head != script.end()) {
        if (std::search(head + 1, script.end(), std::begin(kMagic), std::end(kMagic)) != script.end())
            return "Multiple merged mining headers in coinbase";
        if (head + sizeof(kMagic) != pc)
            return "Merged mining header is not just before chain merkle root";
    } else if (pc - script.begin() > 20) {
        return "Aux POW chain merkle root must start in the first 20 bytes of the parent coinbase";
    }
    pc += static_cast<std::ptrdiff_t>(root_bytes.size());
    if (script.end() - pc < 8)
        return "Aux POW missing chain merkle tree size and nonce in parent coinbase";
    auto le32 = [](auto it) {
        return uint32_t(it[0]) | (uint32_t(it[1]) << 8) | (uint32_t(it[2]) << 16) | (uint32_t(it[3]) << 24);
    };
    const uint32_t size = le32(pc);
    const unsigned height = static_cast<unsigned>(chain_branch.size());
    if (size != (1u << height))
        return "Aux POW merkle branch size does not match parent coinbase";
    const uint32_t nonce = le32(pc + 4);
    if (aux.m_chain_merkle_link.m_index != aux_expected_index(nonce, chain_id, height))
        return "Aux POW wrong index";
    return std::nullopt;
}

/// CheckAuxPowProofOfWork for a parsed header: nullopt when it passes (a
/// header without a proof: its chain id and flag; its own PoW is the header
/// chain's), else why.
template <typename Tx>
std::optional<std::string> check_auxpow_header(const CPureBlockHeader& hdr, const CAuxPow<Tx>* aux,
                                               const AuxPowRules& r)
{
    const int32_t version = static_cast<int32_t>(hdr.m_version);
    const int32_t header_chain_id = version >> 16;
    const bool legacy = version == 1 || (version == 2 && header_chain_id == 0);
    if (!legacy && r.strict_chain_id && header_chain_id != r.chain_id)
        return "block does not have our chain ID";
    const bool flagged = is_auxpow_version(version);
    if (!aux)
        return flagged ? std::optional<std::string>("no auxpow on block with auxpow version") : std::nullopt;
    if (!flagged)
        return "auxpow on block with non-auxpow version";
    if (!aux_check_pow(aux_scrypt(aux->m_parent_block_header), hdr.m_bits, r.pow_limit))
        return "AUX proof of work failed";
    auto packed = pack(hdr);
    const uint256 hash = Hash(packed.get_span());
    if (auto why = check_auxpow(*aux, hash, header_chain_id, r.strict_chain_id))
        return "AUX POW is not valid: " + *why;
    return std::nullopt;
}

} // namespace coin
} // namespace doge
