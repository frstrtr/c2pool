#pragma once

// P2: Share verification — check_hash_link, check_merkle_link, share init/check
// Ported from legacy sharechains/data.cpp + sharechains/share.cpp

#include "config_pool.hpp"
#include "share.hpp"
#include "share_messages.hpp"
#include "share_types.hpp"

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <btclibs/crypto/common.h>
#include <btclibs/crypto/sha256.h>
#include <btclibs/crypto/scrypt.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace ltc
{

// P2Pool witness nonce: '[P2Pool]' repeated 4 times = 32 bytes
// Used for witness commitment: SHA256d(wtxid_merkle_root || P2POOL_WITNESS_NONCE)
static const unsigned char P2POOL_WITNESS_NONCE[32] = {
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
    0x5b, 0x50, 0x32, 0x50, 0x6f, 0x6f, 0x6c, 0x5d,
};

// Compute P2Pool witness commitment hash from raw wtxid merkle root.
// Returns SHA256d(root || '[P2Pool]'*4)
inline uint256 compute_p2pool_witness_commitment(const uint256& wtxid_merkle_root) {
    uint256 nonce;
    std::memcpy(nonce.data(), P2POOL_WITNESS_NONCE, 32);
    return Hash(wtxid_merkle_root, nonce);
}

// ============================================================================
// check_hash_link()
//
// Restores SHA256 mid-state from hash_link, continues hashing with
// (data + extra), then double-SHA256 finalises to the gentx_hash.
//
// Legacy: sharechains/data.cpp  check_hash_link()
// ============================================================================
template <typename HashLinkT>
inline uint256 check_hash_link(const HashLinkT& hash_link,
                               const std::vector<unsigned char>& data,
                               const std::vector<unsigned char>& const_ending = {})
{
    const uint64_t extra_length = hash_link.m_length % 64; // 512/8 = 64

    // hash_link.extra_data handling:
    // Python reference (check_hash_link in p2pool/data.py):
    //   extra = (extra_data + const_ending)[len(extra_data) + len(const_ending) - extra_length:]
    // This takes the LAST extra_length bytes of (extra_data + const_ending),
    // i.e. extra_data first, then const_ending tail — matching the original
    // byte order in the coinbase prefix (after the full SHA256 blocks).
    std::vector<unsigned char> extra;
    if constexpr (requires { hash_link.m_extra_data.m_data; })
    {
        // V36HashLinkType: extra_data is BaseScript (VarStr)
        extra.assign(hash_link.m_extra_data.m_data.begin(),
                     hash_link.m_extra_data.m_data.end());
        if (extra.size() < extra_length)
        {
            // Append const_ending tail AFTER extra_data (matching Python's order)
            auto needed = extra_length - extra.size();
            if (const_ending.size() >= needed)
                extra.insert(extra.end(), const_ending.end() - needed, const_ending.end());
        }
    }
    else
    {
        // Pre-V36: extra_data always empty, use const_ending tail
        extra.assign(const_ending.begin(), const_ending.end());
        if (extra.size() > extra_length)
            extra.erase(extra.begin(), extra.begin() + (extra.size() - extra_length));
    }
    if (extra.size() != extra_length)
        throw std::runtime_error("check_hash_link: extra size mismatch");

    // Restore SHA256 mid-state from hash_link.m_state (32 bytes, big-endian)
    const auto& state_bytes = hash_link.m_state.m_data;
    uint32_t init_state[8] = {
        ReadBE32(state_bytes.data() +  0),
        ReadBE32(state_bytes.data() +  4),
        ReadBE32(state_bytes.data() +  8),
        ReadBE32(state_bytes.data() + 12),
        ReadBE32(state_bytes.data() + 16),
        ReadBE32(state_bytes.data() + 20),
        ReadBE32(state_bytes.data() + 24),
        ReadBE32(state_bytes.data() + 28),
    };

    // Continue hashing from mid-state: Write(data) fills the partial
    // block (extra is already in buf via the constructor), then processes
    // remaining full blocks.  Single SHA256 pass.
    unsigned char out1[CSHA256::OUTPUT_SIZE];
    CSHA256(init_state, extra, hash_link.m_length)
        .Write(data.data(), data.size())
        .Finalize(out1);

    // Second SHA256 pass → double-SHA256
    unsigned char out2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(out1, CSHA256::OUTPUT_SIZE).Finalize(out2);

    // Write raw double-SHA256 output directly into uint256
    // (matches Bitcoin Core's Hash() which does the same)
    uint256 result;
    std::memcpy(result.data(), out2, 32);
    return result;
}

// ============================================================================
// prefix_to_hash_link()
//
// Forward computation of hash_link: given a coinbase prefix (everything up to
// and including the const_ending), capture the SHA256 mid-state so that
// check_hash_link() can resume and produce the coinbase txid.
//
// Python reference (p2pool):
//   def prefix_to_hash_link(prefix, const_ending=''):
//       x = sha256(prefix)
//       return dict(state=x.state, extra_data=x.buf[:max(0,len(x.buf)-len(const_ending))],
//                   length=x.length//8)
// ============================================================================
inline V36HashLinkType prefix_to_hash_link(
    const std::vector<unsigned char>& prefix,
    const std::vector<unsigned char>& const_ending)
{
    // Feed the entire prefix into a CSHA256
    CSHA256 hasher;
    hasher.Write(prefix.data(), prefix.size());

    V36HashLinkType result;

    // Extract mid-state as big-endian bytes (matches check_hash_link's ReadBE32)
    result.m_state.m_data.resize(32);
    for (int i = 0; i < 8; ++i) {
        WriteBE32(result.m_state.m_data.data() + i * 4, hasher.s[i]);
    }

    // extra_data = buf[0 .. bufsize - const_ending_len]
    size_t bufsize = hasher.bytes % 64;
    size_t extra_len = (bufsize > const_ending.size()) ? (bufsize - const_ending.size()) : 0;
    result.m_extra_data.m_data.assign(hasher.buf, hasher.buf + extra_len);

    // length = total bytes processed so far
    result.m_length = hasher.bytes;

    return result;
}

// ============================================================================
// check_merkle_link()
//
// Walk a Merkle branch to compute the root from a given tip_hash.
//
// Legacy: libcoind/data.cpp  check_merkle_link()
// ============================================================================
inline uint256 check_merkle_link(const uint256& tip_hash, const MerkleLink& link)
{
    if (link.m_branch.size() > 0 &&
        link.m_index >= (1u << link.m_branch.size()))
        throw std::invalid_argument("check_merkle_link: index too large");

    uint256 cur = tip_hash;
    for (size_t i = 0; i < link.m_branch.size(); ++i)
    {
        // Combine: if bit i of index is set, branch[i] is on the left
        PackStream ps;
        if ((link.m_index >> i) & 1)
        {
            ps << link.m_branch[i];
            ps << cur;
        }
        else
        {
            ps << cur;
            ps << link.m_branch[i];
        }

        // double-SHA256 of the 64-byte concatenation
        auto sp = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ps.data()), ps.size());
        cur = Hash(sp);
    }
    return cur;
}

// ============================================================================
// compute_gentx_before_refhash()
//
// Computes the constant ending bytes that appear after the coinbase outputs
// and before the ref_hash in the serialised coinbase transaction.
//
// Legacy: networks/network.cpp  "init gentx_before_refhash"
// Formula: VarStr(DONATION_SCRIPT) + int64(0) + VarStr(0x6a28 + int256(0) + int64(0))[:3]
// ============================================================================
inline std::vector<unsigned char> compute_gentx_before_refhash(int64_t share_version)
{
    std::vector<unsigned char> result;

    // 1. VarStr(DONATION_SCRIPT)
    auto donation_script = PoolConfig::get_donation_script(share_version);
    {
        PackStream s;
        BaseScript bs;
        bs.m_data = donation_script;
        s << bs;
        auto* p = reinterpret_cast<const unsigned char*>(s.data());
        result.insert(result.end(), p, p + s.size());
    }

    // 2. int64(0)
    {
        uint64_t zero64 = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero64);
        result.insert(result.end(), p, p + 8);
    }

    // 3. VarStr(0x6a 0x28 + int256(0) + int64(0)) — but only the first 3 bytes
    {
        PackStream inner;
        // raw bytes: OP_RETURN (0x6a) + PUSH_40 (0x28)
        unsigned char prefix[2] = {0x6a, 0x28};
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(prefix), 2));
        // 32 zero bytes (uint256(0))
        uint256 zero256;
        inner << zero256;
        // 8 zero bytes (uint64(0))
        uint64_t zero64 = 0;
        inner.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&zero64), 8));

        // Pack as VarStr
        PackStream outer;
        BaseScript bs;
        bs.m_data.resize(inner.size());
        std::memcpy(bs.m_data.data(), inner.data(), inner.size());
        outer << bs;

        // Take only the first 3 bytes
        auto* p = reinterpret_cast<const unsigned char*>(outer.data());
        result.insert(result.end(), p, p + std::min<size_t>(3, outer.size()));
    }

    return result;
}

// ============================================================================
// compute_ref_hash_for_work()
//
// Computes the p2pool ref_hash for a set of share fields.  Used at Stratum
// work generation time to build the OP_RETURN commitment per connection.
//
// Parameters mirror the share fields that feed into the ref_stream.
// Returns (ref_hash, last_txout_nonce).
// ============================================================================
struct RefHashParams {
    uint256 prev_share;
    std::vector<unsigned char> coinbase_scriptSig;
    uint32_t share_nonce{0};
    uint160  pubkey_hash;
    uint8_t  pubkey_type{0};
    uint64_t subsidy{0};
    uint16_t donation{50};
    uint8_t  stale_info{0};
    uint64_t desired_version{36};
    bool     has_segwit{false};
    SegwitData segwit_data;
    std::vector<MergedAddressEntry> merged_addresses;
    uint256  far_share_hash;
    uint32_t max_bits{0};
    uint32_t bits{0};
    uint32_t timestamp{0};
    uint32_t absheight{0};
    uint128  abswork;
    BaseScript merged_coinbase_info;
    uint256  merged_payout_hash;
    BaseScript message_data;              // V36 PossiblyNoneType(b'', VarStrType())
};

inline std::pair<uint256, uint64_t> compute_ref_hash_for_work(const RefHashParams& p)
{
    PackStream ref_stream;

    // IDENTIFIER
    {
        auto hex = PoolConfig::identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }

    ref_stream << p.prev_share;

    // coinbase as VarStr
    {
        BaseScript bs;
        bs.m_data = p.coinbase_scriptSig;
        ref_stream << bs;
    }

    ref_stream << p.share_nonce;
    ref_stream << p.pubkey_hash;
    ref_stream << p.pubkey_type;
    ::Serialize(ref_stream, VarInt(p.subsidy));
    ref_stream << p.donation;
    ref_stream << p.stale_info;
    ::Serialize(ref_stream, VarInt(p.desired_version));

    if (p.has_segwit)
        ref_stream << p.segwit_data;

    ref_stream << p.merged_addresses;
    ref_stream << p.far_share_hash;
    ref_stream << p.max_bits;
    ref_stream << p.bits;
    ref_stream << p.timestamp;
    ref_stream << p.absheight;
    ::Serialize(ref_stream, Using<AbsworkV36Format>(p.abswork));
    ref_stream << p.merged_coinbase_info;
    ref_stream << p.merged_payout_hash;

    // V36 ref_type includes message_data as PossiblyNoneType(b'', VarStrType())
    // When empty, BaseScript serialises as varint(0) = 0x00, matching Python's behavior.
    ref_stream << p.message_data;

    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 ref_hash = Hash(ref_span);

    // Generate a random-ish last_txout_nonce
    uint64_t nonce = static_cast<uint64_t>(std::time(nullptr)) ^
                     (static_cast<uint64_t>(p.timestamp) << 32) ^
                     (static_cast<uint64_t>(p.absheight) << 16);

    return {ref_hash, nonce};
}

// ============================================================================
// share_init_verify()
//
// Performs the init()-phase verification of a share:
//   1. Basic field validation (coinbase size, merkle branch lengths)
//   2. Compute hash_link_data from ref serialisation
//   3. check_hash_link → gentx_hash
//   4. check_merkle_link → merkle_root
//   5. Build full block header
//   6. Compute hash (double-SHA256 of header)
//   7. Verify pow_hash <= target
//
// Returns the share hash (double-SHA256 of the reconstructed header).
// Throws on any validation failure.
//
// NOTE: The full GenerateShareTransaction reconstruction from check() is
// deferred to a later PR (P2.5).  This function covers the PoW + hash-link
// verification path from legacy Share::init().
// ============================================================================
template <typename ShareT>
uint256 share_init_verify(const ShareT& share, bool check_pow = true)
{
    // --- Basic validation ---
    if (share.m_coinbase.size() < 2 || share.m_coinbase.size() > 100)
        throw std::invalid_argument("bad coinbase size");

    if (share.m_merkle_link.m_branch.size() > 16)
        throw std::invalid_argument("merkle branch too long");

    constexpr int64_t ver = ShareT::version;

    if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
            {
                if (share.m_segwit_data->m_txid_merkle_link.m_branch.size() > 16)
                    throw std::invalid_argument("segwit txid merkle branch too long");
            }
        }
    }

    // --- Compute ref_hash ---
    // RefType serialisation: IDENTIFIER + share_info fields + segwit_data
    // Then hash256 it, then check_merkle_link with ref_merkle_link
    //
    // For now we serialise the minimal fields the same way the legacy code
    // does (share_data + share_info + optional segwit_data) via a PackStream.
    PackStream ref_stream;

    // IDENTIFIER bytes (8 bytes from IDENTIFIER_HEX)
    {
        auto hex = PoolConfig::identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }

    // share_info serialisation — we re-serialise the share's share_info fields
    // through the same Formatter path that was used to decode them.
    // For ref_hash we need: share_data + share_info fields + segwit_data
    // We serialise the relevant fields into the ref_stream.
    {
        // prev_hash
        ref_stream << share.m_prev_hash;
        // coinbase
        ref_stream << share.m_coinbase;
        // nonce (uint32_t LE)
        ref_stream << share.m_nonce;

        // address or pubkey_hash — V34/V35 use m_address (VarStr),
        // V36+ uses m_pubkey_hash (uint160) + m_pubkey_type (uint8_t),
        // pre-V34 uses m_pubkey_hash only.
        if constexpr (requires { share.m_address; })
            ref_stream << share.m_address;
        else if constexpr (requires { share.m_pubkey_type; })
        {
            ref_stream << share.m_pubkey_hash;
            ref_stream << share.m_pubkey_type;
        }
        else
            ref_stream << share.m_pubkey_hash;

        // subsidy: VarInt for V36+, raw uint64_t LE for older
        if constexpr (ver >= 36)
            ::Serialize(ref_stream, VarInt(share.m_subsidy));
        else
            ref_stream << share.m_subsidy;

        ref_stream << share.m_donation;
        // stale_info as EnumType<IntType<8>> — single byte
        {
            uint8_t si = static_cast<uint8_t>(share.m_stale_info);
            ref_stream << si;
        }
        // desired_version as VarInt
        {
            uint64_t dv = share.m_desired_version;
            ::Serialize(ref_stream, VarInt(dv));
        }

        // segwit_data (optional)
        if constexpr (requires { share.m_segwit_data; })
        {
            if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
            {
                if (share.m_segwit_data.has_value())
                    ref_stream << share.m_segwit_data.value();
            }
        }

        // merged_addresses (V36+)
        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_merged_addresses; })
                ref_stream << share.m_merged_addresses;
        }

        // tx info (pre-v34)
        if constexpr (ver < 34)
        {
            if constexpr (requires { share.m_tx_info; })
                ref_stream << share.m_tx_info;
        }

        // far_share_hash, max_bits, bits, timestamp, absheight
        ref_stream << share.m_far_share_hash;
        ref_stream << share.m_max_bits;
        ref_stream << share.m_bits;
        ref_stream << share.m_timestamp;
        ref_stream << share.m_absheight;

        // abswork: AbsworkV36Format for V36+, raw uint128 LE for older
        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_abswork; })
                ::Serialize(ref_stream, Using<AbsworkV36Format>(share.m_abswork));
        }
        else
        {
            ref_stream << share.m_abswork;
        }

        // V36+ merged mining commitment fields
        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_merged_coinbase_info; })
                ref_stream << share.m_merged_coinbase_info;
            if constexpr (requires { share.m_merged_payout_hash; })
                ref_stream << share.m_merged_payout_hash;
        }
    }

    // V36 ref_type includes message_data as PossiblyNoneType(b'', VarStrType())
    // When m_message_data is empty, BaseScript serialises as varint(0) = 0x00.
    if constexpr (ver >= 36)
    {
        if constexpr (requires { share.m_message_data; })
            ref_stream << share.m_message_data;
    }

    // hash256 of the ref_type serialisation
    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 hash_ref = Hash(ref_span);

    // check_merkle_link with ref_merkle_link
    uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

    // --- Build hash_link_data ---
    // hash_link_data = ref_hash bytes + pack(last_txout_nonce, LE64) + pack(0, LE32)
    std::vector<unsigned char> hash_link_data;
    hash_link_data.insert(hash_link_data.end(), ref_hash.data(), ref_hash.data() + 32);
    {
        // last_txout_nonce as little-endian uint64
        uint64_t nonce = share.m_last_txout_nonce;
        auto* p = reinterpret_cast<const unsigned char*>(&nonce);
        hash_link_data.insert(hash_link_data.end(), p, p + 8);
    }
    {
        // trailing zero uint32
        uint32_t zero = 0;
        auto* p = reinterpret_cast<const unsigned char*>(&zero);
        hash_link_data.insert(hash_link_data.end(), p, p + 4);
    }

    auto gentx_before_refhash = compute_gentx_before_refhash(ver);

    // --- check_hash_link → gentx_hash ---
    uint256 gentx_hash = check_hash_link(share.m_hash_link, hash_link_data, gentx_before_refhash);

    // --- Merkle root ---
    // For segwit-activated shares, use segwit_data.txid_merkle_link; otherwise merkle_link
    uint256 merkle_root;
    if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
                merkle_root = check_merkle_link(gentx_hash, share.m_segwit_data->m_txid_merkle_link);
            else
                merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);
        }
        else
        {
            merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);
        }
    }
    else
    {
        merkle_root = check_merkle_link(gentx_hash, share.m_merkle_link);
    }

    // --- Reconstruct full block header and compute hash ---
    // BlockHeaderType: version(int32) + previous_block + merkle_root + timestamp + bits + nonce
    // Note: the full block header uses fixed 4-byte version (not VarInt like SmallBlockHeaderType)
    PackStream header_stream;
    {
        uint32_t hdr_version = static_cast<uint32_t>(share.m_min_header.m_version);
        header_stream << hdr_version;
    }
    header_stream << share.m_min_header.m_previous_block;
    header_stream << merkle_root;
    header_stream << share.m_min_header.m_timestamp;
    header_stream << share.m_min_header.m_bits;
    header_stream << share.m_min_header.m_nonce;

    // hash = double-SHA256 of the header (the share's identity)
    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());
    uint256 share_hash = Hash(hdr_span);

    // --- PoW check (scrypt) ---
    // For Litecoin the POW_FUNC is scrypt(1024,1,1,256).
    // Blocks are identified by SHA256d, but PoW validity uses scrypt hash.
    if (check_pow)
    {
        uint256 target = chain::bits_to_target(share.m_bits);
        if (target.IsNull())
            throw std::invalid_argument("share target is zero");

        // Compute the scrypt hash of the 80-byte block header
        char pow_hash_bytes[32];
        scrypt_1024_1_1_256(reinterpret_cast<const char*>(header_stream.data()),
                            pow_hash_bytes);
        uint256 pow_hash;
        memcpy(pow_hash.begin(), pow_hash_bytes, 32);

        if (pow_hash > target)
        {
            LOG_WARNING << "PoW FAIL: bits=" << share.m_bits
                        << " target=" << target.GetHex().substr(0,32)
                        << " pow_hash=" << pow_hash.GetHex().substr(0,32)
                        << " header_size=" << header_stream.size();
            throw std::invalid_argument("share PoW hash does not meet target");
        }
    }

    return share_hash;
}

// ============================================================================
// Helper: convert pubkey_hash + type to full scriptPubKey
// ============================================================================
inline std::vector<unsigned char> pubkey_hash_to_script(const uint160& hash, uint8_t type = 0)
{
    std::vector<unsigned char> script;
    auto h = hash.GetChars();
    switch (type)
    {
    case 1: // P2WPKH: OP_0 <20>
        script.reserve(22);
        script.push_back(0x00);
        script.push_back(0x14);
        script.insert(script.end(), h.begin(), h.end());
        break;
    case 2: // P2SH: OP_HASH160 <20> OP_EQUAL
        script.reserve(23);
        script.push_back(0xa9);
        script.push_back(0x14);
        script.insert(script.end(), h.begin(), h.end());
        script.push_back(0x87);
        break;
    default: // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
        script.reserve(25);
        script.push_back(0x76);
        script.push_back(0xa9);
        script.push_back(0x14);
        script.insert(script.end(), h.begin(), h.end());
        script.push_back(0x88);
        script.push_back(0xac);
        break;
    }
    return script;
}

// ============================================================================
// Helper: extract full scriptPubKey from a share variant
// ============================================================================
inline std::vector<unsigned char> get_share_script(const auto* obj)
{
    if constexpr (requires { obj->m_pubkey_type; })
        return pubkey_hash_to_script(obj->m_pubkey_hash, obj->m_pubkey_type);
    else if constexpr (requires { obj->m_address; })
        return obj->m_address.m_data;
    else
        return pubkey_hash_to_script(obj->m_pubkey_hash, 0);
}

// ============================================================================
// generate_share_transaction()
//
// Reconstructs the expected coinbase transaction from a share's fields and
// the PPLNS weights computed from the share chain.  Returns the expected
// gentx txid (double-SHA256 of the non-witness serialised transaction).
//
// This is the C++ port of p2pool v36's generate_transaction() / check().
//
// The coinbase structure is:
//   tx_ins:  [ { prev_output: 0...0:ffffffff, script: coinbase } ]
//   tx_outs: [ segwit_commitment?,
//              ...pplns_payout_outputs...,
//              donation_output,
//              op_return_commitment ]
//   lock_time: 0
//
// Reference: frstrtr/p2pool-merged-v36  p2pool/data.py  generate_transaction()
// ============================================================================
template <typename ShareT, typename TrackerT>
uint256 generate_share_transaction(const ShareT& share, TrackerT& tracker)
{
    constexpr int64_t ver = ShareT::version;
    const uint64_t subsidy = share.m_subsidy;
    const uint16_t donation = share.m_donation;

    // --- 1. Compute PPLNS weights with full scriptPubKey keys ---
    // Walk from share's prev_hash (parent) backward through the chain.
    // This matches the Python: weights are computed relative to the share's parent.

    auto prev_hash = share.m_prev_hash;
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;

    if (!prev_hash.IsNull() && tracker.chain.contains(prev_hash))
    {
        auto chain_len = std::min(
            tracker.chain.get_height(prev_hash),
            static_cast<int32_t>(PoolConfig::real_chain_length()));

        // block_target from block header bits (matches Python: self.header['bits'].target)
        auto block_target = chain::bits_to_target(share.m_min_header.m_bits);
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * PoolConfig::SPREAD * 65535;

        // V36: use exponential depth-decay (matching Python's get_decayed_cumulative_weights)
        if constexpr (ver >= 36) {
            auto result = tracker.get_v36_decayed_cumulative_weights(prev_hash, chain_len, max_weight);
            weights = std::move(result.weights);
            total_weight = result.total_weight;
            total_donation_weight = result.total_donation_weight;
        } else {
            // Pre-V36: standard cumulative weights without decay
            auto walk_count = static_cast<size_t>(chain_len);
            auto walk_view = tracker.chain.get_chain(prev_hash, walk_count);

            for (auto& [hash, data] : walk_view)
            {
                uint288 share_att;
                uint32_t share_don = 0;
                std::vector<unsigned char> script;

                data.share.invoke([&](auto* obj) {
                    auto target = chain::bits_to_target(obj->m_bits);
                    share_att = chain::target_to_average_attempts(target);
                    share_don = obj->m_donation;
                    script = get_share_script(obj);
                });

                uint288 share_total = share_att * 65535;
                uint288 share_don_w = share_att * share_don;

                if (total_weight + share_total > max_weight)
                {
                    auto remaining = max_weight - total_weight;
                    auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_don);

                    uint288 partial_addr;
                    if (!share_total.IsNull())
                        partial_addr = remaining / 65535 * share_addr_weight / (share_total / 65535);

                    if (weights.contains(script))
                        weights[script] += partial_addr;
                    else
                        weights[script] = partial_addr;

                    uint288 partial_donation;
                    if (!share_total.IsNull())
                        partial_donation = remaining / 65535 * share_don_w / (share_total / 65535);

                    total_donation_weight += partial_donation;
                    total_weight = max_weight;
                    break;
                }

                auto share_addr_weight = share_att * static_cast<uint32_t>(65535 - share_don);
                if (weights.contains(script))
                    weights[script] += share_addr_weight;
                else
                    weights[script] = share_addr_weight;

                total_weight += share_total;
                total_donation_weight += share_don_w;
            }
        }
    }

    // --- 2. Convert weights to exact integer payout amounts ---
    // Python formula:
    //   Pre-V36: amounts[script] = subsidy * (199 * weight) / (200 * total_weight)
    //            amounts[finder] += subsidy // 200
    //   V36:     amounts[script] = subsidy * weight / total_weight
    //   donation = subsidy - sum(amounts)

    std::map<std::vector<unsigned char>, uint64_t> amounts;

    if (!total_weight.IsNull())
    {
        for (auto& [script, weight] : weights)
        {
            uint64_t amount;
            if constexpr (ver >= 36)
            {
                // V36: amounts[script] = subsidy * weight / total_weight
                uint288 num = uint288(subsidy) * weight;
                amount = (num / total_weight).GetLow64();
            }
            else
            {
                // Pre-V36: amounts[script] = subsidy * (199 * weight) / (200 * total_weight)
                uint288 num = uint288(subsidy) * (weight * 199);
                uint288 den = total_weight * 200;
                amount = (num / den).GetLow64();
            }
            if (amount > 0)
                amounts[script] = amount;
        }
    }

    // Pre-V36: add 0.5% finder fee to share creator
    if constexpr (ver < 36)
    {
        auto finder_script = get_share_script(&share);
        amounts[finder_script] += subsidy / 200;
    }

    // Donation output = subsidy minus sum of all payout amounts
    uint64_t sum_amounts = 0;
    for (auto& [s, a] : amounts)
        sum_amounts += a;
    uint64_t donation_amount = (subsidy > sum_amounts) ? (subsidy - sum_amounts) : 0;

    // V36 consensus: donation output must carry >= 1 satoshi (a60f7f7f)
    if constexpr (ver >= 36) {
        if (donation_amount < 1 && subsidy > 0 && !amounts.empty()) {
            // Deduct 1 sat from the largest miner payout
            auto largest = std::max_element(amounts.begin(), amounts.end(),
                [](const auto& a, const auto& b) { return a.second < b.second; });
            if (largest != amounts.end() && largest->second > 0) {
                largest->second -= 1;
                sum_amounts -= 1;
                donation_amount = subsidy - sum_amounts;
            }
        }
    }

    // --- 3. Build sorted output list ---
    // Python: sorted(dests, key=lambda a: (amounts[a], a))[-4000:]
    // = ascending by (amount, script), keep last 4000 (highest amounts)
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payout_outputs(
        amounts.begin(), amounts.end());
    std::sort(payout_outputs.begin(), payout_outputs.end(),
        [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second < b.second; // asc by amount
            return a.first < b.first; // asc by script for tie-breaking
        });

    // Keep last MAX_OUTPUTS (highest amounts), matching Python's [-4000:]
    constexpr size_t MAX_OUTPUTS = 4000;
    if (payout_outputs.size() > MAX_OUTPUTS)
        payout_outputs.erase(payout_outputs.begin(), payout_outputs.end() - MAX_OUTPUTS);

    // --- 4. Serialise the coinbase transaction ---
    // Non-witness serialization (for txid computation):
    //   version(4) + vin_count(varint) + vin + vout_count(varint) + vouts + locktime(4)
    PackStream tx;

    // tx version = 1
    uint32_t tx_version = 1;
    tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&tx_version), 4));

    // vin count = 1
    {
        unsigned char one = 1;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&one), 1));
    }

    // vin[0]: prev_output = 0...0:ffffffff, script = coinbase, sequence = 0
    {
        // prev_hash (32 zero bytes)
        uint256 zero_hash;
        tx << zero_hash;
        // prev_index (0xffffffff)
        uint32_t prev_idx = 0xffffffff;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&prev_idx), 4));
        // script (VarStr)
        tx << share.m_coinbase;
        // sequence (0xffffffff — standard coinbase sequence, matches Python)
        uint32_t seq = 0xffffffff;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&seq), 4));
    }

    // Count total outputs
    size_t n_outs = payout_outputs.size() + 1 /* donation */ + 1 /* OP_RETURN commitment */;
    // Segwit commitment output (if applicable)
    bool has_segwit = false;
    if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
            {
                has_segwit = true;
                n_outs += 1;
            }
        }
    }

    // vout count (varint — for < 253 outputs, it's a single byte)
    if (n_outs < 253)
    {
        uint8_t cnt = static_cast<uint8_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 1));
    }
    else
    {
        uint8_t marker = 0xfd;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&marker), 1));
        uint16_t cnt = static_cast<uint16_t>(n_outs);
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 2));
    }

    // Helper to write a single tx_out: value(8LE) + script(VarStr)
    auto write_txout = [&](uint64_t value, const std::vector<unsigned char>& script) {
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), 8));
        BaseScript bs;
        bs.m_data = script;
        tx << bs;
    };

    // Segwit commitment output (value=0, script=OP_RETURN + witness_commitment)
    if (has_segwit)
    {
        if constexpr (requires { share.m_segwit_data; })
        {
            if (share.m_segwit_data.has_value())
            {
                // witness commitment: 0x6a24aa21a9ed + SHA256d(wtxid_merkle_root || '[P2Pool]'*4)
                std::vector<unsigned char> wscript;
                wscript.push_back(0x6a); // OP_RETURN
                wscript.push_back(0x24); // PUSH 36
                wscript.push_back(0xaa);
                wscript.push_back(0x21);
                wscript.push_back(0xa9);
                wscript.push_back(0xed);
                auto& sd = share.m_segwit_data.value();
                uint256 commitment = compute_p2pool_witness_commitment(sd.m_wtxid_merkle_root);
                auto commitment_bytes = commitment.GetChars();
                wscript.insert(wscript.end(), commitment_bytes.begin(), commitment_bytes.end());
                write_txout(0, wscript);
            }
        }
    }

    // PPLNS payout outputs
    for (auto& [script, amount] : payout_outputs)
        write_txout(amount, script);

    // Donation output
    auto donation_script = PoolConfig::get_donation_script(ver);
    write_txout(donation_amount, donation_script);

    // OP_RETURN commitment: value=0, script = 0x6a28 + ref_hash(32) + last_txout_nonce(8)
    {
        // We need the ref_hash — recompute it from the share the same way share_init_verify does
        PackStream ref_stream;

        // IDENTIFIER bytes
        {
            auto hex = PoolConfig::identifier_hex();
            for (size_t i = 0; i + 1 < hex.size(); i += 2)
            {
                unsigned char byte = static_cast<unsigned char>(
                    std::stoul(hex.substr(i, 2), nullptr, 16));
                ref_stream.write(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(&byte), 1));
            }
        }

        // share_info fields (same as share_init_verify)
        {
            ref_stream << share.m_prev_hash;
            ref_stream << share.m_coinbase;
            ref_stream << share.m_nonce;

            if constexpr (requires { share.m_address; })
                ref_stream << share.m_address;
            else if constexpr (requires { share.m_pubkey_type; })
            {
                ref_stream << share.m_pubkey_hash;
                ref_stream << share.m_pubkey_type;
            }
            else
                ref_stream << share.m_pubkey_hash;

            if constexpr (ver >= 36)
                ::Serialize(ref_stream, VarInt(share.m_subsidy));
            else
                ref_stream << share.m_subsidy;

            ref_stream << share.m_donation;
            {
                uint8_t si = static_cast<uint8_t>(share.m_stale_info);
                ref_stream << si;
            }
            ::Serialize(ref_stream, VarInt(share.m_desired_version));

            if constexpr (requires { share.m_segwit_data; })
            {
                if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
                {
                    if (share.m_segwit_data.has_value())
                        ref_stream << share.m_segwit_data.value();
                }
            }

            if constexpr (ver >= 36)
            {
                if constexpr (requires { share.m_merged_addresses; })
                    ref_stream << share.m_merged_addresses;
            }

            if constexpr (ver < 34)
            {
                if constexpr (requires { share.m_tx_info; })
                    ref_stream << share.m_tx_info;
            }

            ref_stream << share.m_far_share_hash;
            ref_stream << share.m_max_bits;
            ref_stream << share.m_bits;
            ref_stream << share.m_timestamp;
            ref_stream << share.m_absheight;

            if constexpr (ver >= 36)
            {
                if constexpr (requires { share.m_abswork; })
                    ::Serialize(ref_stream, Using<AbsworkV36Format>(share.m_abswork));
            }
            else
            {
                ref_stream << share.m_abswork;
            }

            if constexpr (ver >= 36)
            {
                if constexpr (requires { share.m_merged_coinbase_info; })
                    ref_stream << share.m_merged_coinbase_info;
                if constexpr (requires { share.m_merged_payout_hash; })
                    ref_stream << share.m_merged_payout_hash;
            }
        }

        // V36 ref_type includes message_data (must match verify_share)
        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_message_data; })
                ref_stream << share.m_message_data;
        }

        auto ref_span = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
        uint256 hash_ref = Hash(ref_span);
        uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

        // Build OP_RETURN script: 0x6a 0x28 + ref_hash(32) + last_txout_nonce(8)
        std::vector<unsigned char> op_return_script;
        op_return_script.push_back(0x6a); // OP_RETURN
        op_return_script.push_back(0x28); // PUSH 40 bytes
        op_return_script.insert(op_return_script.end(), ref_hash.data(), ref_hash.data() + 32);
        {
            uint64_t nonce = share.m_last_txout_nonce;
            auto* p = reinterpret_cast<const unsigned char*>(&nonce);
            op_return_script.insert(op_return_script.end(), p, p + 8);
        }
        write_txout(0, op_return_script);
    }

    // lock_time = 0
    {
        uint32_t locktime = 0;
        tx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&locktime), 4));
    }

    // --- 5. Compute txid (double-SHA256 of non-witness serialization) ---
    auto tx_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(tx.data()), tx.size());
    return Hash(tx_span);
}

// ============================================================================
// share_check()
//
// The check()-phase verification after init:
//   1. Timestamp not too far in the future
//   2. Version counting (stub — version upgrade enforcement)
//   3. Transaction hash resolution (for pre-v34 shares)
//   4. GenerateShareTransaction reconstruction & comparison
//
// Returns true if the share passes all checks.
// Throws on validation failure.
// ============================================================================
template <typename ShareT, typename TrackerT>
bool share_check(const ShareT& share,
                 const uint256& share_hash,
                 const uint256& gentx_hash,
                 TrackerT& tracker)
{
    // 1. Timestamp check — must not be more than 600s in the future
    auto now = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    if (share.m_timestamp > now + 600)
        throw std::invalid_argument("share timestamp is too far in the future");

    // 2. Version counting — AutoRatchet upgrade enforcement
    // If 95% of recent shares desire a higher version, this share's version
    // is considered obsolete and must be rejected.
    {
        auto lookbehind = static_cast<int32_t>(PoolConfig::chain_length());
        auto height = tracker.chain.get_height(share_hash);
        if (height >= lookbehind)
        {
            if (tracker.should_punish_version(share_hash, share.version, lookbehind))
                throw std::invalid_argument("share version too old — newer version has 95%+ activation");
        }
    }

    // 3. GenerateShareTransaction reconstruction & comparison
    // Rebuild the expected coinbase from PPLNS weights and share fields,
    // then verify its txid matches the gentx_hash from share_init_verify().
    if (!share.m_prev_hash.IsNull() && tracker.chain.contains(share.m_prev_hash))
    {
        uint256 expected_gentx = generate_share_transaction(share, tracker);
        if (expected_gentx != gentx_hash)
        {
            LOG_WARNING << "GENTX-MISMATCH detail:"
                        << " share=" << share_hash.ToString().substr(0,16)
                        << " ver=" << share.version
                        << " subsidy=" << share.m_subsidy
                        << " donation=" << share.m_donation
                        << " prev=" << share.m_prev_hash.ToString().substr(0,16);
            LOG_WARNING << "  expected_gentx=" << expected_gentx.ToString().substr(0,32)
                        << " actual_gentx=" << gentx_hash.ToString().substr(0,32);
            
            // Log PPLNS chain depth available
            auto chain_len = std::min(
                tracker.chain.get_height(share.m_prev_hash),
                static_cast<int32_t>(PoolConfig::real_chain_length()));
            LOG_WARNING << "  PPLNS chain_len=" << chain_len
                        << " prev_height=" << tracker.chain.get_height(share.m_prev_hash)
                        << " real_chain_length=" << PoolConfig::real_chain_length();
            
            throw std::invalid_argument("GenerateShareTransaction mismatch — coinbase does not match PPLNS payouts");
        }
    }

    return true;
}

// ============================================================================
// verify_share()
//
// Combined entry point: runs both init-phase and check-phase verification.
// Returns the computed share hash.
// ============================================================================
template <typename ShareT, typename TrackerT>
uint256 verify_share(const ShareT& share, TrackerT& tracker)
{
    // share_init_verify computes gentx_hash along the way — we need it
    // for the GenerateShareTransaction comparison in share_check.
    // Re-extract gentx_hash by running the hash-link path.
    uint256 hash = share_init_verify(share);

    // Re-derive gentx_hash for the check phase
    constexpr int64_t ver = ShareT::version;
    auto gentx_before_refhash = compute_gentx_before_refhash(ver);

    // Rebuild ref_hash + hash_link_data the same way init does
    PackStream ref_stream;
    {
        auto hex = PoolConfig::identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2)
        {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }
    {
        ref_stream << share.m_prev_hash;
        ref_stream << share.m_coinbase;
        ref_stream << share.m_nonce;

        if constexpr (requires { share.m_address; })
            ref_stream << share.m_address;
        else if constexpr (requires { share.m_pubkey_type; })
        {
            ref_stream << share.m_pubkey_hash;
            ref_stream << share.m_pubkey_type;
        }
        else
            ref_stream << share.m_pubkey_hash;

        if constexpr (ver >= 36)
            ::Serialize(ref_stream, VarInt(share.m_subsidy));
        else
            ref_stream << share.m_subsidy;

        ref_stream << share.m_donation;
        {
            uint8_t si = static_cast<uint8_t>(share.m_stale_info);
            ref_stream << si;
        }
        ::Serialize(ref_stream, VarInt(share.m_desired_version));

        if constexpr (requires { share.m_segwit_data; })
        {
            if constexpr (ver >= ltc::SEGWIT_ACTIVATION_VERSION)
            {
                if (share.m_segwit_data.has_value())
                    ref_stream << share.m_segwit_data.value();
            }
        }

        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_merged_addresses; })
                ref_stream << share.m_merged_addresses;
        }

        if constexpr (ver < 34)
        {
            if constexpr (requires { share.m_tx_info; })
                ref_stream << share.m_tx_info;
        }

        ref_stream << share.m_far_share_hash;
        ref_stream << share.m_max_bits;
        ref_stream << share.m_bits;
        ref_stream << share.m_timestamp;
        ref_stream << share.m_absheight;

        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_abswork; })
                ::Serialize(ref_stream, Using<AbsworkV36Format>(share.m_abswork));
        }
        else
        {
            ref_stream << share.m_abswork;
        }

        if constexpr (ver >= 36)
        {
            if constexpr (requires { share.m_merged_coinbase_info; })
                ref_stream << share.m_merged_coinbase_info;
            if constexpr (requires { share.m_merged_payout_hash; })
                ref_stream << share.m_merged_payout_hash;
        }
    }

    // V36 ref_type includes message_data
    if constexpr (ver >= 36)
    {
        if constexpr (requires { share.m_message_data; })
            ref_stream << share.m_message_data;
    }

    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 hash_ref = Hash(ref_span);

    std::vector<unsigned char> hash_link_data;
    {
        uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);
        hash_link_data.insert(hash_link_data.end(), ref_hash.data(), ref_hash.data() + 32);
        uint64_t nonce = share.m_last_txout_nonce;
        auto* p = reinterpret_cast<const unsigned char*>(&nonce);
        hash_link_data.insert(hash_link_data.end(), p, p + 8);
        uint32_t zero = 0;
        auto* z = reinterpret_cast<const unsigned char*>(&zero);
        hash_link_data.insert(hash_link_data.end(), z, z + 4);
    }

    uint256 gentx_hash = check_hash_link(share.m_hash_link, hash_link_data, gentx_before_refhash);

    // V36+: Validate message_data (reject shares with invalid encrypted messages)
    if constexpr (ver >= 36)
    {
        if constexpr (requires { share.m_message_data; })
        {
            auto err = validate_message_data(share.m_message_data.m_data);
            if (!err.empty())
                throw std::invalid_argument("share " + err);
        }
    }

    share_check(share, hash, gentx_hash, tracker);
    return hash;
}

// ============================================================================
// create_local_share()
//
// Constructs a MergedMiningShare (V36) from locally-generated block data and
// adds it to the share tracker.  Returns the share hash (block header double-
// SHA256).
//
// Parameters:
//   tracker     — the ShareTracker to insert the new share into
//   min_header  — parsed SmallBlockHeaderType from the found block
//   coinbase    — the p2pool coinbase scriptSig (BIP34 height + pool marker)
//   subsidy     — block reward (coinbasevalue)
//   prev_share  — previous best share hash from the tracker
//   merkle_branches — Stratum merkle branches (coinbase txid → merkle root)
//   payout_script   — finder's scriptPubKey
//   donation        — donation bps (e.g. 50 = 0.5%)
//   merged_addrs    — optional merged mining addresses
//
// This builds the p2pool coinbase in the same format as
// generate_share_transaction() and computes the hash_link so remote peers
// can verify the share.
// ============================================================================
template <typename TrackerT>
uint256 create_local_share(
    TrackerT& tracker,
    const coin::SmallBlockHeaderType& min_header,
    const BaseScript& coinbase,
    uint64_t subsidy,
    const uint256& prev_share,
    const std::vector<uint256>& merkle_branches,
    const std::vector<unsigned char>& payout_script,
    uint16_t donation = 50,
    const std::vector<MergedAddressEntry>& merged_addrs = {},
    StaleInfo stale_info = StaleInfo::none,
    bool segwit_active = false,
    const std::string& witness_commitment_hex = {},
    const std::vector<unsigned char>& message_data = {},
    const std::vector<unsigned char>& actual_coinbase_bytes = {},
    const uint256& witness_root = uint256(),
    uint32_t override_max_bits = 0,
    uint32_t override_bits = 0)
{
    MergedMiningShare share;
    share.m_min_header = min_header;
    share.m_coinbase   = coinbase;
    share.m_subsidy    = subsidy;
    share.m_prev_hash  = prev_share;
    share.m_donation   = donation;
    share.m_stale_info = stale_info;
    share.m_desired_version = 36;

    // Timestamp: clip to at least previous_share.timestamp + 1 (matches Python)
    share.m_timestamp  = min_header.m_timestamp;
    if (!prev_share.IsNull() && tracker.chain.contains(prev_share)) {
        uint32_t prev_ts = 0;
        tracker.chain.get(prev_share).share.invoke([&](auto* prev) {
            prev_ts = prev->m_timestamp;
        });
        if (share.m_timestamp <= prev_ts)
            share.m_timestamp = prev_ts + 1;
    }

    // Compute pool-level share target AFTER timestamp clipping (matches ref_hash_fn).
    auto desired_target = chain::bits_to_target(min_header.m_bits);
    auto [share_max_bits, share_bits] = tracker.compute_share_target(
        prev_share, share.m_timestamp, desired_target);
    share.m_max_bits   = share_max_bits;
    share.m_bits       = share_bits;

    share.m_nonce      = 0; // share commitment nonce (not block nonce)
    share.m_merged_addresses = merged_addrs;

    // Embed encrypted message_data (from create_message_data()) if provided
    if (!message_data.empty())
        share.m_message_data.m_data = message_data;

    // Compute merged_payout_hash: deterministic hash of V36-only PPLNS
    // weight distribution so peers can verify merged mining payouts.
    if (!prev_share.IsNull() && tracker.chain.contains(prev_share))
    {
        auto block_target = chain::bits_to_target(min_header.m_bits);
        share.m_merged_payout_hash = tracker.compute_merged_payout_hash(
            prev_share, block_target);
    }

    // Payout identity
    if (payout_script.size() >= 20) {
        // Extract hash160 from P2PKH script: 76 a9 14 <hash160> 88 ac
        if (payout_script.size() == 25 &&
            payout_script[0] == 0x76 && payout_script[1] == 0xa9 &&
            payout_script[2] == 0x14 && payout_script[23] == 0x88 &&
            payout_script[24] == 0xac) {
            std::memcpy(share.m_pubkey_hash.data(), payout_script.data() + 3, 20);
            share.m_pubkey_type = 0; // P2PKH
        } else {
            // Store first 20 bytes as hash
            std::memcpy(share.m_pubkey_hash.data(), payout_script.data(), 20);
            share.m_pubkey_type = 1; // raw/other
        }
    }

    // Chain position: absheight and abswork from previous share
    if (!prev_share.IsNull() && tracker.chain.contains(prev_share)) {
        auto [prev_height, last] = tracker.chain.get_height_and_last(prev_share);
        tracker.chain.get(prev_share).share.invoke([&](auto* prev) {
            share.m_absheight = prev->m_absheight + 1;
        });

        // abswork: prev_abswork + target_to_average_attempts(THIS share's bits)
        // Python: abswork = (prev.abswork + target_to_average_attempts(bits.target)) % 2^128
        {
            auto current_attempts = chain::target_to_average_attempts(
                chain::bits_to_target(share.m_bits));
            uint128 prev_abswork;
            tracker.chain.get(prev_share).share.invoke([&](auto* prev) {
                prev_abswork = prev->m_abswork;
            });
            share.m_abswork = prev_abswork + uint128(current_attempts.GetLow64());
        }

        // far_share_hash: 99th ancestor (matches Python: get_nth_parent_hash(prev_hash, 99))
        if (last.IsNull() && prev_height < 99) {
            // Chain is complete and shorter than 99 → None (zero)
            share.m_far_share_hash = uint256();
        } else {
            share.m_far_share_hash = tracker.chain.get_nth_parent_key(prev_share, 99);
        }
    } else {
        share.m_absheight = 0;
        share.m_far_share_hash = uint256();
    }

    // Random last_txout_nonce for OP_RETURN uniqueness
    share.m_last_txout_nonce = static_cast<uint64_t>(std::time(nullptr)) ^
                               (static_cast<uint64_t>(min_header.m_nonce) << 32);

    // --- Build the p2pool coinbase in the same format as generate_share_transaction ---
    // This is needed to compute hash_link and to verify the share locally.
    // The coinbase format is: version(4) + vin(1 input) + vout(outputs...) + locktime(4)
    //
    // For the hash_link, we need to split the coinbase at the ref_hash boundary:
    //   prefix = everything up to (and including) gentx_before_refhash
    //   suffix = ref_hash + last_txout_nonce + locktime (= hash_link_data)
    //
    // We compute generate_share_transaction's coinbase from the share fields,
    // then extract the prefix and compute the hash_link.

    // ref_merkle_link: empty branch (ref_hash = hash_ref directly)
    share.m_ref_merkle_link.m_branch.clear();
    share.m_ref_merkle_link.m_index = 0;

    // merkle_link: from Stratum merkle branches
    share.m_merkle_link.m_branch = merkle_branches;
    share.m_merkle_link.m_index  = 0;

    // Populate segwit_data for V36 when segwit is active
    if (segwit_active && !witness_commitment_hex.empty())
    {
        SegwitData sd;
        // txid_merkle_link == merkle_link (coinbase txid == stripped hash for non-witness)
        sd.m_txid_merkle_link.m_branch = merkle_branches;
        sd.m_txid_merkle_link.m_index  = 0;
        // wtxid_merkle_root: the RAW witness merkle root (not the commitment hash)
        // Python stores this raw root and computes SHA256d(root || '[P2Pool]'*4) at verify time
        if (!witness_root.IsNull()) {
            sd.m_wtxid_merkle_root = witness_root;
        } else if (witness_commitment_hex.size() >= 76) {
            // Legacy fallback: extract commitment hash from witness_commitment_hex
            // (only used if witness_root is not provided)
            sd.m_wtxid_merkle_root = uint256S(witness_commitment_hex.substr(12, 64));
        } else {
            sd.m_wtxid_merkle_root = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        }
        share.m_segwit_data = sd;
    }

    // --- Compute the ref_hash ---
    PackStream ref_stream;
    {
        auto hex = PoolConfig::identifier_hex();
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            unsigned char byte = static_cast<unsigned char>(
                std::stoul(hex.substr(i, 2), nullptr, 16));
            ref_stream.write(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(&byte), 1));
        }
    }
    ref_stream << share.m_prev_hash;
    ref_stream << share.m_coinbase;
    ref_stream << share.m_nonce;
    ref_stream << share.m_pubkey_hash;
    ref_stream << share.m_pubkey_type;
    ::Serialize(ref_stream, VarInt(share.m_subsidy));
    ref_stream << share.m_donation;
    { uint8_t si = static_cast<uint8_t>(share.m_stale_info); ref_stream << si; }
    ::Serialize(ref_stream, VarInt(share.m_desired_version));
    // segwit_data (V36+, optional)
    if (share.m_segwit_data.has_value())
        ref_stream << share.m_segwit_data.value();
    ref_stream << share.m_merged_addresses;
    ref_stream << share.m_far_share_hash;
    ref_stream << share.m_max_bits;
    ref_stream << share.m_bits;
    ref_stream << share.m_timestamp;
    ref_stream << share.m_absheight;
    ::Serialize(ref_stream, Using<AbsworkV36Format>(share.m_abswork));
    ref_stream << share.m_merged_coinbase_info;
    ref_stream << share.m_merged_payout_hash;
    // V36 ref_type includes message_data (empty BaseScript → varint(0) = 0x00)
    ref_stream << share.m_message_data;

    auto ref_span_v = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 hash_ref = Hash(ref_span_v);
    uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

    // --- Build the full coinbase TX (non-witness) ---
    // This MUST match generate_share_transaction() exactly so that remote peers
    // can verify the share.  We compute the same PPLNS outputs here.

    // 1. Compute PPLNS weights (V36: exponential depth-decay matching Python)
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;

    if (!prev_share.IsNull() && tracker.chain.contains(prev_share))
    {
        auto chain_len = std::min(
            tracker.chain.get_height(prev_share),
            static_cast<int32_t>(PoolConfig::real_chain_length()));
        // block_target from block header bits (matches Python: self.header['bits'].target)
        auto block_target = chain::bits_to_target(share.m_min_header.m_bits);
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * PoolConfig::SPREAD * 65535;

        // V36: use exponential depth-decay
        auto result = tracker.get_v36_decayed_cumulative_weights(prev_share, chain_len, max_weight);
        weights = std::move(result.weights);
        total_weight = result.total_weight;
        total_donation_weight = result.total_donation_weight;
    }

    // 2. Convert weights to integer payout amounts (V36 formula)
    std::map<std::vector<unsigned char>, uint64_t> amounts;
    if (!total_weight.IsNull())
    {
        for (auto& [script, weight] : weights)
        {
            uint64_t amount = (uint288(subsidy) * weight / total_weight).GetLow64();
            if (amount > 0)
                amounts[script] = amount;
        }
    }

    uint64_t sum_amounts = 0;
    for (auto& [s, a] : amounts)
        sum_amounts += a;
    uint64_t donation_amount = (subsidy > sum_amounts) ? (subsidy - sum_amounts) : 0;

    // V36 consensus: donation output must carry >= 1 satoshi (a60f7f7f)
    if (donation_amount < 1 && subsidy > 0 && !amounts.empty()) {
        auto largest = std::max_element(amounts.begin(), amounts.end(),
            [](const auto& a, const auto& b) { return a.second < b.second; });
        if (largest != amounts.end() && largest->second > 0) {
            largest->second -= 1;
            sum_amounts -= 1;
            donation_amount = subsidy - sum_amounts;
        }
    }

    // 3. Build sorted output list: ascending by (amount, script)
    // Python: sorted(dests, key=lambda a: (amounts[a], a))[-4000:]
    std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payout_outputs(
        amounts.begin(), amounts.end());
    std::sort(payout_outputs.begin(), payout_outputs.end(),
        [](const auto& a, const auto& b) {
            if (a.second != b.second) return a.second < b.second;
            return a.first < b.first;
        });
    constexpr size_t MAX_OUTPUTS = 4000;
    if (payout_outputs.size() > MAX_OUTPUTS)
        payout_outputs.erase(payout_outputs.begin(), payout_outputs.end() - MAX_OUTPUTS);

    // 4. Serialize the coinbase TX (matches generate_share_transaction exactly)
    PackStream gentx;
    { uint32_t v = 1; gentx.write(std::span<const std::byte>(
          reinterpret_cast<const std::byte*>(&v), 4)); }
    { unsigned char one = 1; gentx.write(std::span<const std::byte>(
          reinterpret_cast<const std::byte*>(&one), 1)); }
    // vin[0]
    { uint256 z; gentx << z; }
    { uint32_t idx = 0xffffffff; gentx.write(std::span<const std::byte>(
          reinterpret_cast<const std::byte*>(&idx), 4)); }
    gentx << share.m_coinbase;
    { uint32_t seq = 0xffffffff; gentx.write(std::span<const std::byte>(
          reinterpret_cast<const std::byte*>(&seq), 4)); }

    // Count total outputs
    size_t n_outs = payout_outputs.size() + 1 /* donation */ + 1 /* OP_RETURN */;
    bool has_segwit = share.m_segwit_data.has_value();
    if (has_segwit) n_outs += 1;

    // vout count
    if (n_outs < 253) {
        uint8_t cnt = static_cast<uint8_t>(n_outs);
        gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 1));
    } else {
        uint8_t marker = 0xfd;
        gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&marker), 1));
        uint16_t cnt = static_cast<uint16_t>(n_outs);
        gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 2));
    }

    auto write_txout = [&](uint64_t value, const std::vector<unsigned char>& script, const std::string& = "") {
        gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), 8));
        BaseScript bs;
        bs.m_data = script;
        gentx << bs;
    };

    // Segwit commitment output (FIRST, if present)
    if (has_segwit)
    {
        auto& sd = share.m_segwit_data.value();
        std::vector<unsigned char> wscript;
        wscript.push_back(0x6a);
        wscript.push_back(0x24);
        wscript.push_back(0xaa);
        wscript.push_back(0x21);
        wscript.push_back(0xa9);
        wscript.push_back(0xed);
        // Compute P2Pool witness commitment: SHA256d(wtxid_merkle_root || '[P2Pool]'*4)
        uint256 commitment = compute_p2pool_witness_commitment(sd.m_wtxid_merkle_root);
        auto commitment_bytes = commitment.GetChars();
        wscript.insert(wscript.end(), commitment_bytes.begin(), commitment_bytes.end());
        write_txout(0, wscript, "segwit_commitment");
    }

    // PPLNS payout outputs (sorted)
    for (auto& [script, amount] : payout_outputs)
        write_txout(amount, script, "pplns");

    // Donation output
    auto donation_script_v = PoolConfig::get_donation_script(int64_t(36));
    write_txout(donation_amount, donation_script_v, "donation");

    // OP_RETURN commitment (LAST)
    {
        std::vector<unsigned char> op_return_data;
        op_return_data.push_back(0x6a);
        op_return_data.push_back(0x28);
        op_return_data.insert(op_return_data.end(), ref_hash.data(), ref_hash.data() + 32);
        { uint64_t n = share.m_last_txout_nonce;
          auto* p = reinterpret_cast<const unsigned char*>(&n);
          op_return_data.insert(op_return_data.end(), p, p + 8); }
        write_txout(0, op_return_data, "op_return");
    }

    // locktime
    { uint32_t lt = 0; gentx.write(std::span<const std::byte>(
          reinterpret_cast<const std::byte*>(&lt), 4)); }

    // --- Compute hash_link from the coinbase prefix ---
    auto gentx_before_refhash = compute_gentx_before_refhash(int64_t(36));

    // P2Pool-compatible hash_link: the extranonce (en1+en2) is now in the
    // last_txout_nonce position (part of the suffix / last 44 bytes), NOT in
    // the scriptSig.  So the prefix (everything before the last 44 bytes)
    // is the SAME regardless of extranonce values — it matches what
    // generate_transaction() would produce from share.m_coinbase.
    std::vector<unsigned char> coinbase_bytes_for_hashlink;
    if (!actual_coinbase_bytes.empty()) {
        coinbase_bytes_for_hashlink = actual_coinbase_bytes;
    } else {
        coinbase_bytes_for_hashlink.assign(
            reinterpret_cast<const unsigned char*>(gentx.data()),
            reinterpret_cast<const unsigned char*>(gentx.data()) + gentx.size());
    }

    // The split point: everything before ref_hash + last_txout_nonce + locktime
    // = coinbase minus last (32 + 8 + 4) = 44 bytes
    constexpr size_t suffix_len = 32 + 8 + 4; // ref_hash + last_txout_nonce + locktime
    if (coinbase_bytes_for_hashlink.size() > suffix_len) {
        std::vector<unsigned char> prefix(
            coinbase_bytes_for_hashlink.begin(), coinbase_bytes_for_hashlink.end() - suffix_len);
        share.m_hash_link = prefix_to_hash_link(prefix, gentx_before_refhash);

        // Extract last_txout_nonce (8 bytes before locktime)
        size_t nonce_offset = coinbase_bytes_for_hashlink.size() - 4 - 8;
        uint64_t extracted_nonce = 0;
        std::memcpy(&extracted_nonce, coinbase_bytes_for_hashlink.data() + nonce_offset, 8);
        share.m_last_txout_nonce = extracted_nonce;
    }

    // --- Compute share hash ---
    // Build the full 80-byte block header and double-SHA256 it
    PackStream header_stream;
    { uint32_t v = static_cast<uint32_t>(min_header.m_version);
      header_stream << v; }
    header_stream << min_header.m_previous_block;

    // Compute merkle root for the block header.
    // The MINER hashed the coinbase with the REAL extranonce2, so we must use
    // actual_coinbase_bytes for the merkle root in the block header.
    uint256 gentx_hash_for_header;
    if (!actual_coinbase_bytes.empty()) {
        auto actual_span = std::span<const unsigned char>(
            actual_coinbase_bytes.data(), actual_coinbase_bytes.size());
        gentx_hash_for_header = Hash(actual_span);
    } else {
        auto gentx_span = std::span<const unsigned char>(
            reinterpret_cast<const unsigned char*>(gentx.data()),
            reinterpret_cast<const unsigned char*>(gentx.data()) + gentx.size());
        gentx_hash_for_header = Hash(gentx_span);
    }
    uint256 merkle_root;
    if (share.m_segwit_data.has_value())
        merkle_root = check_merkle_link(gentx_hash_for_header, share.m_segwit_data->m_txid_merkle_link);
    else
        merkle_root = check_merkle_link(gentx_hash_for_header, share.m_merkle_link);

    header_stream << merkle_root;
    header_stream << min_header.m_timestamp;
    header_stream << min_header.m_bits;
    header_stream << min_header.m_nonce;

    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());
    uint256 share_hash = Hash(hdr_span);

    // Set the share's identity hash
    share.m_hash = share_hash;

    // Phase 1: share_init_verify — checks hash_link, merkle, PoW
    try {
        uint256 verify_hash = share_init_verify(share);
        if (verify_hash != share_hash) {
            LOG_ERROR << "create_local_share: self-validation hash mismatch!"
                      << " expected=" << share_hash.GetHex()
                      << " got=" << verify_hash.GetHex();
            return uint256();
        }
    } catch (const std::exception& e) {
        // PoW failures are expected for most stratum submissions (~1/2700 meet share target)
        std::string msg = e.what();
        if (msg.find("PoW") == std::string::npos) {
            LOG_ERROR << "create_local_share: self-validation FAILED: " << msg
                      << " share=" << share_hash.GetHex();
        }
        return uint256();
    }

    // Phase 2: GENTX comparison — checks that our coinbase matches what
    // generate_share_transaction would produce from PPLNS weights.
    // This is the check Python peers perform in check().
    // (We skip share_check's version/timestamp checks since the share isn't in
    // the tracker yet, and those checks aren't relevant for locally created shares.)
    if (!share.m_prev_hash.IsNull() && tracker.chain.contains(share.m_prev_hash))
    {
        try {
            uint256 expected_gentx = generate_share_transaction(share, tracker);

            // Compute actual gentx_hash via the same hash_link path that Python uses
            auto gst_gentx_before_refhash = compute_gentx_before_refhash(int64_t(36));
            std::vector<unsigned char> gst_hash_link_data;
            {
                uint256 ref_hash_chk = check_merkle_link(ref_hash, share.m_ref_merkle_link);
                gst_hash_link_data.insert(gst_hash_link_data.end(),
                    ref_hash_chk.data(), ref_hash_chk.data() + 32);
                uint64_t nonce = share.m_last_txout_nonce;
                auto* p = reinterpret_cast<const unsigned char*>(&nonce);
                gst_hash_link_data.insert(gst_hash_link_data.end(), p, p + 8);
                uint32_t zero = 0;
                auto* z = reinterpret_cast<const unsigned char*>(&zero);
                gst_hash_link_data.insert(gst_hash_link_data.end(), z, z + 4);
            }
            uint256 actual_gentx = check_hash_link(share.m_hash_link, gst_hash_link_data, gst_gentx_before_refhash);

            if (expected_gentx != actual_gentx) {
                LOG_ERROR << "create_local_share: GENTX MISMATCH!"
                          << "\n  expected=" << expected_gentx.GetHex()
                          << "\n  actual  =" << actual_gentx.GetHex()
                          << "\n  share=" << share_hash.GetHex()
                          << "\n  prev_share=" << prev_share.GetHex()
                          << "\n  height=" << share.m_absheight
                          << "\n  subsidy=" << subsidy
                          << "\n  donation=" << donation;
                return uint256();
            }
            LOG_DEBUG_DIAG << "create_local_share: GENTX comparison PASSED";
        } catch (const std::exception& e) {
            LOG_ERROR << "create_local_share: GENTX comparison FAILED: " << e.what()
                      << " share=" << share_hash.GetHex();
            return uint256();
        }
    }

    // Add to tracker (heap-allocate; ShareChain takes ownership via raw pointer)
    auto* heap_share = new MergedMiningShare(share);
    tracker.add(heap_share);
    LOG_DEBUG_DIAG << "create_local_share: added share " << share_hash.GetHex()
                   << " height=" << share.m_absheight
                   << " prev=" << prev_share.GetHex().substr(0, 16) << "...";

    return share_hash;
}

} // namespace ltc
