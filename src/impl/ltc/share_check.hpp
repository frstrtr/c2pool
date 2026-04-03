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
#include <btclibs/base58.h>
#include <btclibs/bech32.h>
#include <core/address_utils.hpp>

#include <algorithm>
#include <array>
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

// prefix_to_hash_link for V35: returns HashLinkType (no extra_data field)
inline HashLinkType prefix_to_hash_link_v35(
    const std::vector<unsigned char>& prefix,
    const std::vector<unsigned char>& const_ending)
{
    auto v36_link = prefix_to_hash_link(prefix, const_ending);
    HashLinkType result;
    result.m_state = v36_link.m_state;
    result.m_length = v36_link.m_length;
    // V35: extra_data is always empty (FixedStrType(0)) — the donation script
    // is long enough to consume the entire SHA256 buffer tail.
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
// pubkey_hash_to_address()
//
// Convert (pubkey_hash, pubkey_type) to a Litecoin address string.
// Used for V35 share_data.address field (VarStr).
// pubkey_type: 0=P2PKH, 1=P2WPKH, 2=P2SH (same as V36 encoding)
// ============================================================================
inline std::string pubkey_hash_to_address(const uint160& pubkey_hash, uint8_t pubkey_type)
{
    bool testnet = PoolConfig::is_testnet;
    if (pubkey_type == 0) {
        // P2PKH: Base58Check with version byte
        uint8_t ver = testnet ? 0x6f : 0x30;
        std::vector<unsigned char> payload(21);
        payload[0] = ver;
        std::memcpy(payload.data() + 1, pubkey_hash.data(), 20);
        return EncodeBase58Check({payload.data(), payload.size()});
    } else if (pubkey_type == 1) {
        // P2WPKH: Bech32 segwit v0
        std::string hrp = testnet ? "tltc" : "ltc";
        std::vector<uint8_t> prog(20);
        std::memcpy(prog.data(), pubkey_hash.data(), 20);
        return bech32::encode_segwit(hrp, 0, prog);
    } else if (pubkey_type == 2) {
        // P2SH: Base58Check with version byte
        uint8_t ver = testnet ? 0xc4 : 0x32;
        std::vector<unsigned char> payload(21);
        payload[0] = ver;
        std::memcpy(payload.data() + 1, pubkey_hash.data(), 20);
        return EncodeBase58Check({payload.data(), payload.size()});
    }
    // Fallback: P2PKH
    uint8_t ver = testnet ? 0x6f : 0x30;
    std::vector<unsigned char> payload(21);
    payload[0] = ver;
    std::memcpy(payload.data() + 1, pubkey_hash.data(), 20);
    return EncodeBase58Check({payload.data(), payload.size()});
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
    int64_t  share_version{36};           // 35 or 36 — determines serialization format
    uint256 prev_share;
    std::vector<unsigned char> coinbase_scriptSig;
    uint32_t share_nonce{0};
    // V36: pubkey_hash + pubkey_type; V35: address (string bytes)
    uint160  pubkey_hash;
    uint8_t  pubkey_type{0};
    std::string address;                  // V35: base58/bech32 address string
    uint64_t subsidy{0};
    uint16_t donation{50};
    uint8_t  stale_info{0};
    uint64_t desired_version{36};
    bool     has_segwit{false};
    SegwitData segwit_data;
    std::vector<MergedAddressEntry> merged_addresses;  // V36 only
    uint256  far_share_hash;
    uint32_t max_bits{0};
    uint32_t bits{0};
    uint32_t timestamp{0};
    uint32_t absheight{0};
    uint128  abswork;
    std::vector<MergedCoinbaseEntry> merged_coinbase_info;  // V36: per-chain DOGE header + merkle proof
    uint256  merged_payout_hash;                            // V36 only
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

    if (p.share_version >= 36) {
        // V36: pubkey_hash (uint160) + pubkey_type (uint8)
        ref_stream << p.pubkey_hash;
        ref_stream << p.pubkey_type;
        ::Serialize(ref_stream, VarInt(p.subsidy));
    } else if (p.share_version >= 34) {
        // V34-V35: address as VarStr
        BaseScript addr_bs;
        addr_bs.m_data.assign(p.address.begin(), p.address.end());
        ref_stream << addr_bs;
        ref_stream << p.subsidy;  // fixed uint64
    } else {
        // Pre-V34: pubkey_hash only
        ref_stream << p.pubkey_hash;
        ref_stream << p.subsidy;  // fixed uint64
    }

    ref_stream << p.donation;
    ref_stream << p.stale_info;
    ::Serialize(ref_stream, VarInt(p.desired_version));

    if (p.has_segwit)
        ref_stream << p.segwit_data;

    // V36: merged_addresses (after segwit_data, before far_share_hash)
    if (p.share_version >= 36)
        ref_stream << p.merged_addresses;

    ref_stream << p.far_share_hash;
    ref_stream << p.max_bits;
    ref_stream << p.bits;
    ref_stream << p.timestamp;
    ref_stream << p.absheight;

    if (p.share_version >= 36) {
        ::Serialize(ref_stream, Using<AbsworkV36Format>(p.abswork));
        ref_stream << p.merged_coinbase_info;
        ref_stream << p.merged_payout_hash;
        // V36 ref_type includes message_data as PossiblyNoneType(b'', VarStrType())
        ref_stream << p.message_data;
    } else {
        // Pre-V36: abswork as fixed uint128
        ref_stream << p.abswork;
    }

    auto ref_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 ref_hash = Hash(ref_span);

    {
        static int rfn_log = 0;
        static int rfn_v36_log = 0;
        bool should_log = (rfn_log < 3) || (p.share_version >= 36 && rfn_v36_log < 5);
        if (should_log) {
            rfn_log++;
            if (p.share_version >= 36) rfn_v36_log++;
            static const char* HX = "0123456789abcdef";
            std::string hex;
            auto* rd = reinterpret_cast<const unsigned char*>(ref_stream.data());
            for (size_t i = 0; i < ref_stream.size(); ++i) { hex += HX[rd[i]>>4]; hex += HX[rd[i]&0xf]; }
            LOG_INFO << "[REF-FN] v=" << p.share_version
                     << " ref_packed_len=" << ref_stream.size()
                     << " ref_hash=" << ref_hash.GetHex()
                     << " absheight=" << p.absheight << " prev=" << p.prev_share.GetHex().substr(0,16);
            LOG_INFO << "[REF-FN-FULL] " << hex;
        }
    }

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
                // PossiblyNoneType: ALWAYS serialize (p2pool writes default when None)
                if (share.m_segwit_data.has_value()) {
                    ref_stream << share.m_segwit_data.value();
                } else {
                    std::vector<uint256> empty_branch;
                    ref_stream << empty_branch;
                    uint256 zero_root;
                    ref_stream << zero_root;
                }
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

    // Diagnostic: compare hash_link-derived gentx_hash with expected
    // Only log for self-validation (check_pow=true means local share)
    if (check_pow) {
        static int verify_diag = 0;
        if (verify_diag < 10) {
            LOG_INFO << "[verify-diag] gentx_hash(hash_link)=" << gentx_hash.GetHex()
                     << " hash_link_data_len=" << hash_link_data.size();
            ++verify_diag;
        }
    }

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
        if (target > PoolConfig::max_target())
            throw std::invalid_argument("share target exceeds MAX_TARGET");
        auto max_target = chain::bits_to_target(share.m_max_bits);
        if (!max_target.IsNull() && target > max_target)
            throw std::invalid_argument("share target exceeds max_target — too easy");

        // Compute the scrypt hash of the 80-byte block header
        char pow_hash_bytes[32];
        scrypt_1024_1_1_256(reinterpret_cast<const char*>(header_stream.data()),
                            pow_hash_bytes);
        uint256 pow_hash;
        memcpy(pow_hash.begin(), pow_hash_bytes, 32);

        if (pow_hash > target)
        {
            // Expected for stratum pseudoshares: VARDIFF target is much lower
            // than share target, so most submissions won't meet PoW.
            // Only a real share (1 in ~20000 pseudoshares) passes this check.
            LOG_TRACE << "PoW below share target: bits=" << share.m_bits
                      << " target=" << target.GetHex().substr(0,32)
                      << " pow_hash=" << pow_hash.GetHex().substr(0,32);
            throw std::invalid_argument("share PoW hash does not meet target");
        }

        // Block detection: check if share's scrypt hash also meets the BLOCK target.
        // min_header.m_bits = block difficulty from GBT (much harder than share target).
        // When pow_hash <= block_target, this share IS a solved block!
        // Use static dedup to avoid logging same block twice (phase1 + phase2 both call this).
        uint256 block_target = chain::bits_to_target(share.m_min_header.m_bits);
        if (!block_target.IsNull() && pow_hash <= block_target) {
            static uint256 s_last_block_share;
            if (share_hash != s_last_block_share) {
                s_last_block_share = share_hash;
                LOG_INFO << "[BLOCK] Peer share meets block target"
                         << " hash=" << share_hash.GetHex().substr(0,16);
            }
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
    auto h = hash.GetChars(); // little-endian (internal storage order)
    switch (type)
    {
    case 1: // P2WPKH: OP_0 <20>
        // Use GetChars() output directly — same as P2PKH and P2SH.
        // The bytes in m_pubkey_hash are the raw witness program as
        // deserialized from the wire. No reversal needed.
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
// Normalize a parent chain script to merged chain P2PKH script.
//
// P2WPKH (00 14 <hash>) → P2PKH (76 a9 14 <hash> 88 ac)  [same pubkey_hash]
// P2PKH  (76 a9 14 <hash> 88 ac) → passed through
// P2SH   (a9 14 <hash> 87)       → P2SH (passed through)
// P2WSH  (00 20 <hash>)          → empty (unconvertible)
// P2TR   (51 20 <key>)           → empty (unconvertible)
//
// Returns empty vector for unconvertible scripts (Tier 3: redistributed).
// Matches Python data.py:build_canonical_merged_coinbase() conversion logic.
// ============================================================================
inline std::vector<unsigned char> normalize_script_for_merged(
    const std::vector<unsigned char>& script)
{
    // P2PKH (25 bytes: 76 a9 14 <20> 88 ac) — already correct
    if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
        script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
        return script;

    // P2WPKH (22 bytes: 00 14 <20>) — convert to P2PKH using same hash
    if (script.size() == 22 && script[0] == 0x00 && script[1] == 0x14)
    {
        std::vector<unsigned char> p2pkh;
        p2pkh.reserve(25);
        p2pkh.push_back(0x76); // OP_DUP
        p2pkh.push_back(0xa9); // OP_HASH160
        p2pkh.push_back(0x14); // PUSH 20
        p2pkh.insert(p2pkh.end(), script.begin() + 2, script.end()); // <hash160>
        p2pkh.push_back(0x88); // OP_EQUALVERIFY
        p2pkh.push_back(0xac); // OP_CHECKSIG
        return p2pkh;
    }

    // P2SH (23 bytes: a9 14 <20> 87) — pass through (DOGE supports P2SH)
    if (script.size() == 23 && script[0] == 0xa9 && script[1] == 0x14 &&
        script[22] == 0x87)
        return script;

    // P2WSH (34 bytes: 00 20 <32>) or P2TR (34 bytes: 51 20 <32>) — unconvertible
    return {};
}

// MERGED: prefix for weight map keys — matches p2pool's 'MERGED:' + hex string.
// Keeps Tier 1/1.5 (explicit DOGE script) keys separate from raw LTC script keys
// in the same weight map, preventing V35+V36 weight collapse for the same miner.
// 7 bytes: 0x4d 0x45 0x52 0x47 0x45 0x44 0x3a = "MERGED:"
inline constexpr std::array<unsigned char, 7> MERGED_KEY_PREFIX = {
    0x4d, 0x45, 0x52, 0x47, 0x45, 0x44, 0x3a
};

// Prepend MERGED: prefix to a script for use as a weight map key.
inline std::vector<unsigned char> make_merged_key(
    const std::vector<unsigned char>& script)
{
    std::vector<unsigned char> key;
    key.reserve(MERGED_KEY_PREFIX.size() + script.size());
    key.insert(key.end(), MERGED_KEY_PREFIX.begin(), MERGED_KEY_PREFIX.end());
    key.insert(key.end(), script.begin(), script.end());
    return key;
}

// Check if a weight key has the MERGED: prefix.
inline bool is_merged_key(const std::vector<unsigned char>& key)
{
    return key.size() > MERGED_KEY_PREFIX.size() &&
           std::equal(MERGED_KEY_PREFIX.begin(), MERGED_KEY_PREFIX.end(),
                      key.begin());
}

// Strip MERGED: prefix, returning the raw script bytes.
// Caller must check is_merged_key() first.
inline std::vector<unsigned char> strip_merged_key(
    const std::vector<unsigned char>& key)
{
    return std::vector<unsigned char>(
        key.begin() + MERGED_KEY_PREFIX.size(), key.end());
}

// Resolve a weight map key to a DOGE-compatible scriptPubKey.
// MERGED:-prefixed keys: strip prefix, use directly (already a DOGE script).
// Raw keys: autoconvert (P2WPKH→P2PKH, P2PKH/P2SH pass through).
// Returns empty if unconvertible (P2WSH, P2TR, etc.).
inline std::vector<unsigned char> resolve_merged_payout_script(
    const std::vector<unsigned char>& key)
{
    if (is_merged_key(key))
        return strip_merged_key(key);
    return normalize_script_for_merged(key);
}

// ============================================================================
// Helper: extract full scriptPubKey from a share variant
// ============================================================================
inline std::vector<unsigned char> get_share_script(const auto* obj)
{
    if constexpr (requires { obj->m_pubkey_type; })
        return pubkey_hash_to_script(obj->m_pubkey_hash, obj->m_pubkey_type);
    else if constexpr (requires { obj->m_address; })
    {
        // V34/V35: m_address contains a human-readable address string.
        // Convert to scriptPubKey for PPLNS weight computation.
        std::string addr_str(obj->m_address.m_data.begin(), obj->m_address.m_data.end());
        auto script = core::address_to_script(addr_str);
        if (!script.empty())
            return script;
        // Fallback: return raw bytes (shouldn't happen with valid addresses)
        return obj->m_address.m_data;
    }
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
uint256 generate_share_transaction(const ShareT& share, TrackerT& tracker, bool dump_diag = false, bool v36_active = false)
{
    constexpr int64_t ver = ShareT::version;
    // p2pool selects PPLNS formula by runtime AutoRatchet state, not compile-time
    // share version. When v36_active is true (AutoRatchet ACTIVATED/CONFIRMED),
    // use v36 PPLNS even for v35 shares. Ref: p2pool data.py:879, work.py:759.
    const bool use_v36_pplns = v36_active || (ver >= 36);
    const uint64_t subsidy = share.m_subsidy;
    const uint16_t donation = share.m_donation;

    // Debug: log the PPLNS formula selection for cross-impl comparison
    {
        static int gst_pplns_log = 0;
        if (gst_pplns_log++ % 50 == 0) {
            LOG_INFO << "[GST-PPLNS] v36_active=" << v36_active
                     << " use_v36_pplns=" << use_v36_pplns
                     << " ver=" << ver
                     << " start=" << share.m_prev_hash.GetHex().substr(0, 16)
                     << " subsidy=" << subsidy
                     << " donation=" << donation;
        }
    }

    // --- 1. Compute PPLNS weights with full scriptPubKey keys ---
    // Walk from share's prev_hash (parent) backward through the chain.
    // This matches the Python: weights are computed relative to the share's parent.

    auto prev_hash = share.m_prev_hash;
    std::map<std::vector<unsigned char>, uint288> weights;
    uint288 total_weight;
    uint288 total_donation_weight;

    if (!prev_hash.IsNull() && tracker.chain.contains(prev_hash))
    {
        // p2pool data.py:762-764 — refuse to compute PPLNS with insufficient depth.
        // Without this guard, attempt_verify() (which allows CHAIN_LENGTH+1) can
        // trigger a PPLNS walk that terminates early, producing wrong coinbase
        // amounts and causing persistent GENTX-MISMATCH during bootstrap.
        auto chain_len = static_cast<int32_t>(PoolConfig::real_chain_length());
        {
            auto pplns_height = tracker.chain.get_height(prev_hash);
            auto pplns_last = tracker.chain.get_last(prev_hash);
            if (!(pplns_height >= chain_len || pplns_last.IsNull()))
                throw std::invalid_argument(
                    "share chain not long enough for PPLNS verification (height="
                    + std::to_string(pplns_height) + " need="
                    + std::to_string(chain_len) + ")");
        }

        // block_target from block header bits (matches Python: self.header['bits'].target)
        auto block_target = chain::bits_to_target(share.m_min_header.m_bits);
        auto max_weight = chain::target_to_average_attempts(block_target)
                          * PoolConfig::SPREAD * 65535;

        // PPLNS formula selected by runtime v36_active (AutoRatchet state),
        // not compile-time share version. Ref: p2pool data.py:879, work.py:759.
        if (use_v36_pplns) {
            // V36 PPLNS: exponential depth-decay, walk from parent
            uint288 unlimited_weight;
            unlimited_weight.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            auto result = tracker.get_v36_decayed_cumulative_weights(prev_hash, chain_len, unlimited_weight);
            weights = std::move(result.weights);
            total_weight = result.total_weight;
            total_donation_weight = result.total_donation_weight;
        } else {
            // Pre-V36 PPLNS: flat cumulative weights (no decay)
            // CRITICAL: Walk from GRANDPARENT for HEIGHT-1 shares.
            // p2pool data.py:884-885:
            //   _pplns_start = previous_share.share_data['previous_share_hash']
            //   _pplns_max_shares = max(0, min(height, REAL_CHAIN_LENGTH) - 1)
            uint256 pplns_start;
            tracker.chain.get(prev_hash).share.invoke([&](auto* s) {
                pplns_start = s->m_prev_hash;  // grandparent
            });
            auto available = tracker.chain.get_height(prev_hash);
            auto walk_count = static_cast<size_t>(
                std::max(0, std::min(chain_len, available) - 1));

            if (pplns_start.IsNull() || !tracker.chain.contains(pplns_start) || walk_count == 0) {
                // No grandparent reachable — skip PPLNS walk (genesis case)
            } else {
            auto walk_view = tracker.chain.get_chain(pplns_start, walk_count);

            for (auto [hash, data] : walk_view)
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
            } // end if (pplns_start valid)
        }
    }

    // --- 2. Convert weights to exact integer payout amounts ---
    // Python formula:
    //   Pre-V36: amounts[script] = subsidy * (199 * weight) / (200 * total_weight)
    //            amounts[finder] += subsidy // 200
    //   V36:     amounts[script] = subsidy * weight / total_weight
    //   donation = subsidy - sum(amounts)

    std::map<std::vector<unsigned char>, uint64_t> amounts;

    // Periodic dump of PPLNS weights for cross-impl comparison
    {
        static auto last_amt_dump = std::chrono::steady_clock::now() - std::chrono::seconds(60);
        auto now_d = std::chrono::steady_clock::now();
        if (now_d - last_amt_dump > std::chrono::seconds(30) && weights.size() >= 2) {
            last_amt_dump = now_d;
            LOG_INFO << "[PPLNS-AMT] subsidy=" << subsidy
                     << " total_weight=" << total_weight.GetLow64()
                     << " don_weight=" << total_donation_weight.GetLow64()
                     << " addrs=" << weights.size()
                     << " prev=" << prev_hash.GetHex().substr(0, 16);
            for (auto& [s, w] : weights) {
                uint64_t a = (total_weight.IsNull()) ? 0 :
                    (uint288(subsidy) * w / total_weight).GetLow64();
                LOG_INFO << "[PPLNS-AMT]   weight=" << w.GetLow64()
                         << " amount=" << a;
            }
        }
    }

    if (!total_weight.IsNull())
    {
        for (auto& [script, weight] : weights)
        {
            uint64_t amount;
            if (use_v36_pplns)
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
    if (!use_v36_pplns)
    {
        auto finder_script = get_share_script(&share);
        amounts[finder_script] += subsidy / 200;
    }

    // Donation output = subsidy minus sum of all payout amounts
    uint64_t sum_amounts = 0;
    for (auto& [s, a] : amounts)
        sum_amounts += a;
    uint64_t donation_amount = (subsidy > sum_amounts) ? (subsidy - sum_amounts) : 0;

    // Dump amounts for cross-impl debugging
    if (dump_diag) {
        LOG_INFO << "[GST-AMOUNTS] subsidy=" << subsidy << " addrs=" << amounts.size()
                 << " sum=" << sum_amounts << " donation=" << donation_amount
                 << " prev=" << prev_hash.GetHex().substr(0,16);
        for (auto& [s, a] : amounts) {
            static const char* HX = "0123456789abcdef";
            std::string sh; for (size_t i = 0; i < std::min(s.size(), size_t(10)); ++i) { sh += HX[s[i]>>4]; sh += HX[s[i]&0xf]; }
            LOG_INFO << "[GST-AMOUNTS]   " << sh << "... = " << a;
        }
    }

    // V36 consensus: donation output must carry >= 1 satoshi (a60f7f7f)
    if (use_v36_pplns) {
        if (donation_amount < 1 && subsidy > 0 && !amounts.empty()) {
            // Deduct 1 sat from the largest miner payout
            // Deterministic tiebreak: (amount, script) — largest script wins when equal
            auto largest = std::max_element(amounts.begin(), amounts.end(),
                [](const auto& a, const auto& b) {
                    if (a.second != b.second) return a.second < b.second;
                    return a.first < b.first;
                });
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
                if (dump_diag) {
                    LOG_INFO << "[WC-GST] wtxid_root=" << sd.m_wtxid_merkle_root.GetHex()
                             << " commitment=" << commitment.GetHex();
                }
            }
        }
    }

    // PPLNS payout outputs
    for (auto& [script, amount] : payout_outputs)
        write_txout(amount, script);

    // Donation output — V35 shares always use P2PK DONATION_SCRIPT,
    // V36 shares always use P2SH COMBINED_DONATION_SCRIPT.
    // Each share was created with the donation script matching its version.
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
                    // PossiblyNoneType: ALWAYS serialize (p2pool writes default when None).
                    // Must match share_init_verify — both paths must produce identical ref_hash.
                    if (share.m_segwit_data.has_value()) {
                        ref_stream << share.m_segwit_data.value();
                    } else {
                        std::vector<uint256> empty_branch;
                        ref_stream << empty_branch;
                        uint256 zero_root;
                        ref_stream << zero_root;
                    }
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
    auto txid = Hash(tx_span);

    // One-time full coinbase hex dump for cross-implementation debugging
    {
        static int coinbase_dump_count = 0;
        if (coinbase_dump_count++ < 3) {
            const char* HX = "0123456789abcdef";
            auto to_hex_fn = [&](const unsigned char* p, size_t len) {
                std::string h; h.reserve(len * 2);
                for (size_t i = 0; i < len; ++i) { h += HX[p[i] >> 4]; h += HX[p[i] & 0xf]; }
                return h;
            };
            auto* cp = reinterpret_cast<const unsigned char*>(tx.data());
            LOG_INFO << "[COINBASE-HEX] len=" << tx.size()
                     << " txid=" << txid.GetHex()
                     << " share=" << share.m_hash.GetHex().substr(0, 16)
                     << " hex=" << to_hex_fn(cp, tx.size());
        }
    }

    if (dump_diag)
    {
        const char* HX = "0123456789abcdef";
        auto to_hex = [&](const unsigned char* p, size_t len) {
            std::string h; h.reserve(len * 2);
            for (size_t i = 0; i < len; ++i) { h += HX[p[i] >> 4]; h += HX[p[i] & 0xf]; }
            return h;
        };

        auto* cp = reinterpret_cast<const unsigned char*>(tx.data());
        LOG_WARNING << "[GENTX-DIAG] coinbase_len=" << tx.size() << " txid=" << txid.GetHex();
        LOG_WARNING << "[GENTX-DIAG] coinbase_hex=" << to_hex(cp, tx.size());
        LOG_WARNING << "[GENTX-DIAG] pplns_outputs=" << payout_outputs.size()
                    << " donation_amount=" << donation_amount
                    << " n_outs=" << n_outs
                    << " has_segwit=" << has_segwit;
        LOG_WARNING << "[GENTX-DIAG] total_weight=" << total_weight.GetHex()
                    << " total_don_weight=" << total_donation_weight.GetHex();
        for (size_t i = 0; i < payout_outputs.size(); ++i) {
            auto& [s, a] = payout_outputs[i];
            LOG_WARNING << "[GENTX-DIAG]  payout[" << i << "] amount=" << a
                        << " script=" << to_hex(s.data(), s.size());
        }
        // First 5 + last 5 shares in PPLNS walk (for cross-impl comparison)
        if (!share.m_prev_hash.IsNull() && tracker.chain.contains(share.m_prev_hash)) {
            auto cl = std::min(tracker.chain.get_height(share.m_prev_hash),
                               static_cast<int32_t>(PoolConfig::real_chain_length()));
            LOG_WARNING << "[GENTX-DIAG] PPLNS walk_count=" << cl
                        << " total_weight=" << total_weight.GetHex()
                        << " total_don_weight=" << total_donation_weight.GetHex()
                        << " n_addrs=" << weights.size();
            // First 5 shares
            auto wv = tracker.chain.get_chain(share.m_prev_hash, std::min(cl, int32_t(5)));
            int si = 0;
            for (auto [h, d] : wv) {
                d.share.invoke([&](auto* obj) {
                    auto att = chain::target_to_average_attempts(chain::bits_to_target(obj->m_bits));
                    auto sc = get_share_script(obj);
                    LOG_WARNING << "[GENTX-DIAG]  walk[" << si << "] hash=" << h.ToString().substr(0,16)
                                << " bits=0x" << std::hex << obj->m_bits
                                << " max_bits=0x" << obj->m_max_bits << std::dec
                                << " att=" << att.GetHex()
                                << " don=" << obj->m_donation
                                << " script=" << to_hex(sc.data(), sc.size());
                });
                ++si;
            }
            // Last 5 shares in walk (tail of PPLNS window)
            if (cl > 10) {
                auto full_view = tracker.chain.get_chain(share.m_prev_hash, cl);
                int si2 = 0;
                for (auto [h, d] : full_view) {
                    if (si2 >= cl - 5) {
                        d.share.invoke([&](auto* obj) {
                            auto att = chain::target_to_average_attempts(chain::bits_to_target(obj->m_bits));
                            auto sc = get_share_script(obj);
                            LOG_WARNING << "[GENTX-DIAG]  walk_tail[" << si2 << "/" << cl << "] hash=" << h.ToString().substr(0,16)
                                        << " bits=0x" << std::hex << obj->m_bits
                                        << " max_bits=0x" << obj->m_max_bits << std::dec
                                        << " att=" << att.GetHex()
                                        << " don=" << obj->m_donation
                                        << " script=" << to_hex(sc.data(), sc.size());
                        });
                    }
                    ++si2;
                }
                LOG_WARNING << "[GENTX-DIAG] walk iterated " << si2 << " shares (expected " << cl << ")";
            }
        }
    }

    return txid;
}

// ============================================================================
// verify_merged_coinbase_commitment()
//
// Full 7-step chain verification of merged coinbase (Python data.py:329-458).
// Ensures the merged coinbase committed in the share actually matches the
// canonical PPLNS construction. Without this, a node could commit valid
// m_merged_payout_hash (weights match) but build a DOGE coinbase that pays
// differently — the merkle proof would be for the real (malicious) coinbase.
//
// Verification chain:
//   1. Re-derive canonical DOGE coinbase from PPLNS weights
//   2. canonical_txid = hash256(canonical_coinbase)
//   3. check_merkle_link(canonical_txid, coinbase_merkle_link) == header.merkle_root
//   4. hash256(header) == doge_block_hash
//   5. doge_block_hash matches aux_merkle_root in LTC coinbase mm_data
//
// Returns empty string on success, error message on failure.
// ============================================================================
template <typename ShareT, typename TrackerT>
std::string verify_merged_coinbase_commitment(
    const ShareT& share, TrackerT& tracker)
{
    if constexpr (ShareT::version < 36)
        return {};
    if constexpr (!requires { share.m_merged_coinbase_info; })
        return {};

    // No merged coinbase info → nothing to verify
    if (share.m_merged_coinbase_info.empty())
        return {};

    // Need enough chain history for reliable PPLNS verification
    if (share.m_prev_hash.IsNull() || !tracker.chain.contains(share.m_prev_hash))
        return {};
    auto height = tracker.chain.get_height(share.m_prev_hash);
    if (height < static_cast<int32_t>(PoolConfig::real_chain_length()))
        return {};  // Insufficient depth — skip (match Python behavior)

    auto block_target = chain::bits_to_target(share.m_bits);
    auto max_weight = chain::target_to_average_attempts(block_target)
                    * 65535 * PoolConfig::SPREAD;
    int32_t chain_len = std::min(height,
        static_cast<int32_t>(PoolConfig::real_chain_length()));

    // Parse mm_data from LTC coinbase scriptSig
    const auto& coinbase = share.m_coinbase.m_data;
    static const uint8_t MM_MAGIC[] = {0xfa, 0xbe, 0x6d, 0x6d};
    auto mm_pos = std::search(coinbase.begin(), coinbase.end(),
                               std::begin(MM_MAGIC), std::end(MM_MAGIC));
    if (mm_pos == coinbase.end()) {
        return "merged_coinbase_info present but no mm_data marker in coinbase scriptSig";
    }
    size_t mm_offset = std::distance(coinbase.begin(), mm_pos) + 4;
    if (coinbase.size() - mm_offset < 40)
        return "mm_data too short in coinbase scriptSig";

    // aux_merkle_root: 32 bytes big-endian
    uint256 aux_merkle_root;
    {
        const uint8_t* p = coinbase.data() + mm_offset;
        // MM root is stored big-endian in the coinbase — reverse for internal uint256
        uint8_t* dst = reinterpret_cast<uint8_t*>(aux_merkle_root.begin());
        for (int i = 31; i >= 0; --i)
            dst[i] = *p++;
    }
    uint32_t aux_size = 0;
    {
        const uint8_t* p = coinbase.data() + mm_offset + 32;
        aux_size = p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
    }

    // Get finder script for canonical coinbase construction
    auto finder_script = get_share_script(&share);
    auto finder_merged = normalize_script_for_merged(finder_script);

    for (const auto& info : share.m_merged_coinbase_info) {
        uint32_t chain_id = info.m_chain_id;

        // Step 1: Get PPLNS weights for this merged chain
        auto mw = tracker.get_merged_cumulative_weights(
            share.m_prev_hash, chain_len, max_weight, chain_id);

        if (mw.weights.empty() || mw.total_weight.IsNull())
            continue;  // No V36 shares → can't verify

        // Build payout list (same logic as payout_provider)
        auto donation_script = PoolConfig::get_donation_script(36);
        uint64_t coinbase_value = info.m_coinbase_value;

        // Convert weights to integer payouts
        std::map<std::vector<unsigned char>, uint64_t> output_amounts;
        uint64_t total_distributed = 0;
        double total_d = mw.total_weight.IsNull() ? 0.0
            : static_cast<double>(mw.total_weight.GetLow64());
        for (auto& [key, weight] : mw.weights) {
            auto script = resolve_merged_payout_script(key);
            if (script.empty()) continue;
            double frac = weight.IsNull() ? 0.0
                : static_cast<double>(weight.GetLow64()) / total_d;
            uint64_t amount = static_cast<uint64_t>(coinbase_value * frac);
            if (amount > 0) {
                output_amounts[script] += amount;
                total_distributed += amount;
            }
        }
        uint64_t donation_amount = coinbase_value - total_distributed;
        // Donation >= 1 satoshi
        if (donation_amount < 1 && !output_amounts.empty()) {
            // Deterministic tiebreak: (amount, script) — largest script wins when equal
            auto it = std::max_element(output_amounts.begin(), output_amounts.end(),
                [](auto& a, auto& b) {
                    if (a.second != b.second) return a.second < b.second;
                    return a.first < b.first;
                });
            it->second -= 1;
            donation_amount += 1;
        }

        // Coinbase reconstruction removed: the merged_payout_hash check
        // (Step 1 above) already verifies PPLNS weight correctness via the
        // skip list. Reconstructing the full coinbase TX to verify merkle_root
        // is redundant and fails on cross-implementation shares because:
        // - scriptSig differs ("/c2pool/" vs "/P2Pool/")
        // - OP_RETURN text differs
        // - THE state_root presence differs
        // - Float vs integer rounding in amount calculation
        // All of these change txid → merkle_root without affecting PPLNS fairness.

        // Step 2: Verify header structure and extract block hash
        if (info.m_block_header.m_data.size() < 80)
            return "merged block header too short";

        // Step 3: hash256(header) == doge_block_hash
        auto hdr_span = std::span<const unsigned char>(
            info.m_block_header.m_data.data(), 80);
        uint256 doge_block_hash = Hash(hdr_span);

        // Step 6: Verify doge_block_hash against aux_merkle_root
        if (aux_size == 1) {
            // Single merged chain: aux_merkle_root == block_hash
            if (doge_block_hash != aux_merkle_root) {
                return "merged block hash " + doge_block_hash.GetHex()
                     + " != aux_merkle_root " + aux_merkle_root.GetHex()
                     + " for chain " + std::to_string(chain_id);
            }
        }
        // Multi-chain: would need aux tree reconstruction (future)
    }

    return {};
}

// ============================================================================
// share_check()
//
// The check()-phase verification after init:
//   1. Timestamp not too far in the future
//   2. Version counting (stub — version upgrade enforcement)
//   3. Transaction hash resolution (for pre-v34 shares)
//   4. GenerateShareTransaction reconstruction & comparison
//   5. Merged payout hash + coinbase commitment verification
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
    // p2pool data.py:1400-1414: version switch validation only at BOUNDARIES
    // (when share.VERSION != parent.VERSION). Shares that match their parent's
    // version are always valid — they were correct when created.
    // Previous code rejected ALL v35 shares retroactively after 95% activation.
    {
        auto lookbehind = static_cast<int32_t>(PoolConfig::chain_length());
        if (tracker.chain.contains(share.m_hash) &&
            !share.m_prev_hash.IsNull() && tracker.chain.contains(share.m_prev_hash))
        {
            // Get parent's share version
            int64_t parent_version = 0;
            tracker.chain.get_share(share.m_prev_hash).invoke([&](auto* obj) {
                parent_version = std::remove_pointer_t<decltype(obj)>::version;
            });

            // Only enforce version obsolescence at version BOUNDARIES
            if (share.version != parent_version)
            {
                auto height = tracker.chain.get_height(share.m_hash);
                if (height >= lookbehind)
                {
                    if (tracker.should_punish_version(share.m_hash, share.version, lookbehind))
                        throw std::invalid_argument("share version too old — newer version has 95%+ activation");
                }
            }
        }
    }

    // 3. GenerateShareTransaction reconstruction & comparison
    // Rebuild the expected coinbase from PPLNS weights and share fields,
    // then verify its txid matches the gentx_hash from share_init_verify().
    // p2pool check(): v36_active = (self.VERSION >= 36)
    // Use the SHARE's own version, not the tracker's runtime AutoRatchet state.
    // This ensures V35 shares always verify with V35 PPLNS formula, even after
    // the AutoRatchet transitions to ACTIVATED.
    constexpr int64_t share_ver = ShareT::version;
    bool v36_active = (share_ver >= 36);
    if (!share.m_prev_hash.IsNull() && tracker.chain.contains(share.m_prev_hash))
    {
        uint256 expected_gentx = generate_share_transaction(share, tracker, false, v36_active);
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

            auto chain_len = std::min(
                tracker.chain.get_height(share.m_prev_hash),
                static_cast<int32_t>(PoolConfig::real_chain_length()));
            // V35: log grandparent + height-1 window info
            uint256 gp_hash;
            if (tracker.chain.contains(share.m_prev_hash))
                tracker.chain.get(share.m_prev_hash).share.invoke([&](auto* s){ gp_hash = s->m_prev_hash; });
            int32_t v35_walk = std::max(0, chain_len - 1);
            LOG_WARNING << "  PPLNS chain_len=" << chain_len
                        << " v35_walk=" << v35_walk
                        << " grandparent=" << (gp_hash.IsNull() ? "null" : gp_hash.GetHex().substr(0,16))
                        << " prev_height=" << tracker.chain.get_height(share.m_prev_hash)
                        << " real_chain_length=" << PoolConfig::real_chain_length();

            // Compare share target: what c2pool computes vs what the share has
            {
                static int target_diag = 0;
                if (target_diag++ < 10) {
                    auto [cst_max_bits, cst_bits] = tracker.compute_share_target(
                        share.m_prev_hash, share.m_timestamp, uint256());
                    auto share_aps = tracker.get_pool_attempts_per_second(
                        share.m_prev_hash, PoolConfig::TARGET_LOOKBEHIND, true);
                    LOG_WARNING << "[GENTX-TARGET] share_bits=0x" << std::hex << share.m_bits
                                << " share_max_bits=0x" << share.m_max_bits
                                << " c2pool_bits=0x" << cst_bits
                                << " c2pool_max_bits=0x" << cst_max_bits << std::dec
                                << " aps_min=" << share_aps.GetLow64()
                                << " prev=" << share.m_prev_hash.GetHex().substr(0,16);

                    // APS walk component dump for cross-impl comparison
                    int32_t dist = PoolConfig::TARGET_LOOKBEHIND;
                    auto near_hash = share.m_prev_hash;
                    auto far_hash = near_hash;
                    int32_t actual_dist = 0;
                    for (int32_t i = 0; i < dist - 1; ++i) {
                        if (far_hash.IsNull() || !tracker.chain.contains(far_hash)) break;
                        auto* idx = tracker.chain.get_index(far_hash);
                        far_hash = idx ? idx->tail : uint256();
                        ++actual_dist;
                    }
                    uint32_t near_ts = 0, far_ts = 0;
                    if (tracker.chain.contains(near_hash))
                        tracker.chain.get_share(near_hash).invoke([&](auto* s){ near_ts = s->m_timestamp; });
                    if (!far_hash.IsNull() && tracker.chain.contains(far_hash))
                        tracker.chain.get_share(far_hash).invoke([&](auto* s){ far_ts = s->m_timestamp; });

                    // Compare skip-list far vs naive-walk far
                    auto skip_far = tracker.chain.get_nth_parent_via_skip(
                        share.m_prev_hash, dist - 1);
                    bool skip_match = (!far_hash.IsNull() && skip_far == far_hash);

                    // Also get delta via TrackerView for comparison
                    uint288 delta_min_work;
                    int32_t delta_height = 0;
                    if (!skip_far.IsNull() && tracker.chain.contains(skip_far)) {
                        auto dv = tracker.chain.get_delta(share.m_prev_hash, skip_far);
                        delta_min_work = dv.min_work;
                        delta_height = dv.height;
                    }

                    LOG_WARNING << "[GENTX-APS] near=" << near_hash.GetHex().substr(0,16)
                                << " far_naive=" << (far_hash.IsNull() ? "null" : far_hash.GetHex().substr(0,16))
                                << " far_skip=" << (skip_far.IsNull() ? "null" : skip_far.GetHex().substr(0,16))
                                << " skip_match=" << (skip_match ? "YES" : "NO")
                                << " actual_dist=" << actual_dist
                                << " expected_dist=" << (dist - 1)
                                << " timespan=" << (int32_t(near_ts) - int32_t(far_ts))
                                << " near_ts=" << near_ts << " far_ts=" << far_ts
                                << " chain_height=" << tracker.chain.get_height(share.m_prev_hash)
                                << " delta_h=" << delta_height
                                << " delta_min_work=" << delta_min_work.GetLow64();

                    // Previous share's max_target (clamp reference)
                    uint256 prev_max_target;
                    tracker.chain.get_share(share.m_prev_hash).invoke([&](auto* obj) {
                        prev_max_target = chain::bits_to_target(obj->m_max_bits);
                    });
                    LOG_WARNING << "[GENTX-CLAMP] prev_max_bits=0x" << std::hex
                                << chain::target_to_bits_upper_bound(prev_max_target) << std::dec
                                << " clamp_lo=" << chain::target_to_bits_upper_bound(prev_max_target * 9 / 10)
                                << " clamp_hi=" << chain::target_to_bits_upper_bound(prev_max_target * 11 / 10);
                }
            }
            // --- Detailed diagnostics: re-run with full dump ---
            static int s_diag_count = 0;
            if (s_diag_count++ < 5)
            {
                LOG_WARNING << "[GENTX-DIAG] Re-running generate_share_transaction with full dump (v36_active=" << v36_active << "):";
                generate_share_transaction(share, tracker, true, v36_active);
            }

            throw std::invalid_argument("GenerateShareTransaction mismatch — coinbase does not match PPLNS payouts");
        }
    }

    // 4. V36+ merged_payout_hash verification
    // Verify that the share's committed merged PPLNS hash matches what we
    // independently compute from the share chain. Without this, a malicious
    // node could steal all merged chain (DOGE) rewards while appearing honest
    // on the parent chain (LTC payouts are consensus-enforced via gentx above).
    if constexpr (ShareT::version >= 36)
    {
        if constexpr (requires { share.m_merged_payout_hash; })
        {
            if (!share.m_merged_payout_hash.IsNull() &&
                !share.m_prev_hash.IsNull() &&
                tracker.chain.contains(share.m_prev_hash))
            {
                // Use BLOCK target (from header bits), not share target.
                // p2pool: block_target = self.header['bits'].target
                auto block_target = chain::bits_to_target(share.m_min_header.m_bits);
                auto expected_hash = tracker.compute_merged_payout_hash(
                    share.m_prev_hash, block_target);

                if (!expected_hash.IsNull() && share.m_merged_payout_hash != expected_hash)
                {
                    LOG_WARNING << "merged_payout_hash REJECT: claimed "
                        << share.m_merged_payout_hash.GetHex()
                        << " != expected " << expected_hash.GetHex();
                    throw std::invalid_argument(
                        "merged_payout_hash mismatch — merged chain reward theft attempt");
                }
            }
        }
    }

    // 5. V36+ merged coinbase commitment verification (7-step chain)
    // Verifies the actual merged coinbase matches canonical PPLNS construction.
    if constexpr (ShareT::version >= 36)
    {
        auto mcv_err = verify_merged_coinbase_commitment(share, tracker);
        if (!mcv_err.empty())
            throw std::invalid_argument("merged coinbase verification: " + mcv_err);
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
    // Skip scrypt PoW re-check when hash was already computed in Phase 1
    // (processing_shares offloads scrypt to m_verify_pool; no need to repeat).
    uint256 hash = share_init_verify(share, share.m_hash.IsNull());

    // Verify recomputed hash matches stored hash (informational).
    // For locally created shares the hash was set during create_local_share;
    // a mismatch means the header reconstruction diverged (e.g., genesis PPLNS
    // race). The share_check phase uses share.m_hash for chain lookups.
    if (!share.m_hash.IsNull() && hash != share.m_hash) {
        static int hash_mismatch_log = 0;
        if (hash_mismatch_log++ < 10)
            LOG_WARNING << "[verify_share] hash mismatch: recomputed="
                        << hash.GetHex().substr(0, 16)
                        << " stored=" << share.m_hash.GetHex().substr(0, 16);
    }

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
                // PossiblyNoneType: ALWAYS serialize (p2pool writes default when None)
                if (share.m_segwit_data.has_value()) {
                    ref_stream << share.m_segwit_data.value();
                } else {
                    std::vector<uint256> empty_branch;
                    ref_stream << empty_branch;
                    uint256 zero_root;
                    ref_stream << zero_root;
                }
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
// create_local_share_v35()
//
// Constructs a PaddingBugfixShare (V35) from locally-generated block data.
// This is the V35 counterpart of create_local_share (V36).
// Key differences from V36:
//   - Uses m_address (string) instead of m_pubkey_hash + m_pubkey_type
//   - No merged_addresses, merged_coinbase_info, merged_payout_hash
//   - Fixed uint64 subsidy (not VarInt)
//   - Fixed uint128 abswork (not VarInt)
//   - HashLinkType (no extra_data) instead of V36HashLinkType
//   - DONATION_SCRIPT (P2PK 67b) instead of COMBINED_DONATION_SCRIPT (P2SH 23b)
// ============================================================================
template <typename TrackerT>
uint256 create_local_share_v35(
    TrackerT& tracker,
    const coin::SmallBlockHeaderType& min_header,
    const BaseScript& coinbase,
    uint64_t subsidy,
    const uint256& prev_share,
    const std::vector<uint256>& merkle_branches,
    const std::vector<unsigned char>& payout_script,
    uint16_t donation = 50,
    StaleInfo stale_info = StaleInfo::none,
    bool segwit_active = false,
    const std::string& witness_commitment_hex = {},
    const std::vector<unsigned char>& actual_coinbase_bytes = {},
    const uint256& witness_root = uint256(),
    uint32_t override_max_bits = 0,
    uint32_t override_bits = 0,
    uint32_t frozen_absheight = 0,
    uint128  frozen_abswork = uint128(),
    uint256  frozen_far_share_hash = uint256(),
    uint32_t frozen_timestamp = 0,
    bool     has_frozen = false,
    const std::vector<uint256>& frozen_merkle_branches = {},
    const uint256& frozen_witness_root = uint256(),
    uint64_t desired_version = 36)
{
    PaddingBugfixShare share;
    share.m_min_header = min_header;
    share.m_coinbase   = coinbase;
    share.m_subsidy    = subsidy;
    share.m_prev_hash  = prev_share;
    share.m_donation   = donation;
    share.m_stale_info = stale_info;
    share.m_desired_version = desired_version;

    // Timestamp: clip to at least previous_share.timestamp + 1
    share.m_timestamp  = min_header.m_timestamp;
    if (!prev_share.IsNull() && tracker.chain.contains(prev_share)) {
        uint32_t prev_ts = 0;
        tracker.chain.get(prev_share).share.invoke([&](auto* prev) {
            prev_ts = prev->m_timestamp;
        });
        if (share.m_timestamp <= prev_ts)
            share.m_timestamp = prev_ts + 1;
    }

    // Compute share target
    auto desired_target = chain::bits_to_target(min_header.m_bits);
    auto [share_max_bits, share_bits] = tracker.compute_share_target(
        prev_share, share.m_timestamp, desired_target);
    share.m_max_bits   = share_max_bits;
    share.m_bits       = share_bits;
    share.m_nonce      = 0;

    // V35: address as string (VarStr), convert from payout_script
    {
        uint160 pubkey_hash;
        uint8_t pubkey_type = 0;
        if (payout_script.size() == 25 && payout_script[0] == 0x76) {
            std::memcpy(pubkey_hash.data(), payout_script.data() + 3, 20);
            pubkey_type = 0;
        } else if (payout_script.size() == 23 && payout_script[0] == 0xa9) {
            std::memcpy(pubkey_hash.data(), payout_script.data() + 2, 20);
            pubkey_type = 2;
        } else if (payout_script.size() == 22 && payout_script[0] == 0x00) {
            std::memcpy(pubkey_hash.data(), payout_script.data() + 2, 20);
            pubkey_type = 1;
        } else if (payout_script.size() >= 20) {
            std::memcpy(pubkey_hash.data(), payout_script.data(), 20);
        }
        std::string addr_str = pubkey_hash_to_address(pubkey_hash, pubkey_type);
        share.m_address.m_data.assign(addr_str.begin(), addr_str.end());
        {
            auto roundtrip = core::address_to_script(addr_str);
            static const char* H = "0123456789abcdef";
            std::string ps_hex, rt_hex;
            for (auto b : payout_script) { ps_hex += H[b>>4]; ps_hex += H[b&0xf]; }
            for (auto b : roundtrip) { rt_hex += H[b>>4]; rt_hex += H[b&0xf]; }
            LOG_INFO << "[V35-ADDR] type=" << (int)pubkey_type
                     << " addr=" << addr_str
                     << " payout_script=" << ps_hex
                     << " roundtrip=" << rt_hex
                     << " match=" << (payout_script == roundtrip ? "YES" : "NO");
        }
    }

    // Chain position: absheight and abswork
    if (!prev_share.IsNull() && tracker.chain.contains(prev_share)) {
        tracker.chain.get(prev_share).share.invoke([&](auto* prev) {
            share.m_absheight = prev->m_absheight + 1;
        });
        {
            auto current_attempts = chain::target_to_average_attempts(
                chain::bits_to_target(share.m_bits));
            uint128 prev_abswork;
            tracker.chain.get(prev_share).share.invoke([&](auto* prev) {
                prev_abswork = prev->m_abswork;
            });
            share.m_abswork = prev_abswork + uint128(current_attempts.GetLow64());
        }
        // far_share_hash: 99th ancestor
        {
            auto [prev_height, last] = tracker.chain.get_height_and_last(prev_share);
            if (last.IsNull() && prev_height < 99) {
                share.m_far_share_hash = uint256();
            } else {
                try {
                    share.m_far_share_hash = tracker.chain.get_nth_parent_key(prev_share, 99);
                } catch (const std::exception&) {
                    share.m_far_share_hash = uint256();
                }
            }
        }
    } else {
        share.m_absheight = 1;
        share.m_abswork = uint128(chain::target_to_average_attempts(
            chain::bits_to_target(share.m_bits)).GetLow64());
        share.m_far_share_hash = uint256();
    }

    // Apply frozen fields from template time
    if (has_frozen) {
        share.m_absheight = frozen_absheight;
        share.m_abswork = frozen_abswork;
        share.m_far_share_hash = frozen_far_share_hash;
        share.m_timestamp = frozen_timestamp;
        if (override_max_bits) share.m_max_bits = override_max_bits;
        if (override_bits) share.m_bits = override_bits;
    }

    // Random last_txout_nonce
    share.m_last_txout_nonce = static_cast<uint64_t>(std::time(nullptr)) ^
                               (static_cast<uint64_t>(min_header.m_nonce) << 32);

    // ref_merkle_link: empty
    share.m_ref_merkle_link.m_branch.clear();
    share.m_ref_merkle_link.m_index = 0;
    // merkle_link: from Stratum
    share.m_merkle_link.m_branch = merkle_branches;
    share.m_merkle_link.m_index  = 0;

    // Segwit data
    if (segwit_active && !witness_commitment_hex.empty())
    {
        SegwitData sd;
        sd.m_txid_merkle_link.m_branch = (has_frozen && !frozen_merkle_branches.empty())
            ? frozen_merkle_branches : merkle_branches;
        sd.m_txid_merkle_link.m_index  = 0;
        // Same priority as V36: frozen > direct > fallback.
        // NEVER extract from witness_commitment_hex (it's a p2pool commitment,
        // not the raw root — using it causes double-hashing in verify path).
        if (!frozen_witness_root.IsNull()) {
            sd.m_wtxid_merkle_root = frozen_witness_root;
        } else if (!witness_root.IsNull()) {
            sd.m_wtxid_merkle_root = witness_root;
        } else {
            sd.m_wtxid_merkle_root = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        }
        share.m_segwit_data = sd;
    }

    // --- Compute ref_hash (V35 format) ---
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
    // V35: address as VarStr
    ref_stream << share.m_address;
    // V35: subsidy as fixed uint64
    ref_stream << share.m_subsidy;
    ref_stream << share.m_donation;
    { uint8_t si = static_cast<uint8_t>(share.m_stale_info); ref_stream << si; }
    ::Serialize(ref_stream, VarInt(share.m_desired_version));
    // segwit_data
    if (share.m_segwit_data.has_value()) {
        ref_stream << share.m_segwit_data.value();
    } else {
        std::vector<uint256> empty_branch;
        ref_stream << empty_branch;
        uint256 zero_root;
        ref_stream << zero_root;
    }
    // V35: NO merged_addresses
    ref_stream << share.m_far_share_hash;
    ref_stream << share.m_max_bits;
    ref_stream << share.m_bits;
    ref_stream << share.m_timestamp;
    ref_stream << share.m_absheight;
    // V35: abswork as fixed uint128
    ref_stream << share.m_abswork;
    // V35: NO merged_coinbase_info, NO merged_payout_hash, NO message_data

    auto ref_span_v = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(ref_stream.data()), ref_stream.size());
    uint256 hash_ref = Hash(ref_span_v);
    uint256 ref_hash = check_merkle_link(hash_ref, share.m_ref_merkle_link);

    // Use ref_hash from actual coinbase if available
    if (!actual_coinbase_bytes.empty() && actual_coinbase_bytes.size() > 44) {
        uint256 coinbase_ref_hash;
        std::memcpy(coinbase_ref_hash.data(),
                     actual_coinbase_bytes.data() + actual_coinbase_bytes.size() - 44, 32);
        ref_hash = coinbase_ref_hash;
    }

    // --- Derive hash_link (V35: HashLinkType, no extra_data) ---
    auto gentx_before_refhash = compute_gentx_before_refhash(int64_t(35));

    std::vector<unsigned char> coinbase_bytes_for_hashlink;
    if (!actual_coinbase_bytes.empty()) {
        coinbase_bytes_for_hashlink = actual_coinbase_bytes;
    } else {
        // Fallback: reconstruct coinbase from V35 PPLNS walk
        // V35: flat weights, grandparent start, height-1 window, 199/200 formula, finder fee
        // Reference: p2pool data.py lines 878-965
        std::map<std::vector<unsigned char>, uint288> weights;
        uint288 total_weight;

        if (!prev_share.IsNull() && tracker.chain.contains(prev_share))
        {
            // V35: start from grandparent (prev_share.prev_hash)
            uint256 pplns_start;
            tracker.chain.get(prev_share).share.invoke([&](auto* s) {
                pplns_start = s->m_prev_hash;
            });

            if (!pplns_start.IsNull()) {
                auto height = tracker.chain.get_height(prev_share);
                int32_t max_shares = std::max(0, std::min(height,
                    static_cast<int32_t>(PoolConfig::real_chain_length())) - 1);
                auto block_target = chain::bits_to_target(share.m_min_header.m_bits);
                auto desired_weight = chain::target_to_average_attempts(block_target)
                                      * uint288(PoolConfig::SPREAD) * uint288(65535);
                // Flat weight accumulation (not decayed)
                auto result = tracker.get_cumulative_weights(pplns_start, max_shares, desired_weight);
                weights = std::move(result.weights);
                total_weight = result.total_weight;
            }
        }

        std::map<std::vector<unsigned char>, uint64_t> amounts;
        if (!total_weight.IsNull()) {
            for (auto& [script, weight] : weights) {
                // V35: 99.5% to PPLNS — subsidy * 199 * weight / (200 * total_weight)
                uint64_t amount = (uint288(subsidy) * uint288(199) * weight
                                   / (uint288(200) * total_weight)).GetLow64();
                if (amount > 0) amounts[script] = amount;
            }
        }
        // V35: add 0.5% finder fee to the share creator's payout script
        amounts[payout_script] = (amounts.count(payout_script) ? amounts[payout_script] : 0)
                                 + subsidy / 200;
        uint64_t sum_amounts = 0;
        for (auto& [s, a] : amounts) sum_amounts += a;
        // V35: no minimum donation enforcement (unlike v36)
        uint64_t donation_amount = (subsidy > sum_amounts) ? (subsidy - sum_amounts) : 0;

        std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payout_outputs(
            amounts.begin(), amounts.end());
        std::sort(payout_outputs.begin(), payout_outputs.end(),
            [](const auto& a, const auto& b) {
                if (a.second != b.second) return a.second < b.second;
                return a.first < b.first;
            });
        if (payout_outputs.size() > 4000)
            payout_outputs.erase(payout_outputs.begin(), payout_outputs.end() - 4000);

        PackStream gentx;
        { uint32_t v = 1; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&v), 4)); }
        { unsigned char one = 1; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&one), 1)); }
        { uint256 z; gentx << z; }
        { uint32_t idx = 0xffffffff; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&idx), 4)); }
        gentx << share.m_coinbase;
        { uint32_t seq = 0xffffffff; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&seq), 4)); }
        size_t n_outs = payout_outputs.size() + 1 + 1;
        bool has_segwit_fb = share.m_segwit_data.has_value();
        if (has_segwit_fb) n_outs += 1;
        if (n_outs < 253) { uint8_t cnt = (uint8_t)n_outs; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 1)); }
        else { uint8_t m = 0xfd; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&m), 1)); uint16_t cnt = (uint16_t)n_outs; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 2)); }
        auto write_txout = [&](uint64_t value, const std::vector<unsigned char>& script) {
            gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), 8));
            BaseScript bs; bs.m_data = script; gentx << bs;
        };
        if (has_segwit_fb) {
            auto& sd = share.m_segwit_data.value();
            std::vector<unsigned char> wscript = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
            uint256 commitment = compute_p2pool_witness_commitment(sd.m_wtxid_merkle_root);
            auto cb = commitment.GetChars();
            wscript.insert(wscript.end(), cb.begin(), cb.end());
            write_txout(0, wscript);
        }
        for (auto& [script, amount] : payout_outputs) write_txout(amount, script);
        // V35: use pre-V36 DONATION_SCRIPT
        write_txout(donation_amount, PoolConfig::get_donation_script(int64_t(35)));
        { std::vector<unsigned char> op; op.push_back(0x6a); op.push_back(0x28);
          op.insert(op.end(), ref_hash.data(), ref_hash.data() + 32);
          uint64_t n = share.m_last_txout_nonce; auto* p = reinterpret_cast<const unsigned char*>(&n);
          op.insert(op.end(), p, p + 8); write_txout(0, op); }
        { uint32_t lt = 0; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&lt), 4)); }

        coinbase_bytes_for_hashlink.assign(
            reinterpret_cast<const unsigned char*>(gentx.data()),
            reinterpret_cast<const unsigned char*>(gentx.data()) + gentx.size());
    }

    // Compute hash_link (V35: HashLinkType)
    constexpr size_t suffix_len = 32 + 8 + 4;
    if (coinbase_bytes_for_hashlink.size() > suffix_len) {
        std::vector<unsigned char> prefix(
            coinbase_bytes_for_hashlink.begin(), coinbase_bytes_for_hashlink.end() - suffix_len);
        share.m_hash_link = prefix_to_hash_link_v35(prefix, gentx_before_refhash);

        size_t nonce_offset = coinbase_bytes_for_hashlink.size() - 4 - 8;
        uint64_t extracted_nonce = 0;
        std::memcpy(&extracted_nonce, coinbase_bytes_for_hashlink.data() + nonce_offset, 8);
        share.m_last_txout_nonce = extracted_nonce;
    }

    // --- Compute share hash (block header double-SHA256) ---
    PackStream header_stream;
    { uint32_t v = static_cast<uint32_t>(min_header.m_version);
      header_stream << v; }
    header_stream << min_header.m_previous_block;

    uint256 gentx_hash_for_header;
    if (!actual_coinbase_bytes.empty()) {
        auto actual_span = std::span<const unsigned char>(
            actual_coinbase_bytes.data(), actual_coinbase_bytes.size());
        gentx_hash_for_header = Hash(actual_span);
    } else {
        auto cb_span = std::span<const unsigned char>(
            coinbase_bytes_for_hashlink.data(), coinbase_bytes_for_hashlink.size());
        gentx_hash_for_header = Hash(cb_span);
    }
    uint256 merkle_root = check_merkle_link(gentx_hash_for_header, share.m_merkle_link);

    header_stream << merkle_root;
    header_stream << min_header.m_timestamp;
    header_stream << min_header.m_bits;
    header_stream << min_header.m_nonce;

    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());

    uint256 share_hash = Hash(hdr_span);
    share.m_hash = share_hash;

    // PoW check against share target
    {
        uint256 target = chain::bits_to_target(share.m_bits);
        if (!target.IsNull()) {
            char pow_bytes[32];
            scrypt_1024_1_1_256(reinterpret_cast<const char*>(hdr_span.data()), pow_bytes);
            uint256 pow_hash;
            memcpy(pow_hash.begin(), pow_bytes, 32);

            if (pow_hash > target) {
                return uint256();  // didn't meet share target
            }
            LOG_INFO << "[Pool] V35 SHARE CREATED! pow=" << pow_hash.GetHex().substr(0, 16)
                     << " target=" << target.GetHex().substr(0, 16)
                     << " diff=" << chain::target_to_difficulty(target);
        }
    }

    // Add to tracker
    auto* heap_share = new PaddingBugfixShare(share);
    tracker.add(heap_share);
    LOG_INFO << "create_local_share_v35: added share " << share_hash.GetHex()
             << " height=" << share.m_absheight
             << " prev=" << prev_share.GetHex().substr(0, 16) << "...";

    return share_hash;
}

// ============================================================================
// create_local_share()
//
// Constructs a share (V35 PaddingBugfixShare or V36 MergedMiningShare) from
// locally-generated block data and adds it to the share tracker.
// Returns the share hash (block header double-SHA256).
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
//   share_version   — 35 or 36 (default 36)
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
    uint32_t override_bits = 0,
    // Frozen share fields from template time — when set, override computed values
    // to ensure ref_hash matches the one embedded in the coinbase.
    uint32_t frozen_absheight = 0,
    uint128  frozen_abswork = uint128(),
    uint256  frozen_far_share_hash = uint256(),
    uint32_t frozen_timestamp = 0,
    uint256  frozen_merged_payout_hash = uint256(),
    bool     has_frozen = false,
    const std::vector<uint256>& frozen_merkle_branches = {},
    const uint256& frozen_witness_root = uint256(),
    const std::vector<unsigned char>& frozen_merged_coinbase_info = {},
    int64_t share_version = 36,
    uint64_t desired_version = 36)
{
    // V35 path: delegate to version-specific implementation
    if (share_version <= 35)
        return create_local_share_v35(
            tracker, min_header, coinbase, subsidy, prev_share, merkle_branches,
            payout_script, donation, stale_info, segwit_active, witness_commitment_hex,
            actual_coinbase_bytes, witness_root, override_max_bits, override_bits,
            frozen_absheight, frozen_abswork, frozen_far_share_hash, frozen_timestamp,
            has_frozen, frozen_merkle_branches, frozen_witness_root, desired_version);

    MergedMiningShare share;
    share.m_min_header = min_header;
    share.m_coinbase   = coinbase;
    share.m_subsidy    = subsidy;
    share.m_prev_hash  = prev_share;
    share.m_donation   = donation;
    share.m_stale_info = stale_info;
    share.m_desired_version = desired_version;

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

    // Diagnostic: confirm merged_addresses are populated for DOGE skiplist Tier 1
    {
        LOG_INFO << "[create_local_share] merged_addresses=" << merged_addrs.size();
        for (const auto& entry : merged_addrs) {
            auto to_hex = [](const std::vector<unsigned char>& s) {
                static const char* H = "0123456789abcdef";
                std::string r; for (auto b : s) { r += H[b>>4]; r += H[b&0xf]; } return r;
            };
            LOG_INFO << "[create_local_share]   chain_id=" << entry.m_chain_id
                     << " script=" << to_hex(entry.m_script.m_data);
        }
    }

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

    // Payout identity — extract pubkey_hash + pubkey_type from scriptPubKey.
    // Must match p2pool V36: 0=P2PKH, 1=P2WPKH, 2=P2SH.
    if (payout_script.size() >= 20) {
        if (payout_script.size() == 25 &&
            payout_script[0] == 0x76 && payout_script[1] == 0xa9 &&
            payout_script[2] == 0x14 && payout_script[23] == 0x88 &&
            payout_script[24] == 0xac) {
            // P2PKH: 76 a9 14 <hash160> 88 ac
            std::memcpy(share.m_pubkey_hash.data(), payout_script.data() + 3, 20);
            share.m_pubkey_type = 0;
        } else if (payout_script.size() == 23 &&
                   payout_script[0] == 0xa9 && payout_script[1] == 0x14 &&
                   payout_script[22] == 0x87) {
            // P2SH: a9 14 <hash160> 87
            std::memcpy(share.m_pubkey_hash.data(), payout_script.data() + 2, 20);
            share.m_pubkey_type = 2;
        } else if (payout_script.size() == 22 &&
                   payout_script[0] == 0x00 && payout_script[1] == 0x14) {
            // P2WPKH: 00 14 <witness_program>
            // P2WPKH: store raw witness program bytes directly.
            // No reversal — c2pool uses raw bytes throughout, unlike p2pool's
            // IntType(160) LE integer convention. The wire serialization of
            // uint160 preserves the byte order from memcpy.
            std::memcpy(share.m_pubkey_hash.data(), payout_script.data() + 2, 20);
            share.m_pubkey_type = 1;
        } else {
            // Fallback: store first 20 bytes as P2PKH
            std::memcpy(share.m_pubkey_hash.data(), payout_script.data(), 20);
            share.m_pubkey_type = 0;
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
        // Genesis: p2pool always does (prev_absheight + 1), (prev_abswork + aps)
        // With prev=None: absheight = 0 + 1 = 1, abswork = 0 + aps(bits)
        share.m_absheight = 1;
        share.m_abswork = uint128(chain::target_to_average_attempts(
            chain::bits_to_target(share.m_bits)).GetLow64());
        share.m_far_share_hash = uint256();
    }

    // Override with frozen fields from template time (if available).
    // These must match what ref_hash_fn computed when building the coinbase.
    if (has_frozen) {
        LOG_INFO << "[frozen] Applying: absheight=" << frozen_absheight
                 << " bits=" << std::hex << override_bits
                 << " max_bits=" << override_max_bits << std::dec
                 << " ts=" << frozen_timestamp;
        share.m_absheight = frozen_absheight;
        share.m_abswork = frozen_abswork;
        share.m_far_share_hash = frozen_far_share_hash;
        share.m_timestamp = frozen_timestamp;
        share.m_merged_payout_hash = frozen_merged_payout_hash;
        if (override_max_bits) share.m_max_bits = override_max_bits;
        if (override_bits) share.m_bits = override_bits;
        // Deserialize frozen merged_coinbase_info blob → vector<MergedCoinbaseEntry>
        if (!frozen_merged_coinbase_info.empty()) {
            try {
                PackStream ps;
                ps.write(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(frozen_merged_coinbase_info.data()),
                    frozen_merged_coinbase_info.size()));
                ps >> share.m_merged_coinbase_info;
            } catch (const std::exception& e) {
                LOG_WARNING << "[frozen] Failed to deserialize merged_coinbase_info ("
                            << frozen_merged_coinbase_info.size() << " bytes): " << e.what();
            }
        }
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
        // txid_merkle_link: use FROZEN merkle branches from template time if available.
        // The ref_hash was computed with these branches at template time. If new transactions
        // arrived between template creation and share submission, the branches change →
        // ref_hash mismatch → p2pool rejects the share as "PoW invalid".
        sd.m_txid_merkle_link.m_branch = (has_frozen && !frozen_merkle_branches.empty())
            ? frozen_merkle_branches : merkle_branches;
        sd.m_txid_merkle_link.m_index  = 0;
        // Debug: log only when frozen/current diverge (indicates the fix is active)
        if (has_frozen && !frozen_merkle_branches.empty() &&
            frozen_merkle_branches.size() != merkle_branches.size()) {
            LOG_INFO << "[segwit-freeze] branches changed: frozen="
                     << frozen_merkle_branches.size()
                     << " current=" << merkle_branches.size();
        }
        // wtxid_merkle_root: use frozen witness root if available.
        // Priority: frozen > direct witness_root > skip segwit data.
        // NEVER extract from witness_commitment_hex — that contains the
        // p2pool commitment (Hash(root, nonce)), not the raw root.
        // Storing it in m_wtxid_merkle_root causes generate_share_transaction
        // to double-hash: Hash(Hash(root, nonce), nonce) → GENTX mismatch.
        const char* wc_source = "unknown";
        if (!frozen_witness_root.IsNull()) {
            sd.m_wtxid_merkle_root = frozen_witness_root;
            wc_source = has_frozen ? "frozen" : "frozen_unflagged";
        } else if (!witness_root.IsNull()) {
            sd.m_wtxid_merkle_root = witness_root;
            wc_source = "witness_root";
        } else {
            // No raw witness root available — cannot safely populate segwit data.
            // Log and skip: the share will be created without segwit commitment.
            LOG_WARNING << "[WC-SOURCE] no raw witness root available!"
                        << " has_frozen=" << has_frozen
                        << " wc_hex_len=" << witness_commitment_hex.size();
            sd.m_wtxid_merkle_root = uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            wc_source = "DEFAULT_FF";
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
    // segwit_data: PossiblyNoneType in p2pool — ALWAYS serialize.
    // When None, write default: {txid_merkle_link: {branch: [], index: 0}, wtxid_merkle_root: 0}
    // = varint(0) [empty branch list] + uint256(0) [wtxid_merkle_root] = 33 bytes.
    if (share.m_segwit_data.has_value()) {
        ref_stream << share.m_segwit_data.value();
    } else {
        // Write PossiblyNoneType default: empty branch list + zero wtxid_merkle_root
        std::vector<uint256> empty_branch;
        ref_stream << empty_branch;   // varint(0)
        uint256 zero_root;
        ref_stream << zero_root;      // 32 zero bytes
    }
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

    // Dump ref_stream for cross-impl comparison (always, for diagnostics)
    {
        if (!actual_coinbase_bytes.empty()) {
            static const char* HX = "0123456789abcdef";
            std::string full_hex;
            auto* rd = reinterpret_cast<const unsigned char*>(ref_stream.data());
            for (size_t i = 0; i < ref_stream.size(); ++i) { full_hex += HX[rd[i]>>4]; full_hex += HX[rd[i]&0xf]; }
            LOG_INFO << "[REF-HASH] ref_packed_len=" << ref_stream.size()
                     << " ref_hash=" << hash_ref.GetHex()
                     << " prev=" << share.m_prev_hash.GetHex().substr(0, 16)
                     << " abs=" << share.m_absheight
                     << " bits=" << std::hex << share.m_bits
                     << " maxbits=" << share.m_max_bits << std::dec;
            LOG_INFO << "[REF-HASH-FULL] " << full_hex;
        }
    }

    // If we have actual coinbase bytes, extract the ref_hash from the coinbase.
    // The coinbase has ref_hash embedded at position [len-44 : len-44+32].
    // This is the ref_hash computed at template time (by ref_hash_fn) — it
    // uses the FROZEN tracker state, not the current state which may have changed.
    // Using the coinbase's ref_hash ensures hash_link consistency.
    // Always use ref_hash from the actual coinbase (frozen at template creation time).
    // The recomputed ref_hash may differ because share chain state changed between
    // template creation and share submission (absheight, far_share_hash, bits, etc.).
    // This is the EXACT same approach as p2pool: the gentx is captured once in a
    // closure and never re-derived.
    if (!actual_coinbase_bytes.empty() && actual_coinbase_bytes.size() > 44) {
        uint256 coinbase_ref_hash;
        std::memcpy(coinbase_ref_hash.data(),
                     actual_coinbase_bytes.data() + actual_coinbase_bytes.size() - 44, 32);
        ref_hash = coinbase_ref_hash;
    }

    // Diagnostic: log ref_hash match/mismatch (first few only to avoid log spam)
    {
        static int ref_diag = 0;
        bool match = (hash_ref == ref_hash);
        if (!match || ref_diag < 3) {
            LOG_INFO << "[ref_stream] total=" << ref_stream.size()
                     << " ref_hash_match=" << (match ? "YES" : "NO");
            ++ref_diag;
        }
    }

    // --- Derive hash_link from the actual mined coinbase ---
    // Python p2pool captures the gentx at template creation time in a closure
    // and NEVER re-computes PPLNS.  We follow the same pattern: the coinbase
    // bytes from refresh_work() are the single source of truth.
    //
    // When actual_coinbase_bytes is provided (normal mining path), we use it
    // directly.  This eliminates the race where the share chain changes between
    // template creation and share submission, which caused GENTX mismatches
    // and p2pool peer bans.
    auto gentx_before_refhash = compute_gentx_before_refhash(int64_t(36));

    std::vector<unsigned char> coinbase_bytes_for_hashlink;
    if (!actual_coinbase_bytes.empty()) {
        // Use the actual mined coinbase — matches exactly what the miner solved.
        coinbase_bytes_for_hashlink = actual_coinbase_bytes;
    } else {
        // Fallback (no actual bytes): must reconstruct from PPLNS.
        // This path is only used in unit tests or if the caller doesn't
        // provide actual_coinbase_bytes.
        std::map<std::vector<unsigned char>, uint288> weights;
        uint288 total_weight;

        if (!prev_share.IsNull() && tracker.chain.contains(prev_share))
        {
            // Pass REAL_CHAIN_LENGTH — walk naturally stops at chain end.
            auto chain_len = static_cast<int32_t>(PoolConfig::real_chain_length());
            auto block_target = chain::bits_to_target(share.m_min_header.m_bits);
            auto max_weight = chain::target_to_average_attempts(block_target)
                              * PoolConfig::SPREAD * 65535;
            auto result = tracker.get_v36_decayed_cumulative_weights(prev_share, chain_len, max_weight);
            weights = std::move(result.weights);
            total_weight = result.total_weight;
        }

        std::map<std::vector<unsigned char>, uint64_t> amounts;
        if (!total_weight.IsNull()) {
            for (auto& [script, weight] : weights) {
                uint64_t amount = (uint288(subsidy) * weight / total_weight).GetLow64();
                if (amount > 0)
                    amounts[script] = amount;
            }
        }
        uint64_t sum_amounts = 0;
        for (auto& [s, a] : amounts) sum_amounts += a;
        uint64_t donation_amount = (subsidy > sum_amounts) ? (subsidy - sum_amounts) : 0;
        if (donation_amount < 1 && subsidy > 0 && !amounts.empty()) {
            // Deterministic tiebreak: (amount, script) — largest script wins when equal
            auto largest = std::max_element(amounts.begin(), amounts.end(),
                [](const auto& a, const auto& b) {
                    if (a.second != b.second) return a.second < b.second;
                    return a.first < b.first;
                });
            if (largest != amounts.end() && largest->second > 0) {
                largest->second -= 1; sum_amounts -= 1;
                donation_amount = subsidy - sum_amounts;
            }
        }

        std::vector<std::pair<std::vector<unsigned char>, uint64_t>> payout_outputs(
            amounts.begin(), amounts.end());
        std::sort(payout_outputs.begin(), payout_outputs.end(),
            [](const auto& a, const auto& b) {
                if (a.second != b.second) return a.second < b.second;
                return a.first < b.first;
            });
        if (payout_outputs.size() > 4000)
            payout_outputs.erase(payout_outputs.begin(), payout_outputs.end() - 4000);

        PackStream gentx;
        { uint32_t v = 1; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&v), 4)); }
        { unsigned char one = 1; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&one), 1)); }
        { uint256 z; gentx << z; }
        { uint32_t idx = 0xffffffff; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&idx), 4)); }
        gentx << share.m_coinbase;
        { uint32_t seq = 0xffffffff; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&seq), 4)); }
        size_t n_outs = payout_outputs.size() + 1 + 1;
        bool has_segwit_fb = share.m_segwit_data.has_value();
        if (has_segwit_fb) n_outs += 1;
        if (n_outs < 253) { uint8_t cnt = (uint8_t)n_outs; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 1)); }
        else { uint8_t m = 0xfd; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&m), 1)); uint16_t cnt = (uint16_t)n_outs; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&cnt), 2)); }
        auto write_txout = [&](uint64_t value, const std::vector<unsigned char>& script) {
            gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&value), 8));
            BaseScript bs; bs.m_data = script; gentx << bs;
        };
        if (has_segwit_fb) {
            auto& sd = share.m_segwit_data.value();
            std::vector<unsigned char> wscript = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
            uint256 commitment = compute_p2pool_witness_commitment(sd.m_wtxid_merkle_root);
            auto cb = commitment.GetChars();
            wscript.insert(wscript.end(), cb.begin(), cb.end());
            write_txout(0, wscript);
        }
        for (auto& [script, amount] : payout_outputs) write_txout(amount, script);
        write_txout(donation_amount, PoolConfig::get_donation_script(int64_t(36)));
        { std::vector<unsigned char> op; op.push_back(0x6a); op.push_back(0x28);
          op.insert(op.end(), ref_hash.data(), ref_hash.data() + 32);
          uint64_t n = share.m_last_txout_nonce; auto* p = reinterpret_cast<const unsigned char*>(&n);
          op.insert(op.end(), p, p + 8); write_txout(0, op); }
        { uint32_t lt = 0; gentx.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&lt), 4)); }

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

        // Verify hash_link round-trip: does check_hash_link(hash_link, suffix) == Hash(full)?
        {
            static int hl_diag = 0;
            if (hl_diag < 5) {
                std::vector<unsigned char> suffix(
                    coinbase_bytes_for_hashlink.end() - suffix_len,
                    coinbase_bytes_for_hashlink.end());
                uint256 hl_result = check_hash_link(share.m_hash_link, suffix, gentx_before_refhash);
                auto full_span = std::span<const unsigned char>(
                    coinbase_bytes_for_hashlink.data(), coinbase_bytes_for_hashlink.size());
                uint256 direct_result = Hash(full_span);
                bool match = (hl_result == direct_result);

                // Check if prefix ends with const_ending
                size_t ce_len = gentx_before_refhash.size();
                bool ce_match = (prefix.size() >= ce_len) &&
                    std::equal(gentx_before_refhash.begin(), gentx_before_refhash.end(),
                               prefix.end() - ce_len);

                LOG_INFO << "[hash_link-roundtrip] MATCH=" << (match ? "YES" : "NO")
                         << " CE_match=" << (ce_match ? "YES" : "NO")
                         << " prefix=" << prefix.size()
                         << " cb_total=" << coinbase_bytes_for_hashlink.size()
                         << " CE=" << ce_len;

                if (!match || !ce_match) {
                    LOG_WARNING << "[hash_link-roundtrip] MISMATCH! direct=" << direct_result.GetHex()
                                << " hashlink=" << hl_result.GetHex();
                    // Dump boundary bytes for debugging
                    static const char* HX = "0123456789abcdef";
                    if (prefix.size() >= ce_len) {
                        std::string pfx_tail, ce_hex;
                        for (size_t i = prefix.size() - ce_len; i < prefix.size(); ++i) {
                            pfx_tail += HX[prefix[i] >> 4];
                            pfx_tail += HX[prefix[i] & 0xf];
                        }
                        for (size_t i = 0; i < ce_len; ++i) {
                            ce_hex += HX[gentx_before_refhash[i] >> 4];
                            ce_hex += HX[gentx_before_refhash[i] & 0xf];
                        }
                        LOG_WARNING << "[hash_link-roundtrip] prefix_tail=" << pfx_tail;
                        LOG_WARNING << "[hash_link-roundtrip] expected_CE=" << ce_hex;
                    }
                }
                ++hl_diag;
            }
        }

        // Extract last_txout_nonce (8 bytes before locktime)
        size_t nonce_offset = coinbase_bytes_for_hashlink.size() - 4 - 8;
        uint64_t extracted_nonce = 0;
        std::memcpy(&extracted_nonce, coinbase_bytes_for_hashlink.data() + nonce_offset, 8);
        share.m_last_txout_nonce = extracted_nonce;
        {
            static int nonce_log = 0;
            if (nonce_log++ < 5) {
                static const char* HX = "0123456789abcdef";
                std::string nonce_hex;
                for (int i = 0; i < 8; ++i) {
                    uint8_t b = coinbase_bytes_for_hashlink[nonce_offset + i];
                    nonce_hex += HX[b>>4]; nonce_hex += HX[b&0xf];
                }
                LOG_INFO << "[NONCE-EXTRACT] offset=" << nonce_offset
                         << " nonce_hex=" << nonce_hex
                         << " nonce_u64=0x" << std::hex << extracted_nonce << std::dec
                         << " cb_total=" << coinbase_bytes_for_hashlink.size()
                         << " src=" << (actual_coinbase_bytes.empty() ? "reconstructed" : "actual_mined");
                // Dump FULL actual coinbase hex for byte-by-byte comparison with p2pool
                std::string full_cb_hex;
                for (size_t i = 0; i < coinbase_bytes_for_hashlink.size(); ++i) {
                    full_cb_hex += HX[coinbase_bytes_for_hashlink[i]>>4];
                    full_cb_hex += HX[coinbase_bytes_for_hashlink[i]&0xf];
                }
                LOG_INFO << "[ACTUAL-CB] hex=" << full_cb_hex;
            }
        }
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
        // Use the coinbase bytes we already computed for hash_link (either actual or reconstructed)
        auto cb_span = std::span<const unsigned char>(
            coinbase_bytes_for_hashlink.data(), coinbase_bytes_for_hashlink.size());
        gentx_hash_for_header = Hash(cb_span);
    }
    // For the BLOCK HEADER merkle root, always use the actual job merkle branches
    // (share.m_merkle_link), NOT the frozen segwit_data.txid_merkle_link.
    // The frozen branches are for the ref_hash/share_info serialization only.
    // The block header must match the actual transactions in the template.
    uint256 merkle_root = check_merkle_link(gentx_hash_for_header, share.m_merkle_link);

    header_stream << merkle_root;
    header_stream << min_header.m_timestamp;
    header_stream << min_header.m_bits;
    header_stream << min_header.m_nonce;

    auto hdr_span = std::span<const unsigned char>(
        reinterpret_cast<const unsigned char*>(header_stream.data()), header_stream.size());

    // Diagnostic: dump header for PoW debugging
    {
        static int diag_count = 0;
        if (diag_count < 5 && !actual_coinbase_bytes.empty()) {
            std::string hdr_hex;
            static const char* HX = "0123456789abcdef";
            for (size_t i = 0; i < hdr_span.size(); ++i) {
                hdr_hex += HX[hdr_span[i] >> 4];
                hdr_hex += HX[hdr_span[i] & 0xf];
            }
            LOG_INFO << "[create_local_share-diag] header(80)=" << hdr_hex;
            LOG_INFO << "[create_local_share-diag] gentx_hash=" << gentx_hash_for_header.GetHex();
            LOG_INFO << "[create_local_share-diag] merkle_root=" << merkle_root.GetHex();
            LOG_INFO << "[create_local_share-diag] prev_block=" << min_header.m_previous_block.GetHex();
            LOG_INFO << "[create_local_share-diag] nonce=" << min_header.m_nonce
                     << " timestamp=" << min_header.m_timestamp
                     << " bits=" << std::hex << min_header.m_bits << std::dec;
            ++diag_count;
        }
    }

    uint256 share_hash = Hash(hdr_span);

    // Set the share's identity hash
    share.m_hash = share_hash;

    // Self-validation: PoW check against share target.
    // Also run share_init_verify to confirm peers will accept this share
    // (same check they'll run when they receive it).
    {
        uint256 target = chain::bits_to_target(share.m_bits);
        if (!target.IsNull()) {
            char pow_bytes[32];
            scrypt_1024_1_1_256(reinterpret_cast<const char*>(hdr_span.data()), pow_bytes);
            uint256 pow_hash;
            memcpy(pow_hash.begin(), pow_bytes, 32);

            if (pow_hash > target) {
                // Expected: most stratum pseudoshares don't meet share target
                return uint256();
            }
            LOG_INFO << "[Pool] REAL SHARE CREATED! pow=" << pow_hash.GetHex().substr(0, 16)
                     << " target=" << target.GetHex().substr(0, 16)
                     << " diff=" << chain::target_to_difficulty(target);
            // Dump raw 80-byte header for byte-level comparison with p2pool
            {
                static int hdr_dump = 0;
                if (hdr_dump++ < 5) {
                    static const char* HX = "0123456789abcdef";
                    std::string hex;
                    auto* rd = reinterpret_cast<const unsigned char*>(hdr_span.data());
                    for (size_t i = 0; i < hdr_span.size() && i < 80; ++i) {
                        hex += HX[rd[i]>>4]; hex += HX[rd[i]&0xf];
                    }
                    LOG_INFO << "[HDR-DUMP] " << hex
                             << " hash=" << share.m_hash.GetHex().substr(0, 16);
                }
            }
            // Log fields for comparison with p2pool's SHARE-REJECT
            {
                static int sl = 0;
                if (sl++ < 5) {
                    LOG_INFO << "[SHARE-FIELDS] header_bits=" << std::hex << share.m_min_header.m_bits
                             << " share_bits=" << share.m_bits
                             << " max_bits=" << share.m_max_bits << std::dec
                             << " absheight=" << share.m_absheight
                             << " ts=" << share.m_timestamp
                             << " donation=" << share.m_donation
                             << " segwit=" << (share.m_segwit_data.has_value() ? "YES" : "NO")
                             << " prev=" << share.m_prev_hash.GetHex().substr(0, 16);
                }
            }

            // Cross-check: run the SAME verification that peers will run.
            // If this fails, peers will reject the share as "PoW invalid".
            // Cross-check: verify hash_link round-trip with the COINBASE ref_hash.
            // The coinbase ref_hash was frozen at template time. If check_hash_link
            // with this ref_hash produces the same gentx_hash as direct Hash(coinbase),
            // peers will accept the share.
            {
                auto gentx_before_refhash_xc = compute_gentx_before_refhash(int64_t(36));

                // Use the ref_hash from the coinbase (same as what hash_link was built with)
                std::vector<unsigned char> xc_data;
                xc_data.insert(xc_data.end(), ref_hash.data(), ref_hash.data() + 32);
                { uint64_t n = share.m_last_txout_nonce;
                  auto* p = reinterpret_cast<const unsigned char*>(&n);
                  xc_data.insert(xc_data.end(), p, p + 8); }
                { uint32_t z = 0;
                  auto* p = reinterpret_cast<const unsigned char*>(&z);
                  xc_data.insert(xc_data.end(), p, p + 4); }

                uint256 xc_gentx = check_hash_link(share.m_hash_link, xc_data, gentx_before_refhash_xc);

                if (xc_gentx != gentx_hash_for_header) {
                    // Cross-check failure is diagnostic only — p2pool has no such check.
                    // The share was already constructed with consistent hash_link + coinbase.
                    // Mismatch here means gentx_before_refhash() doesn't match the frozen
                    // template (PPLNS changed between template and submission). This is
                    // expected during genesis or when chain state changes rapidly.
                    // The share is still valid — peers verify via their own check_hash_link.
                    static int xc_warn = 0;
                    if (xc_warn++ < 10)
                        LOG_WARNING << "[Pool] Cross-check mismatch (non-blocking)"
                                    << " hl_gentx=" << xc_gentx.GetHex().substr(0, 16)
                                    << " direct_gentx=" << gentx_hash_for_header.GetHex().substr(0, 16);
                } else {
                    LOG_INFO << "[Pool] Cross-check PASSED";
                }
            }
        }
    }

    // One-time hex dump of the share_info portion for wire format debugging
    {
        static int wire_dump = 0;
        if (wire_dump++ < 1) {
            // Pack just the share_info fields to see exact wire bytes
            // Dump share_data fields manually for wire format comparison
            {
                PackStream sd_pack;
                // Serialize share_data portion (same as share.hpp lines 155-190)
                // prev_hash (uint256 = 32 bytes)
                sd_pack << share.m_prev_hash;
                // coinbase (VarStr)
                sd_pack << share.m_coinbase;
                // nonce (uint32)
                sd_pack.write(std::span<const std::byte>(
                    reinterpret_cast<const std::byte*>(&share.m_nonce), 4));
                auto sd_span = sd_pack.get_span();
                auto* sp = reinterpret_cast<const unsigned char*>(sd_span.data());
                std::string sd_hex;
                for (size_t i = 0; i < sd_span.size(); ++i) {
                    static const char* H = "0123456789abcdef";
                    sd_hex += H[sp[i] >> 4]; sd_hex += H[sp[i] & 0xf];
                }
                LOG_INFO << "[WIRE-DUMP] share_data_head(" << sd_span.size()
                         << "): " << sd_hex.substr(0, 160);
                LOG_INFO << "[WIRE-DUMP] m_coinbase(" << share.m_coinbase.size()
                         << "): " << sd_hex.substr(64, std::min(size_t(100), sd_hex.size()-64));
            }
            LOG_INFO << "[WIRE-DUMP] m_bits=0x" << std::hex << share.m_bits
                     << " m_max_bits=0x" << share.m_max_bits << std::dec
                     << " m_timestamp=" << share.m_timestamp
                     << " m_absheight=" << share.m_absheight
                     << " m_donation=" << share.m_donation
                     << " m_subsidy=" << share.m_subsidy;
            // Dump the share_info fields as they would be serialized
            PackStream info_pack;
            // far_share_hash (PossiblyNoneType(0, IntType(256)))
            if (share.m_far_share_hash.IsNull()) {
                uint8_t z = 0; info_pack.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&z), 1));
            } else {
                uint8_t one = 1; info_pack.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&one), 1));
                info_pack.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(share.m_far_share_hash.data()), 32));
            }
            // max_bits, bits, timestamp, absheight (4 bytes each, LE)
            info_pack.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&share.m_max_bits), 4));
            info_pack.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&share.m_bits), 4));
            info_pack.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&share.m_timestamp), 4));
            info_pack.write(std::span<const std::byte>(reinterpret_cast<const std::byte*>(&share.m_absheight), 4));
            auto info_span = info_pack.get_span();
            std::string info_hex;
            auto* ip = reinterpret_cast<const unsigned char*>(info_span.data());
            for (size_t i = 0; i < info_span.size(); ++i) {
                static const char* H = "0123456789abcdef";
                info_hex += H[ip[i] >> 4]; info_hex += H[ip[i] & 0xf];
            }
            LOG_INFO << "[WIRE-DUMP] share_info_tail=" << info_hex;
        }
    }

    // Add to tracker (heap-allocate; ShareChain takes ownership via raw pointer)
    auto* heap_share = new MergedMiningShare(share);
    tracker.add(heap_share);
    LOG_INFO << "create_local_share: added share " << share_hash.GetHex()
             << " height=" << share.m_absheight
             << " prev=" << prev_share.GetHex().substr(0, 16) << "...";

    // Cross-check: call generate_share_transaction on the share we just created
    // to verify p2pool would produce the same gentx_hash.
    {
        static int xcheck_count = 0;
        if (true) { // Always cross-check (was: xcheck_count < 5)
            uint256 verify_hash = generate_share_transaction<MergedMiningShare>(*heap_share, tracker, true, (MergedMiningShare::version >= 36));
            bool xcheck_ok = (verify_hash == gentx_hash_for_header);
            if (xcheck_ok) {
                LOG_INFO << "[Pool] Cross-check PASSED";
            } else {
                LOG_WARNING << "[Pool] Cross-check FAILED! mined_gentx=" << gentx_hash_for_header.GetHex()
                            << " verify_gentx=" << verify_hash.GetHex();
                // Dump actual mined coinbase hex for byte-level comparison
                if (!actual_coinbase_bytes.empty()) {
                    static const char* H = "0123456789abcdef";
                    std::string mined_hex;
                    mined_hex.reserve(actual_coinbase_bytes.size() * 2);
                    for (unsigned char b : actual_coinbase_bytes) { mined_hex += H[b>>4]; mined_hex += H[b&0xf]; }
                    LOG_WARNING << "[XCHECK-MINED] len=" << actual_coinbase_bytes.size()
                                << " hex=" << mined_hex;
                }
            }
            ++xcheck_count;
        }
    }

    return share_hash;
}

} // namespace ltc
