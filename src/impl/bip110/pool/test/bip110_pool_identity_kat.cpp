// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_pool_identity_kat — KILLER known-answer test for the BIP-110 v36
// sharechain lane's ONE consensus delta: the small-header + reconstructed-merkle
// => 164B v2 header => BLAKE2b share-hash == block-identity path (share_identity.hpp).
//
// [A] IDENTITY vs LIVE CHAIN: the canonical 164-byte v2 header of REAL BIP-110
//     block 961640 (the first BLAKE2b block) round-trips through
//     Bip110SmallBlockHeaderType::from_full -> compute_share_hash and reproduces
//     the block's canonical hash BYTE-FOR-BYTE — proving the merkle-drop /
//     merkle-reinsert reconstruction is exact and the share-hash IS the block hash.
// [B] SMALL-HEADER WIRE round-trip (Serialize -> Unserialize) is lossless on all
//     v2 fields.
// [C] FAIL-CLOSED (decision #6): nonzero flags / clear_bits / xor_key are refused.
// [D] SHARE TEMPLATE instantiation: MergedMiningShare / ShareType / ShareChain /
//     ShareIndex compile and default-construct (proves share.hpp is well-formed).

#include "../share_identity.hpp"
#include "../share_types.hpp"
#include "../share.hpp"
#include "../config_pool.hpp"
#include "../donation_consensus.hpp"
#include "../peer.hpp"
#include "../messages.hpp"        // compile-check the full pool wire message set
#include "../../coin/block.hpp"

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

int g_fail = 0;

std::vector<unsigned char> from_hex(const std::string& s)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<unsigned char> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

void expect_eq(const std::string& name, const std::string& got, const std::string& want)
{
    if (got == want) {
        std::printf("  [ok]   %s\n", name.c_str());
    } else {
        std::printf("  [FAIL] %s\n         got : %s\n         want: %s\n",
                    name.c_str(), got.c_str(), want.c_str());
        ++g_fail;
    }
}

void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

// REAL BIP-110 chain block 961640: raw 164-byte v2 header (mempool.guide) + its
// canonical block hash (display byte order). Same vector the M2 bip110_blake2b_kat
// pins — reused here to prove the POOL-LANE reconstruction reproduces it.
const char* HDR_961640 =
    "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000"
    "c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc768"
    "4dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d030000000000000000"
    "0000001e0300000000000000000000000000000000000068ac0e0000000000000000000000"
    "00000000000000000000000000000000000000000000000000";
const char* HASH_961640 =
    "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";

} // namespace

int main()
{
    using namespace bip110::pool;
    namespace coin = bip110::coin;

    std::printf("bip110_pool_identity_kat: BIP-110 v36 sharechain identity delta\n");

    // Parse the real 164B v2 header into a full coin::BlockHeaderType.
    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);

    coin::BlockHeaderType full;
    {
        PackStream ps(hdr_bytes);
        ps >> full;
    }
    expect_true("[pre] parsed header is v2 (version bit31 set)", full.is_v2());
    expect_true("[pre] parsed flags are zero (live block)", full.m_flags == 0);
    // The canonical v2 header re-serializes to exactly 164 bytes.
    { PackStream chk; chk << full; expect_true("[pre] canonical v2 header is 164 bytes", chk.size() == 164); }

    // [A.0] Direct block-hash of the full header reproduces the canonical hash.
    {
        uint256 h = compute_block_hash(full);
        expect_eq("[A.0] compute_block_hash(full 961640) == canonical", h.GetHex(), HASH_961640);
    }

    // [A.1] Drop the merkle root into a small header, then reconstruct + hash.
    //       This is the exact sharechain verify path: min_header + reconstructed
    //       merkle_root -> 164B -> BLAKE2b. Must equal the canonical block hash.
    {
        Bip110SmallBlockHeaderType small = Bip110SmallBlockHeaderType::from_full(full);
        uint256 share_hash = compute_share_hash(small, full.m_merkle_root);
        expect_eq("[A.1] compute_share_hash(small, merkle) == canonical block hash",
                  share_hash.GetHex(), HASH_961640);
    }

    // [A.2] to_full is the exact inverse of from_full (byte-exact header rebuild).
    {
        Bip110SmallBlockHeaderType small = Bip110SmallBlockHeaderType::from_full(full);
        coin::BlockHeaderType rebuilt = small.to_full(full.m_merkle_root);
        PackStream a; a << full;
        PackStream b; b << rebuilt;
        bool same = (a.size() == b.size()) &&
                    (std::memcmp(a.data(), b.data(), a.size()) == 0);
        expect_true("[A.2] to_full(from_full) reproduces the 164B header byte-for-byte", same);
    }

    // [B] Small-header wire round-trip (VarInt version + v2 extension minus merkle).
    {
        Bip110SmallBlockHeaderType small = Bip110SmallBlockHeaderType::from_full(full);
        PackStream s; s << small;
        Bip110SmallBlockHeaderType back;
        { PackStream in(std::span<const std::byte>(s.data(), s.size())); in >> back; }
        bool eq = back.m_version == small.m_version
               && back.m_previous_block == small.m_previous_block
               && back.m_timestamp == small.m_timestamp
               && back.m_bits == small.m_bits
               && back.m_nonce == small.m_nonce
               && back.m_nonce2 == small.m_nonce2
               && back.m_nonce3 == small.m_nonce3
               && back.m_extranonce == small.m_extranonce
               && back.m_time_offset == small.m_time_offset
               && back.m_txcount == small.m_txcount
               && back.m_flags == small.m_flags
               && back.m_clear_bits == small.m_clear_bits
               && back.m_xor_key == small.m_xor_key
               && back.m_height == small.m_height
               && back.m_mm_rhs == small.m_mm_rhs;
        expect_true("[B] Bip110SmallBlockHeaderType serialize/deserialize round-trip", eq);
        // The small-header wire form must be SHORTER than the full header (merkle dropped).
        expect_true("[B] small-header wire omits the 32B merkle root", s.size() + 32 <= 164 + 4 /*varint slack*/);
    }

    // [C] Fail-closed guard on hostile header risk fields (decision #6).
    {
        Bip110SmallBlockHeaderType ok = Bip110SmallBlockHeaderType::from_full(full);
        bool threw = false;
        try { check_header_fail_closed(ok); } catch (...) { threw = true; }
        expect_true("[C] fail-closed PASSES a clean (flags=0) header", !threw);

        Bip110SmallBlockHeaderType bad_flags = ok; bad_flags.m_flags = 1;
        threw = false;
        try { check_header_fail_closed(bad_flags); } catch (const std::invalid_argument&) { threw = true; }
        expect_true("[C] fail-closed REJECTS nonzero flags", threw);

        Bip110SmallBlockHeaderType bad_clear = ok; bad_clear.m_clear_bits = 1;
        threw = false;
        try { check_header_fail_closed(bad_clear); } catch (const std::invalid_argument&) { threw = true; }
        expect_true("[C] fail-closed REJECTS nonzero clear_bits", threw);

        Bip110SmallBlockHeaderType bad_xor = ok; bad_xor.m_xor_key[7] = 0xAB;
        threw = false;
        try { check_header_fail_closed(bad_xor); } catch (const std::invalid_argument&) { threw = true; }
        expect_true("[C] fail-closed REJECTS nonzero xor_key", threw);
    }

    // [D] Share templates instantiate + default-construct (share.hpp well-formed).
    {
        MergedMiningShare s;
        s.m_bits = 0x1a008d4f;
        s.m_max_bits = 0x1a008d4f;
        expect_true("[D] MergedMiningShare version == 36", MergedMiningShare::version == 36);
        expect_true("[D] identity constants: P2P_PORT 9337", PoolConfig::P2P_PORT == 9337);
        expect_true("[D] identity constants: CHAIN_LENGTH 8640 (BTC-verbatim)", PoolConfig::CHAIN_LENGTH == 8640);
        expect_true("[D] identity constants: SPREAD 3 (BTC-verbatim)", PoolConfig::SPREAD == 3);
        expect_true("[D] identity constants: MIN_PROTO 3600 (v36 floor)", PoolConfig::MINIMUM_PROTOCOL_VERSION == 3600);
        expect_true("[D] bootstrap ladder has NO public fallback (empty default seeds)",
                    PoolConfig::default_bootstrap_hosts().empty());
        ShareChain chain;   // instantiate the chain container
        (void)chain;
        // Compile-check the rest of the pool wire surface (peer state, message
        // handler alias, donation validators) so the whole PR-A lane is proven.
        Peer peer; (void)peer;
        using H = Handler; (void)sizeof(H);
        std::vector<consensus::CoinbaseOutput> outs;
        auto dv = consensus::validate_coinbase_total(outs, 5000000000ULL);
        expect_true("[D] donation validators compile + accept empty coinbase", dv.valid);
    }

    if (g_fail == 0) {
        std::printf("RESULT: PASS — BIP-110 v36 sharechain identity delta reproduced (share-hash == block-hash @ 961640).\n");
        return 0;
    }
    std::printf("RESULT: FAIL — %d check(s) failed.\n", g_fail);
    return 1;
}
