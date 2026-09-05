// AGPL-3.0-or-later. c2pool XMR-lane primitives -- light self-check.
// Exercises the load-bearing paths that do NOT need libsodium: Keccak midstate
// resume == one-shot, tree_root/branch, check_hash, seed_height, pow_select.
// CI target: xmr_primitives_selfcheck (src/impl/xmr/test/CMakeLists.txt). It
// compiles the self-contained vendored C (keccak/hash/tree-hash) + authored
// xmr_blob.cpp; crypto-ops.c / xmr_derivation.cpp (libsodium ed25519) are not
// exercised here. Headers resolve via the global src/ include dir.

#include <cassert>
#include <cstdio>
#include <cstring>
#include <vector>

#include "impl/xmr/coin/xmr_keccak_midstate.hpp"
#include "impl/xmr/coin/xmr_blob.hpp"
#include "impl/xmr/coin/xmr_check_hash.hpp"
#include "impl/xmr/coin/xmr_seedheight.hpp"
#include "impl/xmr/coin/xmr_pow_select.hpp"

using namespace xmr::coin;

static int fails = 0;
#define CHECK(c) do { if(!(c)){ std::printf("FAIL %s:%d  %s\n",__FILE__,__LINE__,#c); ++fails;} } while(0)

static std::vector<unsigned char> pattern(std::size_t n) {
    std::vector<unsigned char> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<unsigned char>((i * 131 + 7) & 0xff);
    return v;
}

int main() {
    // 1) Keccak midstate resume == one-shot, at several split points incl.
    //    non-block-aligned and > one 136-byte block (the coinbase-opening core).
    for (std::size_t total : {40u, 136u, 200u, 300u, 512u}) {
        auto data = pattern(total);
        Hash256 oneshot = keccak256(data);
        for (std::size_t split : {0u, 1u, 135u, 136u, 137u, 200u}) {
            if (split > total) continue;
            KeccakMidstate m;
            m.absorb(data.data(), split);
            auto wire = m.serialize();                       // receipt coinbase-opening head
            KeccakMidstate r = KeccakMidstate::deserialize(wire);
            r.absorb(data.data() + split, total - split);    // absorb the tx_extra tail
            Hash256 resumed = r.finalize_copy();
            CHECK(resumed == oneshot);
            // block-aligned split => 201-byte wire (1 + 0 + 200); else larger.
            if (split % 136 == 0) CHECK(wire.size() == 201);
        }
    }

    // 2) v2 RCTTypeNull coinbase tx hash + tree_root + branch verify.
    {
        auto prefix = pattern(120);
        Hash256 pfx = tx_prefix_hash(prefix);
        Hash256 cb  = coinbase_tx_hash(pfx);                 // tree leaf 0
        std::vector<Hash256> leaves;
        leaves.push_back(cb);
        for (int i = 1; i < 7; ++i) leaves.push_back(keccak256(pattern(32 + i)));
        Hash256 root = tree_root(leaves);
        TreeBranch br;
        CHECK(make_coinbase_branch(leaves, br));
        CHECK(verify_branch(cb, br, root));                  // opening proof holds
        Hash256 tampered = cb; tampered.data()[0] ^= 0x01;
        CHECK(!verify_branch(tampered, br, root));           // and rejects a wrong leaf
        // single-tx block: root == the (only) leaf.
        std::vector<Hash256> one{cb};
        CHECK(tree_root(one) == cb);
    }

    // 3) check_hash: hash*difficulty <= 2^256-1.
    {
        Hash256 zero{};                                      // 0 passes any difficulty
        CHECK(check_hash(zero, 1000000ULL));
        CHECK(check_hash(zero, 0xFFFFFFFFFFFFFFFFULL));
        Hash256 maxh; std::memset(maxh.data(), 0xFF, 32);    // ~2^256-1 fails d>=2
        CHECK(check_hash(maxh, 1ULL));
        CHECK(!check_hash(maxh, 2ULL));
        // 128-bit path delegates to 64-bit when dhi==0.
        CHECK(check_hash(zero, 1000ULL, 0ULL));
        CHECK(!check_hash(maxh, 2ULL, 0ULL));
        // A hash equal to floor(2^256 / d): boundary-ish sanity for small d.
        Hash256 half; std::memset(half.data(), 0x00, 32); half.data()[31] = 0x80; // 2^255
        CHECK(check_hash(half, 1ULL));   // 2^255 * 1 < 2^256
        CHECK(!check_hash(half, 3ULL));  // 3*2^255 > 2^256
    }

    // 4) seed_height (rx-slow-hash.c formula).
    {
        CHECK(rx_seedheight(0) == 0);
        CHECK(rx_seedheight(2112) == 0);                     // <= 2048+64 -> 0
        CHECK(rx_seedheight(2113) == 2048);                  // (2113-65)=2048; 2048&~2047 = 2048
        CHECK(rx_seedheight(4160) == 2048);                  // (4160-65)=4095 &~2047 = 2048
        CHECK(rx_seedheight(4161) == 4096);                  // (4161-65)=4096 &~2047 = 4096
        std::uint64_t s, n; rx_seedheights(4161, s, n);
        CHECK(s == 4096);
        CHECK(n == rx_seedheight(4161 + 64));
    }

    // 5) pow_select fences.
    {
        CHECK(select_pow_algo(11) == PowAlgo::Unsupported);  // pre-RandomX rejected
        CHECK(select_pow_algo(12) == PowAlgo::RandomXv1);    // RX_BLOCK_VERSION
        CHECK(select_pow_algo(16) == PowAlgo::RandomXv1);    // current mainnet top
        CHECK(is_supported_major(16));
        CHECK(!is_supported_major(7));
        CHECK(coinbase_derivation_is_pre_carrot(16));        // CARROT unscheduled -> pre-CARROT
    }

    if (fails == 0) std::printf("ALL PASS (xmr-primitives selfcheck)\n");
    else            std::printf("%d CHECK(s) FAILED\n", fails);
    return fails ? 1 : 0;
}
