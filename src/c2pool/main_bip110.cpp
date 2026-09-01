// SPDX-License-Identifier: AGPL-3.0-or-later
// c2pool-bip110 — Bitcoin Knots BLAKE2b hard fork (BIP-110) p2pool node entry.
//
// NEW-LANE slice: BIP-110 replaces Bitcoin's SHA256d proof-of-work with the
// BLAKE2b commitment pipeline (bip110::pow) and caps block weight (RDTS). This
// entrypoint mirrors the c2pool-bch --selftest tier: it drives the LIVE
// consensus path — the CoinParams-bound BLAKE2b block-hash function — against a
// REAL BIP-110 chain block so the coin smoke gate exercises the actual hash,
// not a stub.
//
// TWO MODES:
//   --selftest (default) : build bip110::make_coin_params, hash the real block
//       961640 v2 header through CoinParams::pow_func, and assert it EQUALS the
//       chain's canonical block hash and satisfies its nBits. Network-free.
//   --run                : LABELLED STUB. The production pool run-loop (embedded
//       sharechain peer + Stratum + won-block dispatch) is cloned from the BTC
//       lane in a later slice and needs a Bitcoin Knots 29.4.1 getblocktemplate
//       backend (with the "blake2b" rule) that does not yet exist on the fleet.
//       This mode prints exactly what live deployment still requires and exits
//       non-zero rather than pretend to mine.
//
// PER-COIN ISOLATION: src/impl/bip110 headers + the lane-local BLAKE2b primitive
// only. Links core (uint256/target utils) + btclibs (SHA256) + the isolated
// blake2b.c. No SHA256d/scrypt/X11 lane is touched.

#include <impl/bip110/params.hpp>
#include <impl/bip110/pow.hpp>

#include <core/uint256.hpp>
#include <core/target_utils.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#ifndef C2POOL_VERSION
#define C2POOL_VERSION "dev"
#endif

namespace {

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

void print_banner(const char* argv0)
{
    std::printf(
        "c2pool-bip110 %s — Bitcoin Knots BLAKE2b hard fork (BIP-110)\n\n"
        "Usage: %s [--version] [--help] [--selftest]\n"
        "       %s --run   (stub; needs a Bitcoin Knots 29.4.1 GBT backend)\n\n"
        "PoW: BLAKE2b commitment pipeline (bip110::pow), block hash == PoW hash.\n"
        "Fork: Blake2bHeight = %u; RDTS weight cap = %u WU; network == Bitcoin\n"
        "      mainnet (magic f9beb4d9, ports %u/%u).\n",
        C2POOL_VERSION, argv0, argv0,
        bip110::BLAKE2B_HEIGHT, bip110::RDTS_MAX_BLOCK_WEIGHT,
        bip110::COIN_P2P_PORT, bip110::COIN_RPC_PORT);
}

// Drive the LIVE CoinParams-bound BLAKE2b block-hash path against real block
// 961640 (the first BLAKE2b block; also a Knots checkpoint).
int run_selftest()
{
    core::CoinParams params = bip110::make_coin_params(/*testnet=*/false);

    const std::string header_hex =
        "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc7684dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d0300000000000000000000001e0300000000000000000000000000000000000068ac0e000000000000000000000000000000000000000000000000000000000000000000";
    const std::string canonical =
        "0000000000000050c1e5f69672f459293be14f46e5a494e7a8c8541396f18eeb";
    const uint32_t nbits = 0x1a008d4f;

    std::vector<unsigned char> header = from_hex(header_hex);
    uint256 got = params.block_hash_func(std::span<const unsigned char>(header.data(), header.size()));
    uint256 pow = params.pow_func(std::span<const unsigned char>(header.data(), header.size()));
    uint256 target = chain::bits_to_target(nbits);

    const bool hash_ok = (got.GetHex() == canonical);
    const bool pow_bound = (pow.GetHex() == canonical);  // pow == block hash for BIP-110
    const bool pow_ok = (pow <= target);

    std::printf("[selftest] coin=%s  pow == block_hash (BLAKE2b) bound\n", params.symbol.c_str());
    std::printf("[selftest]   block 961640 hash   = %s\n", got.GetHex().c_str());
    std::printf("[selftest]   canonical (chain)   = %s  match=%s\n",
                canonical.c_str(), hash_ok ? "yes" : "NO");
    std::printf("[selftest]   pow == block_hash   = %s\n", pow_bound ? "yes" : "NO");
    std::printf("[selftest]   PoW <= target(0x%08x) = %s\n", nbits, pow_ok ? "yes" : "NO");
    std::printf("[selftest]   RDTS weight cap     = %u WU\n", params.block_max_weight);
    std::printf("[selftest]   subsidy(961640)     = %llu sat (3.125 BTC)\n",
                (unsigned long long)params.subsidy_func(961640));

    if (hash_ok && pow_bound && pow_ok) {
        std::printf("[selftest] PASS — CoinParams BLAKE2b reproduces the real chain block hash.\n");
        return 0;
    }
    std::printf("[selftest] FAIL — BLAKE2b block hash did not match the chain.\n");
    return 1;
}

int run_stub()
{
    std::printf(
        "c2pool-bip110 --run is not wired yet.\n\n"
        "This slice delivers the BLAKE2b PoW module + KAT-proven coin lane. A live\n"
        "BIP-110 pool still needs:\n"
        "  1. A synced Bitcoin Knots 29.4.1(rc5+) fork-following node as the\n"
        "     getblocktemplate backend, requesting rules [\"segwit\",\"blake2b\"].\n"
        "     (Must NOT reuse a bitcoind datadir pointed at the majority chain.)\n"
        "  2. A BLAKE2b stratum job dialect + BLAKE2b-capable miner clients —\n"
        "     existing SHA256d rigs cannot grind the flags=0 pseudo-header.\n"
        "  3. The BTC-lane pool run-loop cloned onto the 164-byte v2 header\n"
        "     (share types, submitblock serialization).\n"
        "Run --selftest to exercise the BLAKE2b block hash against real chain data.\n");
    return 2;
}

} // namespace

int main(int argc, char** argv)
{
    bool selftest = true;
    bool run = false;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--version") { std::printf("c2pool-bip110 %s\n", C2POOL_VERSION); return 0; }
        if (a == "--help" || a == "-h") { print_banner(argv[0]); return 0; }
        if (a == "--selftest") { selftest = true; run = false; }
        else if (a == "--run") { run = true; selftest = false; }
    }

    print_banner(argv[0]);
    std::printf("\n");
    if (run)
        return run_stub();
    return run_selftest();
}
