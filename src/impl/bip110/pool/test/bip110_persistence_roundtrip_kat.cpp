// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_persistence_roundtrip_kat — FINDING C (and the persistence half of
// FINDING A) round-trip KAT: locally-minted shares BELOW the >=50 flush gate
// must survive a restart.
//
// Pre-fix, a low-share-rate node lost recent shares two ways:
//   (1) the local mint path never persisted the share BODY (only handle_shares —
//       the PEER receive path — writes bodies), so even a flushed "verified"
//       flag pointed at a body that was never stored;
//   (2) the verified-status flush was count-gated at >=50 with no periodic and
//       no graceful-shutdown flush, so a node that minted < 50 shares and then
//       stopped flushed nothing.
//
// The fix: verify_and_persist_local_share() stores the body immediately AND
// flushes the verified status on the mint path; NodeImpl::shutdown() (now wired
// into the signal handler) flushes on graceful stop; a periodic timer flushes on
// cadence. This KAT drives a REAL NodeImpl over an isolated LevelDB dir:
//   mint N (< 50) shares -> verify_and_persist each -> shutdown() ->
//   DESTROY the node -> REOPEN a fresh node on the SAME dir -> load_persisted_shares
//   must bring the shares back (chain_size > 0, and the verified flags reload).
//
// RED on the pre-fix tree: create_local_share never stored the body and shutdown
// was never called, so the reopened node's chain_size == 0. GREEN after the fix.

#include "../node.hpp"              // Node / NodeImpl / Config
#include "../share_check.hpp"       // create_local_share
#include "../config_pool.hpp"
#include "../../coin/block.hpp"     // coin::BlockHeaderType

#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/filesystem.hpp>

#include <boost/asio/io_context.hpp>

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

namespace {

int g_fail = 0;
void expect_true(const std::string& name, bool cond)
{
    if (cond) std::printf("  [ok]   %s\n", name.c_str());
    else { std::printf("  [FAIL] %s\n", name.c_str()); ++g_fail; }
}

std::vector<unsigned char> from_hex(const std::string& s)
{
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    std::vector<unsigned char> out; out.reserve(s.size() / 2);
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<unsigned char>((nib(s[i]) << 4) | nib(s[i + 1])));
    return out;
}

const char* HDR_961640 =
    "000000a0657e02138733654183a2c7320d85ca9d743fe139c4bb01000000000000000000"
    "c137a8515a0f6b3aaf6049cc7611787c022ad523d51094be0a0363d0dc0bc768"
    "4dca936a4f8d001a5671798c84daeb494dca936a00000000b1ccf00d030000000000000000"
    "0000001e0300000000000000000000000000000000000068ac0e0000000000000000000000"
    "00000000000000000000000000000000000000000000000000";

// Mint one genesis share (distinct per `salt`) into `tracker`. Returns the hash
// or ZERO on failure. Grinds the header nonce against an easy target.
uint256 mint_one(bip110::pool::ShareTracker& tracker, uint32_t salt)
{
    using namespace bip110::pool;
    namespace coin = bip110::coin;

    std::vector<unsigned char> hdr_bytes = from_hex(HDR_961640);
    coin::BlockHeaderType full;
    { PackStream ps(hdr_bytes); ps >> full; }

    std::vector<unsigned char> payout_script = {
        0x76, 0xa9, 0x14,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,
        0xbb,0xcc,0xdd,0xee,0xff,0x01,0x02,0x03,0x04,0x05,
        0x88, 0xac };
    BaseScript coinbase_bs;
    coinbase_bs.m_data = { 0x03, 0x28,0xab,0x0e, 0x00, 0x00, 0x2f, 0x62, 0x69,
                           0x70, 0x31, 0x31, 0x30, 0x2f, 0x00, 0x00, 0x00, 0x00 };

    // Distinct coinbase (salted last_txout_nonce) so each mint is a unique share.
    const uint64_t nonce = 0x0102030405060708ULL + salt;
    std::vector<unsigned char> actual_coinbase(80, 0xAB);
    for (int i = 0; i < 32; ++i) actual_coinbase[actual_coinbase.size() - 44 + i] = (unsigned char)(0x40 + i);
    std::memcpy(actual_coinbase.data() + actual_coinbase.size() - 12, &nonce, 8);
    for (int i = 1; i <= 4; ++i) actual_coinbase[actual_coinbase.size() - i] = 0;

    uint128 frozen_abswork; frozen_abswork.SetHex("10000000000000309");
    const uint32_t EASY_BITS = 0x207fffff;
    const uint64_t subsidy = 312500000ULL;

    for (uint32_t grind = salt * 300000u; grind < salt * 300000u + 300000u; ++grind) {
        full.m_nonce = grind;
        uint256 h;
        try {
            h = create_local_share(
                tracker, full, coinbase_bs,
                subsidy, uint256(), std::vector<uint256>{}, payout_script,
                66, {}, StaleInfo::none, true, std::string{}, {},
                actual_coinbase, uint256(),
                EASY_BITS, EASY_BITS,
                // Distinct absheight per share (salt=1,2,3): the LevelDB height
                // index is one-hash-per-height, so genesis siblings at the SAME
                // height would collapse to a single reloaded entry. Real chains
                // increment height; give each KAT share a unique height so the
                // round-trip exercises N distinct persisted+reloaded shares.
                /* frozen_absheight */ (int64_t)salt,
                frozen_abswork, uint256(), full.m_timestamp, uint256(),
                true, std::vector<uint256>{}, uint256(), std::vector<unsigned char>{},
                36, 36);
        } catch (const std::exception& e) {
            std::printf("  [FAIL] create_local_share threw: %s\n", e.what());
            ++g_fail; return uint256();
        }
        if (!h.IsNull()) return h;
    }
    return uint256();
}

} // namespace

int main()
{
    using namespace bip110::pool;

    std::printf("bip110_persistence_roundtrip_kat: FINDING C — <50 shares survive restart\n");

    // Isolated LevelDB dir so this never touches a real c2pool datadir.
    auto tmp = std::filesystem::temp_directory_path()
             / ("bip110_persist_kat_" + std::to_string(::getpid()));
    std::error_code ec;
    std::filesystem::remove_all(tmp, ec);
    std::filesystem::create_directories(tmp, ec);
    core::filesystem::set_data_dir(tmp);

    const int N = 3;   // deliberately < 50 (the flush fast-path gate)
    std::vector<uint256> minted;

    // ── Session 1: mint, verify+persist, graceful shutdown ──
    {
        boost::asio::io_context ioc;
        Config cfg;                       // mainnet identity; isolated by tmp dir
        Node node(&ioc, &cfg);

        // Assert against the tracker DIRECTLY (chain/verified sizes) — the
        // lock-free snapshot is only published by run_think() on the compute
        // thread, which this single-threaded KAT never spins; the tracker is the
        // ground truth get_tracker_snapshot() mirrors in production.
        expect_true("[pre] fresh node starts with empty chain",
                    node.tracker().chain.size() == 0);

        for (int i = 0; i < N; ++i) {
            uint256 h = mint_one(node.tracker(), (uint32_t)(i + 1));
            expect_true("[mint] share minted", !h.IsNull());
            if (h.IsNull()) { std::printf("RESULT: FAIL — mint failed.\n"); return 1; }
            // The production mint path calls this INSIDE the exclusive lock; here
            // (single-threaded, no compute thread) the public variant takes the
            // lock itself. It marks verified + persists the BODY + flushes status.
            node.verify_and_persist_local_share(h);
            minted.push_back(h);
        }

        expect_true("[live] chain_size == N after mint",
                    (int)node.tracker().chain.size() == N);
        expect_true("[live] verified_size == N after verify+persist",
                    (int)node.tracker().verified.size() == N);

        // Graceful shutdown — flushes below the >=50 gate (the C fix).
        node.shutdown();
    }

    // ── Session 2: reopen on the SAME dir — shares must reload ──
    {
        boost::asio::io_context ioc2;
        Config cfg2;
        Node node2(&ioc2, &cfg2);        // ctor calls load_persisted_shares()

        int chain_sz    = (int)node2.tracker().chain.size();
        int verified_sz = (int)node2.tracker().verified.size();
        std::printf("  [info] reopened chain_size=%d verified_size=%d\n",
                    chain_sz, verified_sz);
        expect_true("[reload] chain_size > 0 after restart (bodies were persisted)",
                    chain_sz > 0);
        expect_true("[reload] all N minted shares survived", chain_sz == N);
        int reloaded_present = 0;
        for (const auto& h : minted)
            if (node2.tracker().chain.contains(h)) ++reloaded_present;
        expect_true("[reload] every minted hash is back in the chain",
                    reloaded_present == N);
        expect_true("[reload] verified flags reloaded (verified_size > 0)",
                    verified_sz > 0);
    }

    std::filesystem::remove_all(tmp, ec);

    if (g_fail == 0) {
        std::printf("RESULT: PASS — %d minted shares (< 50) persisted and reloaded across a "
                    "restart (body-store on mint + shutdown flush).\n", N);
        return 0;
    }
    std::printf("RESULT: FAIL — %d assertion(s) failed.\n", g_fail);
    return 1;
}
