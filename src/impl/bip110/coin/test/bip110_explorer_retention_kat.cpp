// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_explorer_retention_kat — known-answer test for the BIP-110 explorer
// raw-block RETENTION seam that runs on EVERY received full block.
//
// This binds the SHIPPED retention decision directly: bip110::coin::
// retain_full_block (explorer_retention.hpp), the exact function the live
// main_bip110.cpp full_block subscriber calls. It is NOT a re-derivation — a
// regression in that function fails this KAT.
//
// The live failure it locks down: the header chain is keyed by the BIP-110 block
// IDENTITY (bip110::coin::block_hash = BLAKE2b at/after the v2 fork), but the old
// subscriber looked the received block up by SHA256d(header) (Hash(packed_hdr)).
// Past the M3 fork EVERY received block is v2, so the SHA256d key never matched
// the BLAKE2b-keyed chain, the height was never resolved, put_raw_block never
// ran, and getblock stayed header-partial for every height including the tip.
//
// Proves:
//   [1] Driving retain_full_block with a REAL post-fork (v2) block resolves the
//       height via the BLAKE2b identity and WRITES the body (put_raw_block) —
//       round-trips byte-identical out of the store.
//   [2] REGRESSION WITNESS: the block's SHA256d(header) differs from its BLAKE2b
//       identity, and a resolver keyed on the SHA256d hash (what the old code
//       used) resolves NOTHING → retain_full_block stores nothing. i.e. the fix
//       is load-bearing; reverting to Hash() reproduces the empty store.
//   [3] The retained body then serves as a FULL getblock (tx array + size, no
//       partial/unavailable/error) — the daemonless explorer end-to-end.
//   [4] BOUNDED WINDOW: driving retain_full_block across > EXPLORER_DEPTH heights
//       keeps ~EXPLORER_DEPTH recent bodies and prunes the rest.
//
// Pure store/decode — no node, no network, no consensus/reward/share/coinbase/
// gentx/wire path. A failure is a display-surface regression only.

#include <impl/bip110/coin/explorer_retention.hpp>
#include <impl/bip110/coin/explorer_getblock.hpp>
#include <impl/bip110/coin/block.hpp>
#include <impl/bip110/coin/transaction.hpp>
#include <impl/bip110/coin/header_chain.hpp>

#include <core/coin/utxo_view_db.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <vector>

using namespace bip110::coin;

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

// Mirrors EXPLORER_DEPTH in main_bip110.cpp:283 (288 = ~2 days at 10-min blocks).
static constexpr uint32_t EXPLORER_DEPTH = 288;

static std::vector<unsigned char> p2pkh_spk(unsigned char fill)
{
    std::vector<unsigned char> s;
    s.push_back(0x76); s.push_back(0xa9); s.push_back(0x14);
    s.insert(s.end(), 20, fill);
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

// A REAL post-fork (v2) block: version bit31 set → is_v2(), 164-byte header, the
// BIP-110 BLAKE2b commitment fields populated (flags=0 → the 80-byte Sia layout,
// which hashes without throwing). Its block_hash() is therefore BLAKE2b, NOT the
// SHA256d of the header — exactly the live post-fork shape.
static BlockType make_v2_block(int32_t height)
{
    MutableTransaction cb;                 // default version=2, locktime=0
    {
        TxIn in;
        in.prevout.hash.SetNull();
        in.prevout.index = 0xffffffff;
        in.scriptSig.m_data = {0x03, 0xe8, 0x03, 0x00}; // BIP34 height stand-in
        in.sequence = 0xffffffff;
        cb.vin.push_back(in);
    }
    {
        TxOut o;
        o.value = 5000000000;              // 50 BTC
        o.scriptPubKey.m_data = p2pkh_spk(0x11);
        cb.vout.push_back(o);
    }

    BlockType block;
    block.m_version = 0x80000000u | 0x20000000u;   // bit31 set → v2 header
    block.m_previous_block.SetHex("0000000000000000000000000000000000000000000000000000000000000abc");
    block.m_merkle_root.SetHex("0000000000000000000000000000000000000000000000000000000000000def");
    block.m_timestamp = 1700000000;
    block.m_bits      = 0x1d00ffff;
    block.m_nonce     = 42;
    // ── v2 extension (present iff bit31 set) ──
    block.m_nonce2     = 7;
    block.m_nonce3     = 9;
    block.m_extranonce.fill(0xa5);
    block.m_time_offset = 3;
    block.m_txcount     = 1;
    block.m_flags       = 0;               // Sia 80-byte layout (no throw)
    block.m_clear_bits  = 0;
    block.m_xor_key.fill(0x00);
    block.m_height      = height;          // must equal the block's height
    block.m_mm_rhs.SetNull();
    block.m_txs.push_back(cb);
    return block;
}

static std::vector<uint8_t> pack_block(const BlockType& b)
{
    PackStream ps;
    ps << b;
    auto span = ps.get_span();
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(span.data()),
        reinterpret_cast<const uint8_t*>(span.data()) + span.size());
}

static uint256 sha256d_of_header(const BlockType& b)
{
    auto packed = pack(static_cast<const BlockHeaderType&>(b));
    return Hash(packed.get_span());
}

static IndexEntry make_entry(const BlockType& b, const uint256& hash, uint32_t height)
{
    IndexEntry e;
    e.header      = static_cast<const BlockHeaderType&>(b);
    e.block_hash  = hash;
    e.height      = height;
    return e;
}

int main()
{
    const uint32_t H = 970000;   // comfortably past the M3 fork (961640)

    BlockType block = make_v2_block(static_cast<int32_t>(H));
    CHECK(block.is_v2(), "block is v2 (post-fork header)");

    // The two candidate keys: BLAKE2b identity (what the chain uses) vs SHA256d
    // of the header (what the old subscriber used).
    uint256 ident   = block_hash(static_cast<const BlockHeaderType&>(block));
    uint256 sha256d = sha256d_of_header(block);
    CHECK(!ident.IsNull(), "BLAKE2b identity hash is real (not the null sentinel)");
    CHECK(ident != sha256d, "[regression] BLAKE2b identity != SHA256d(header) for a v2 block");

    auto raw = pack_block(block);

    std::string path = "/tmp/bip110_retain_kat_" + std::to_string(::getpid());
    core::coin::UTXOViewDB udb(path);
    CHECK(udb.open(), "UTXOViewDB opened");

    // ── [1] retain_full_block with the CORRECT (BLAKE2b-keyed) resolver stores ─
    {
        std::map<uint256, uint32_t> by_ident{{ident, H}};
        auto resolver = [&](const uint256& id) -> std::optional<uint32_t> {
            auto it = by_ident.find(id);
            if (it == by_ident.end()) return std::nullopt;
            return it->second;
        };
        auto stored = retain_full_block(resolver, udb, block, EXPLORER_DEPTH);
        CHECK(stored.has_value() && *stored == H, "[1] retain_full_block resolved height via identity");
        auto rt = udb.get_raw_block(H);
        CHECK(rt.has_value(), "[1] put_raw_block WROTE the body");
        CHECK(rt.has_value() && *rt == raw, "[1] retained body round-trips byte-identical");
    }

    // ── [2] REGRESSION WITNESS: a SHA256d-keyed resolver stores NOTHING ────────
    // This is what the pre-fix subscriber effectively did (look up by Hash()).
    {
        std::string path2 = "/tmp/bip110_retain_kat_sha_" + std::to_string(::getpid());
        core::coin::UTXOViewDB udb2(path2);
        CHECK(udb2.open(), "[2] second UTXOViewDB opened");
        std::map<uint256, uint32_t> by_sha256d{{sha256d, H}};  // the WRONG key
        auto resolver = [&](const uint256& id) -> std::optional<uint32_t> {
            auto it = by_sha256d.find(id);          // retain_full_block queries with the BLAKE2b identity
            if (it == by_sha256d.end()) return std::nullopt;
            return it->second;
        };
        auto stored = retain_full_block(resolver, udb2, block, EXPLORER_DEPTH);
        CHECK(!stored.has_value(), "[2] SHA256d-keyed resolver resolves NOTHING (the live failure)");
        CHECK(!udb2.get_raw_block(H).has_value(), "[2] nothing was stored (getblock would stay header-partial)");
    }

    // ── [3] the retained body serves as a FULL getblock ────────────────────────
    {
        uint256 pow_limit;
        pow_limit.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");
        ExplorerChainParams params;
        params.bech32_hrp = "bc";
        params.p2pkh_ver  = 0x00;
        params.p2sh_ver   = 0x05;
        params.chain_name = "main";

        IndexEntry entry = make_entry(block, ident, H);
        uint32_t tip = H;   // in-window
        nlohmann::json j = explorer_getblock_body(
            entry, ident, tip, std::nullopt, pow_limit, udb, EXPLORER_DEPTH, params);
        std::printf("---- [3] full-body getblock (retained v2 block) ----\n%s\n----\n", j.dump(2).c_str());
        CHECK(j.contains("tx") && j["tx"].is_array() && j["tx"].size() == 1, "[3] tx array present, size 1");
        CHECK(j.contains("size"), "[3] size present");
        CHECK(!j.contains("partial"), "[3] no partial flag (full body served)");
        CHECK(!j.contains("unavailable"), "[3] no unavailable map");
        CHECK(!j.contains("error"), "[3] no error key");
        CHECK(j.value("hash", std::string()) == ident.GetHex(), "[3] block identity echoed");
        CHECK(j.value("height", uint32_t{0}) == H, "[3] height echoed");
        CHECK(j["tx"][0].contains("vin") && j["tx"][0]["vin"].size() == 1
              && j["tx"][0]["vin"][0].contains("coinbase"), "[3] coinbase vin decoded");
    }

    // ── [4] BOUNDED WINDOW: retain across > EXPLORER_DEPTH heights, prune holds ─
    {
        std::string ppath = "/tmp/bip110_retain_kat_prune_" + std::to_string(::getpid());
        core::coin::UTXOViewDB pdb(ppath);
        CHECK(pdb.open(), "[4] prune DB opened");
        const uint32_t base = 962000;
        const uint32_t top  = 962400;   // 401 heights; window keeps the last 288
        for (uint32_t h = base; h <= top; ++h) {
            BlockType b = make_v2_block(static_cast<int32_t>(h));
            uint256 id = block_hash(static_cast<const BlockHeaderType&>(b));
            std::map<uint256, uint32_t> m{{id, h}};
            auto resolver = [&](const uint256& q) -> std::optional<uint32_t> {
                auto it = m.find(q);
                if (it == m.end()) return std::nullopt;
                return it->second;
            };
            auto stored = retain_full_block(resolver, pdb, b, EXPLORER_DEPTH);
            if (!stored.has_value()) { std::printf("FAIL: [4] retain missed at h=%u\n", h); ++g_fail; }
        }
        CHECK(!pdb.get_raw_block(base).has_value(), "[4] oldest body pruned (out of window)");
        CHECK(!pdb.get_raw_block(top - EXPLORER_DEPTH - 1).has_value(), "[4] body just below window pruned");
        CHECK(pdb.get_raw_block(top).has_value(), "[4] tip body retained");
        CHECK(pdb.get_raw_block(top - EXPLORER_DEPTH).has_value(), "[4] window-edge body retained");
        uint32_t retained = 0;
        for (uint32_t h = base; h <= top; ++h)
            if (pdb.get_raw_block(h).has_value()) ++retained;
        std::printf("[4] retained bodies = %u (expect ~%u)\n", retained, EXPLORER_DEPTH + 1);
        CHECK(retained <= EXPLORER_DEPTH + 1, "[4] retained count bounded by window");
    }

    if (g_fail == 0) std::printf("\nALL PASS: bip110 explorer retention seam (v2 identity + bounded window + full serve)\n");
    else             std::printf("\n%d CHECK(s) FAILED\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
