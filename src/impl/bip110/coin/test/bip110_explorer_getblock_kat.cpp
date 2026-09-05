// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_explorer_getblock_kat — known-answer test for the BIP-110 explorer
// raw-block RETENTION + full-then-partial getblock SERVE path (DASH parity).
//
// The bip110 node already downloads every full block over coin-p2p for its M3
// own-UTXO view and RETAINS the last EXPLORER_DEPTH (288) bodies in the
// UTXOViewDB it already owns (main_bip110.cpp:935-943 full_block subscriber ->
// put_raw_block / prune_raw_blocks). The read-only /api/explorer getblock hook
// (main_bip110.cpp set_explorer_getblock_fn) then serves the FULL body when the
// block is retained and an honest HEADER-PARTIAL when it is not — the exact
// #1460/#99 DASH shape. Both the retention store (core::coin::UTXOViewDB
// put/get/prune_raw_block) and the serve decision (bip110::coin::
// explorer_getblock_body / explorer_header_partial, hoisted verbatim out of the
// main closure) are the SHIPPED primitives — this KAT binds them directly, not a
// re-derivation.
//
// Proves:
//   [A] RETAINED + in-window  -> FULL body: "tx" array present + non-empty,
//       "size" present, coinbase vin decoded; NO "partial"/"unavailable"/"error".
//   [B] retained but BELOW the 288-block window -> HEADER PARTIAL: partial:true,
//       "unavailable" names {tx,nTx,size,strippedsize,weight}, NO "tx", NO
//       "error" (so explorer.py still renders the row), header truth echoed,
//       confirmations = tip - height + 1.
//   [C] in-window but body ABSENT (never stored / get_raw_block miss) -> HEADER
//       PARTIAL (same honest shape).
//   [D] BOUNDED WINDOW: driving put_raw_block + prune_raw_blocks the way the live
//       full_block subscriber does keeps ~EXPLORER_DEPTH recent bodies and prunes
//       everything older — the daemonless storage bound holds.
//
// Pure decode/store test — no node, no network, no consensus/reward/share/
// coinbase/gentx/wire path. A failure is a display-surface regression only.

#include <impl/bip110/coin/explorer_getblock.hpp>
#include <impl/bip110/coin/block.hpp>
#include <impl/bip110/coin/transaction.hpp>
#include <impl/bip110/coin/header_chain.hpp>

#include <core/coin/utxo_view_db.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

using namespace bip110::coin;

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

// Mirrors the EXPLORER_DEPTH constant in main_bip110.cpp:282 (288 = ~2 days at
// 10-min blocks). The retention window this KAT gates.
static constexpr uint32_t EXPLORER_DEPTH = 288;

// P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
static std::vector<unsigned char> p2pkh_spk(unsigned char fill)
{
    std::vector<unsigned char> s;
    s.push_back(0x76); s.push_back(0xa9); s.push_back(0x14);
    s.insert(s.end(), 20, fill);
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

// A minimal but real coinbase-bearing block. Serializes/deserializes round-trip
// through the UTXOViewDB raw-block store, exactly like a coin-p2p full block.
static BlockType make_block()
{
    MutableTransaction cb;                 // default version=2, locktime=0
    {
        TxIn in;
        in.prevout.hash.SetNull();
        in.prevout.index = 0xffffffff;
        in.scriptSig.m_data = {0x03, 0xe8, 0x03, 0x00}; // push BIP34 height stand-in
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
    block.m_version = 0x20000000;          // classic (v1) header, no v2 extension
    block.m_previous_block.SetHex("0000000000000000000000000000000000000000000000000000000000000abc");
    block.m_merkle_root.SetHex("0000000000000000000000000000000000000000000000000000000000000def");
    block.m_timestamp = 1700000000;
    block.m_bits      = 0x1d00ffff;        // a plausible BTC-range compact target
    block.m_nonce     = 42;
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
    uint256 pow_limit;
    pow_limit.SetHex("00000000ffff0000000000000000000000000000000000000000000000000000");

    ExplorerChainParams params;
    params.bech32_hrp = "bc";
    params.p2pkh_ver  = 0x00;
    params.p2sh_ver   = 0x05;
    params.chain_name = "main";

    BlockType block = make_block();
    auto raw = pack_block(block);

    uint256 blk_hash;
    blk_hash.SetHex("00000000000000001111111111111111222222222222222233333333cafebabe");

    const uint32_t H = 1000;   // the retained block's height

    std::string path = "/tmp/bip110_getblock_kat_" + std::to_string(::getpid());
    core::coin::UTXOViewDB udb(path);
    CHECK(udb.open(), "UTXOViewDB opened");

    // Store the block body the way the full_block subscriber does.
    CHECK(udb.put_raw_block(H, raw), "put_raw_block(H) stored");
    {
        auto rt = udb.get_raw_block(H);
        CHECK(rt.has_value() && *rt == raw, "raw block round-trips byte-identical");
    }

    IndexEntry entry = make_entry(block, blk_hash, H);

    // ── [A] RETAINED + in-window -> FULL body ─────────────────────────────
    {
        uint32_t tip = H;   // height == tip: comfortably inside the window
        nlohmann::json j = explorer_getblock_body(
            entry, blk_hash, tip, std::nullopt, pow_limit, udb, EXPLORER_DEPTH, params);
        std::printf("---- [A] full-body getblock ----\n%s\n--------------------------------\n",
                    j.dump(2).c_str());
        CHECK(j.contains("tx") && j["tx"].is_array() && j["tx"].size() == 1, "[A] tx array present, size 1");
        CHECK(j.contains("size"), "[A] size present");
        CHECK(!j.contains("partial"), "[A] no partial flag (full body)");
        CHECK(!j.contains("unavailable"), "[A] no unavailable map (full body)");
        CHECK(!j.contains("error"), "[A] no error key");
        CHECK(j.value("hash", std::string()) == blk_hash.GetHex(), "[A] block hash echoed");
        CHECK(j.value("height", uint32_t{0}) == H, "[A] height echoed");
        // coinbase vin decoded
        CHECK(j["tx"][0].contains("vin") && j["tx"][0]["vin"].is_array()
              && j["tx"][0]["vin"].size() == 1
              && j["tx"][0]["vin"][0].contains("coinbase"), "[A] coinbase vin decoded");
        CHECK(j["tx"][0].contains("vout") && j["tx"][0]["vout"].size() == 1, "[A] coinbase vout decoded");
    }

    // ── [B] retained but BELOW the window -> HEADER PARTIAL ────────────────
    {
        uint32_t tip = H + EXPLORER_DEPTH + 5;  // height < tip - depth -> out of window
        nlohmann::json j = explorer_getblock_body(
            entry, blk_hash, tip, std::nullopt, pow_limit, udb, EXPLORER_DEPTH, params);
        std::printf("---- [B] below-window partial ----\n%s\n----------------------------------\n",
                    j.dump(2).c_str());
        CHECK(j.value("partial", false) == true, "[B] partial:true");
        CHECK(!j.contains("tx"), "[B] NO tx array (never faked)");
        CHECK(!j.contains("error"), "[B] NO error key (row still renders)");
        CHECK(j.contains("unavailable") && j["unavailable"].is_object(), "[B] unavailable map present");
        for (const char* f : {"tx", "nTx", "size", "strippedsize", "weight"})
            CHECK(j["unavailable"].contains(f), (std::string("[B] unavailable names ") + f).c_str());
        // header truth echoed
        CHECK(j.value("hash", std::string()) == blk_hash.GetHex(), "[B] header hash echoed");
        CHECK(j.value("height", uint32_t{0}) == H, "[B] header height echoed");
        CHECK(j.contains("previousblockhash") && j.contains("merkleroot")
              && j.contains("bits") && j.contains("nonce") && j.contains("time")
              && j.contains("version"), "[B] header fields present");
        CHECK(j.contains("difficulty"), "[B] difficulty present");
        CHECK(j.value("confirmations", int64_t{0}) ==
              static_cast<int64_t>(tip) - static_cast<int64_t>(H) + 1, "[B] confirmations = tip-height+1");
    }

    // ── [C] in-window but body ABSENT (get_raw_block miss) -> HEADER PARTIAL ─
    {
        const uint32_t H2 = 2000;  // never stored
        uint256 hash2;
        hash2.SetHex("0000000000000000aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccdeadbeef0");
        IndexEntry entry2 = make_entry(block, hash2, H2);
        uint32_t tip = H2;         // in-window (height == tip) but no body stored
        CHECK(!udb.get_raw_block(H2).has_value(), "[C] body genuinely absent in the DB");
        nlohmann::json j = explorer_getblock_body(
            entry2, hash2, tip, std::nullopt, pow_limit, udb, EXPLORER_DEPTH, params);
        std::printf("---- [C] get-miss partial ----\n%s\n------------------------------\n",
                    j.dump(2).c_str());
        CHECK(j.value("partial", false) == true, "[C] partial:true on body miss");
        CHECK(!j.contains("tx"), "[C] NO tx array");
        CHECK(!j.contains("error"), "[C] NO error key");
        CHECK(j.contains("unavailable"), "[C] unavailable map present");
        CHECK(j.value("hash", std::string()) == hash2.GetHex(), "[C] header hash echoed");
    }

    // ── [D] BOUNDED WINDOW: prune keeps ~EXPLORER_DEPTH recent bodies ──────
    {
        std::string dpath = "/tmp/bip110_getblock_kat_prune_" + std::to_string(::getpid());
        core::coin::UTXOViewDB pdb(dpath);
        CHECK(pdb.open(), "[D] prune DB opened");
        const uint32_t base = 1000;
        const uint32_t top  = 1400;   // 401 bodies; window keeps the last 288
        std::vector<uint8_t> blob = {0xde, 0xad, 0xbe, 0xef};
        for (uint32_t h = base; h <= top; ++h) {
            pdb.put_raw_block(h, blob);
            pdb.prune_raw_blocks(h, EXPLORER_DEPTH);  // drive it like the live subscriber
        }
        // After the incremental drive the cursor is at top - EXPLORER_DEPTH = 1112.
        // Heights below the window are pruned; the tip and recent heights remain.
        CHECK(!pdb.get_raw_block(base).has_value(), "[D] oldest body pruned (out of window)");
        CHECK(!pdb.get_raw_block(top - EXPLORER_DEPTH - 1).has_value(), "[D] body just below window pruned");
        CHECK(pdb.get_raw_block(top).has_value(), "[D] tip body retained");
        CHECK(pdb.get_raw_block(top - EXPLORER_DEPTH).has_value(), "[D] body at window edge retained");
        // Count retained -> ~EXPLORER_DEPTH+1 (the bound holds; not unbounded growth).
        uint32_t retained = 0;
        for (uint32_t h = base; h <= top; ++h)
            if (pdb.get_raw_block(h).has_value()) ++retained;
        std::printf("[D] retained bodies = %u (expect ~%u)\n", retained, EXPLORER_DEPTH + 1);
        CHECK(retained <= EXPLORER_DEPTH + 1, "[D] retained count bounded by window");
    }

    if (g_fail == 0) std::printf("\nALL PASS: bip110 explorer retention + full-then-partial getblock\n");
    else             std::printf("\n%d CHECK(s) FAILED\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
