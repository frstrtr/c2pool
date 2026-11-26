// SPDX-License-Identifier: AGPL-3.0-or-later
//
// bip110_block_body_check_kat -- bip110::coin::block_body_matches_header
// (impl/bip110/coin/block_body_check.hpp), the check a pooled block body must
// pass before the coin peer pool connects it to the UTXO view or passes it to
// the mempool.
//
// Proves:
//   [A] a v2 (164-byte header) block whose body matches its header passes,
//       with and without the RDTS cap; its identity is BLAKE2b, not SHA256d.
//   [B] the c2pool-btc checks hold for BIP-110 bodies: a wrong merkle root, a
//       repeated transaction, a second coinbase, witness data without a
//       commitment, and a good / bad BIP 141 commitment.
//   [C] the committed transaction count: a v2 body with one transaction more
//       or fewer than m_txcount fails although every c2pool-btc check passes
//       (a body valid for Bitcoin, invalid for BIP-110); m_txcount is part of
//       the block identity; a v1 header commits no count.
//   [D] the RDTS weight cap: block_weight is BIP 141 weight of the whole block
//       (4 x header and count bytes, a v2 header is 164 bytes); a v2 body over
//       800000 WU fails while the cap applies and passes once it does not; one
//       of exactly 800000 WU passes.
//   [E] when the cap applies: a v2 block whose parent's median time past is
//       before RDTS_EXPIRY_TIME, or unknown; not at or after it; never a v1
//       block. parent_median_time_past is Core's median of 11.
//   [F] block_body_rule names the rule a body breaks (the c2pool-btc checks
//       first); BodyRuleAlarm logs a block whose bodies from 2+ peers fail
//       only a BIP-110 rule, once per block and at most every 10 minutes.
//
// Pure decode / hash test: no node, no network.

#include <impl/bip110/coin/block_body_check.hpp>
#include <impl/bip110/coin/block.hpp>
#include <impl/bip110/coin/header_chain.hpp>
#include <impl/bip110/coin/template_builder.hpp>
#include <impl/bip110/coin/transaction.hpp>
#include <impl/bip110/params.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

using namespace bip110::coin;

namespace {

int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

MutableTransaction make_coinbase(uint32_t tag)
{
    MutableTransaction cb;
    TxIn in;
    in.prevout.hash.SetNull();
    in.prevout.index = 0xffffffff;
    in.scriptSig.m_data = {0x03, static_cast<unsigned char>(tag & 0xff),
                           static_cast<unsigned char>((tag >> 8) & 0xff), 0x00};
    in.sequence = 0xffffffff;
    cb.vin.push_back(in);
    TxOut o;
    o.value = 312500000;
    o.scriptPubKey.m_data = {0x76, 0xa9, 0x14};
    o.scriptPubKey.m_data.insert(o.scriptPubKey.m_data.end(), 20, 0x11);
    o.scriptPubKey.m_data.push_back(0x88);
    o.scriptPubKey.m_data.push_back(0xac);
    cb.vout.push_back(o);
    return cb;
}

/// A plain spend of (prev, n) with an output script of `script_size` bytes.
MutableTransaction make_spend(uint32_t n, size_t script_size = 25)
{
    MutableTransaction tx;
    TxIn in;
    in.prevout.hash.SetHex("00000000000000000000000000000000000000000000000000000000000000aa");
    in.prevout.index = n;
    in.scriptSig.m_data = {0x51};
    in.sequence = 0xfffffffe;
    tx.vin.push_back(in);
    TxOut o;
    o.value = 1000;
    o.scriptPubKey.m_data.assign(script_size, 0x51);
    tx.vout.push_back(o);
    return tx;
}

void set_merkle(BlockType& b)
{
    std::vector<uint256> txids;
    for (const auto& tx : b.m_txs)
        txids.push_back(compute_txid(tx));
    b.m_merkle_root = compute_merkle_root(txids);
}

/// A v2 block at `height` with `txs` after the coinbase; m_txcount and the
/// merkle root match.
BlockType make_v2_block(int32_t height, std::vector<MutableTransaction> txs = {})
{
    BlockType b;
    b.m_version = 0x80000000u | 0x20000000u;
    b.m_previous_block.SetHex("0000000000000000000000000000000000000000000000000000000000000abc");
    b.m_timestamp = 1790000000;
    b.m_bits = 0x1d00ffff;
    b.m_nonce = 42;
    b.m_nonce2 = 7;
    b.m_nonce3 = 9;
    b.m_extranonce.fill(0xa5);
    b.m_time_offset = 3;
    b.m_flags = 0;
    b.m_clear_bits = 0;
    b.m_xor_key.fill(0x00);
    b.m_height = height;
    b.m_mm_rhs.SetNull();
    b.m_txs.push_back(make_coinbase(static_cast<uint32_t>(height)));
    for (auto& tx : txs)
        b.m_txs.push_back(std::move(tx));
    b.m_txcount = static_cast<uint16_t>(b.m_txs.size());
    set_merkle(b);
    return b;
}

uint256 sha256d_of_header(const BlockHeaderType& h)
{
    auto packed = pack(h);
    return Hash(packed.get_span());
}

/// Add a BIP 141 commitment to b's coinbase (reserved value 32 zero bytes).
void commit_witness(BlockType& b)
{
    std::vector<uint256> others;
    for (size_t i = 1; i < b.m_txs.size(); ++i)
        others.push_back(Bip110BodyHashes::wtxid(b.m_txs[i]));
    const uint256 root = witness_merkle_root(others);
    std::vector<unsigned char> reserved(32, 0x00);
    const uint256 c = Hash(std::span<const uint8_t>(root.data(), 32),
                           std::span<const uint8_t>(reserved.data(), 32));
    TxOut o;
    o.value = 0;
    o.scriptPubKey.m_data = {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
    o.scriptPubKey.m_data.insert(o.scriptPubKey.m_data.end(), c.data(), c.data() + 32);
    b.m_txs[0].vout.push_back(o);
    b.m_txs[0].vin[0].scriptWitness.stack = {reserved};
    set_merkle(b);
}

bool btc_rules(const BlockType& b)
{
    return btc::coin::basic_block_body_matches_header<Bip110BodyHashes>(b);
}

} // namespace

int run_block_body_check_kat()
{
    // ── [A] a matching v2 body ────────────────────────────────────────────────
    {
        BlockType b = make_v2_block(970000, {make_spend(0), make_spend(1)});
        CHECK(b.is_v2(), "[A] the block header is v2");
        CHECK(block_body_matches_header(b, true), "[A] matching v2 body passes (RDTS cap on)");
        CHECK(block_body_matches_header(b, false), "[A] matching v2 body passes (RDTS cap off)");
        const uint256 id = block_hash(b);
        CHECK(!id.IsNull() && id != sha256d_of_header(b),
              "[A] the v2 block identity is BLAKE2b, not SHA256d(header)");
    }

    // ── [B] the c2pool-btc checks ─────────────────────────────────────────────
    {
        BlockType b = make_v2_block(970001, {make_spend(0), make_spend(1)});
        BlockType bad_root = b;
        bad_root.m_merkle_root.SetHex("00000000000000000000000000000000000000000000000000000000deadbeef");
        CHECK(!block_body_matches_header(bad_root, true), "[B] a wrong merkle root fails");

        BlockType dup = make_v2_block(970001, {make_spend(0), make_spend(0)});
        CHECK(!block_body_matches_header(dup, true), "[B] a repeated transaction fails");

        BlockType two_cb = make_v2_block(970001, {make_coinbase(5)});
        CHECK(!block_body_matches_header(two_cb, true), "[B] a second coinbase fails");

        BlockType empty = b;
        empty.m_txs.clear();
        CHECK(!block_body_matches_header(empty, false), "[B] a body without transactions fails");

        MutableTransaction wit = make_spend(3);
        wit.vin[0].scriptWitness.stack = {std::vector<unsigned char>(72, 0x30)};
        BlockType no_commit = make_v2_block(970001, {wit});
        CHECK(!block_body_matches_header(no_commit, true),
              "[B] witness data without a commitment fails");

        BlockType committed = make_v2_block(970001, {wit});
        commit_witness(committed);
        committed.m_txcount = static_cast<uint16_t>(committed.m_txs.size());
        CHECK(block_body_matches_header(committed, true), "[B] a good BIP 141 commitment passes");
        BlockType wrong = committed;
        wrong.m_txs[1].vin[0].scriptWitness.stack[0][0] ^= 0x01;   // wtxid changes, txid not
        CHECK(!block_body_matches_header(wrong, true), "[B] a wrong BIP 141 commitment fails");
    }

    // ── [C] the committed transaction count ───────────────────────────────────
    {
        BlockType b = make_v2_block(970002, {make_spend(0), make_spend(1)});
        CHECK(txcount_matches(b), "[C] m_txcount == 3 matches a 3-transaction body");
        BlockType more = b;
        more.m_txcount = 4;
        CHECK(btc_rules(more), "[C] m_txcount 4 for 3 txs: every c2pool-btc check passes");
        CHECK(!block_body_matches_header(more, true) && !block_body_matches_header(more, false),
              "[C] ... but the BIP-110 check fails it (valid for Bitcoin, not BIP-110)");
        BlockType fewer = b;
        fewer.m_txcount = 2;
        CHECK(!block_body_matches_header(fewer, true), "[C] m_txcount 2 for 3 txs fails");
        CHECK(block_hash(more) != block_hash(b),
              "[C] m_txcount is part of the block identity (the PoW hash)");

        BlockType v1 = b;
        v1.m_version = 0x20000000u;   // v1: 80-byte header, no committed count
        v1.m_txcount = 0;
        CHECK(!v1.is_v2() && txcount_matches(v1), "[C] a v1 header commits no transaction count");
        CHECK(block_body_matches_header(v1, false), "[C] a matching v1 body passes");
        CHECK(block_hash(v1) == sha256d_of_header(v1), "[C] a v1 identity is SHA256d(header)");
    }

    // ── [D] the RDTS weight cap ───────────────────────────────────────────────
    {
        BlockType small = make_v2_block(970003, {make_spend(0)});
        {
            PackStream ps;
            ps << small;
            CHECK(block_weight(small) == 4 * static_cast<uint64_t>(ps.size()),
                  "[D] no witness: weight == 4 x serialized size");
            CHECK(pack(static_cast<const BlockHeaderType&>(small)).size() == 164,
                  "[D] a v2 header serializes to 164 bytes");
        }
        {
            MutableTransaction wit = make_spend(3);
            wit.vin[0].scriptWitness.stack = {std::vector<unsigned char>(72, 0x30)};
            BlockType w = make_v2_block(970003, {wit});
            commit_witness(w);
            w.m_txcount = static_cast<uint16_t>(w.m_txs.size());
            PackStream full;
            full << w;
            uint64_t base = pack(static_cast<const BlockHeaderType&>(w)).size() + 1;
            for (const auto& tx : w.m_txs)
                base += pack(TX_NO_WITNESS(tx)).size();
            CHECK(block_weight(w) == base * 3 + static_cast<uint64_t>(full.size()),
                  "[D] with witness: weight == 3 x base size + total size");
        }
        // Two transactions of ~100 kB each: base size > 200000 bytes, so the
        // block is over 800000 WU (and under Bitcoin's 4000000 WU).
        BlockType heavy = make_v2_block(970003, {make_spend(0, 100000), make_spend(1, 100000)});
        CHECK(block_weight(heavy) > bip110::RDTS_MAX_BLOCK_WEIGHT
                  && block_weight(heavy) < 4000000u,
              "[D] the heavy block is over 800000 WU and under 4000000 WU");
        CHECK(btc_rules(heavy), "[D] the heavy block passes every c2pool-btc check");
        CHECK(!block_body_matches_header(heavy, true),
              "[D] ... but fails while the RDTS cap applies (valid for Bitcoin, not BIP-110)");
        CHECK(block_body_matches_header(heavy, false), "[D] ... and passes once the cap no longer applies");

        // Exactly at the cap: pad one output until the weight is 800000.
        BlockType edge = make_v2_block(970003, {make_spend(0, 100000)});
        const uint64_t w0 = block_weight(edge);
        const uint64_t room = (bip110::RDTS_MAX_BLOCK_WEIGHT - w0) / 4;
        // Growing the script by `room` bytes adds 4 x room WU, plus the size
        // prefix growth (both 100000 and 100000 + room need a 5-byte prefix).
        edge.m_txs[1].vout[0].scriptPubKey.m_data.resize(100000 + room, 0x51);
        set_merkle(edge);
        const uint64_t w_edge = block_weight(edge);
        CHECK(w_edge <= bip110::RDTS_MAX_BLOCK_WEIGHT && w_edge + 4 > bip110::RDTS_MAX_BLOCK_WEIGHT,
              "[D] the edge block is within 4 WU under or at 800000");
        CHECK(block_body_matches_header(edge, true), "[D] a block at the cap passes");
        BlockType over = edge;
        over.m_txs[1].vout[0].scriptPubKey.m_data.push_back(0x51);
        set_merkle(over);
        CHECK(block_weight(over) > bip110::RDTS_MAX_BLOCK_WEIGHT
                  && !block_body_matches_header(over, true),
              "[D] one byte more is over the cap and fails");
    }

    // ── [E] when the cap applies; the parent's median time past ───────────────
    {
        BlockType v2 = make_v2_block(970004);
        CHECK(rdts_weight_cap_applies(v2, std::nullopt), "[E] unknown median time: the cap applies");
        CHECK(rdts_weight_cap_applies(v2, bip110::RDTS_EXPIRY_TIME - 1),
              "[E] median time before RDTS_EXPIRY_TIME: the cap applies");
        CHECK(!rdts_weight_cap_applies(v2, bip110::RDTS_EXPIRY_TIME),
              "[E] median time at RDTS_EXPIRY_TIME: the cap no longer applies");
        BlockType v1 = v2;
        v1.m_version = 0x20000000u;
        CHECK(!rdts_weight_cap_applies(v1, std::nullopt), "[E] a v1 block: the cap does not apply");

        // A chain of 15 headers with shuffled times; the median of the last 11.
        std::map<uint256, BlockHeaderType> chain;
        uint256 prev;
        std::vector<uint32_t> times = {50, 10, 70, 30, 90, 20, 80, 40, 60, 100, 110, 5, 95, 15, 65};
        for (size_t i = 0; i < times.size(); ++i) {
            BlockHeaderType h;
            h.m_version = 0x20000000u;
            h.m_previous_block = prev;
            h.m_timestamp = 1800000000u + times[i];
            h.m_bits = 0x1d00ffff;
            h.m_nonce = static_cast<uint32_t>(i);
            prev = sha256d_of_header(h);
            chain[prev] = h;
        }
        auto lookup = [&chain](const uint256& h) -> std::optional<BlockHeaderType> {
            auto it = chain.find(h);
            if (it == chain.end()) return std::nullopt;
            return it->second;
        };
        // Last 11: 90 20 80 40 60 100 110 5 95 15 65 -> sorted median = 65.
        const auto mtp = parent_median_time_past(prev, lookup);
        CHECK(mtp && *mtp == 1800000000u + 65, "[E] median of the last 11 timestamps");
        // Only 3 held (the first three headers): median of 50 10 70 = 50.
        std::map<uint256, BlockHeaderType> short_chain;
        uint256 p3;
        for (size_t i = 0; i < 3; ++i) {
            BlockHeaderType h;
            h.m_version = 0x20000000u;
            h.m_previous_block = p3;
            h.m_timestamp = 1800000000u + times[i];
            h.m_bits = 0x1d00ffff;
            h.m_nonce = static_cast<uint32_t>(i);
            p3 = sha256d_of_header(h);
            short_chain[p3] = h;
        }
        auto short_lookup = [&short_chain](const uint256& h) -> std::optional<BlockHeaderType> {
            auto it = short_chain.find(h);
            if (it == short_chain.end()) return std::nullopt;
            return it->second;
        };
        const auto mtp3 = parent_median_time_past(p3, short_lookup);
        CHECK(mtp3 && *mtp3 == 1800000000u + 50, "[E] fewer than 11 held: median of those");
        uint256 unknown;
        unknown.SetHex("00000000000000000000000000000000000000000000000000000000000000ff");
        CHECK(!parent_median_time_past(unknown, lookup), "[E] an unknown parent: no median time");
    }

    // ── [F] the rule a body breaks; the alarm ─────────────────────────────────
    {
        BlockType ok = make_v2_block(970005, {make_spend(0)});
        CHECK(block_body_rule(ok, true) == BodyRule::Ok, "[F] a matching body: ok");
        BlockType root = ok;
        root.m_merkle_root.SetHex("00000000000000000000000000000000000000000000000000000000000000ee");
        root.m_txcount = 9;
        CHECK(block_body_rule(root, true) == BodyRule::Header,
              "[F] a wrong merkle root (and count): the c2pool-btc check is named first");
        BlockType count = ok;
        count.m_txcount = 3;
        CHECK(block_body_rule(count, true) == BodyRule::TxCount, "[F] the committed count");
        BlockType heavy = make_v2_block(970005, {make_spend(0, 100000), make_spend(1, 100000)});
        CHECK(block_body_rule(heavy, true) == BodyRule::Weight
                  && block_body_rule(heavy, false) == BodyRule::Ok,
              "[F] the RDTS weight cap (and none once it no longer applies)");
        CHECK(std::string(body_rule_name(BodyRule::TxCount)) == "committed transaction count"
                  && std::string(body_rule_name(BodyRule::Weight)) == "RDTS weight cap",
              "[F] the rules are named");

        BodyRuleAlarm alarm;
        const auto t0 = BodyRuleAlarm::Clock::time_point{} + std::chrono::hours(10);
        uint256 b1, b2, b3;
        b1.SetHex("00000000000000000000000000000000000000000000000000000000000000b1");
        b2.SetHex("00000000000000000000000000000000000000000000000000000000000000b2");
        b3.SetHex("00000000000000000000000000000000000000000000000000000000000000b3");
        CHECK(!alarm.should_log(b1, BodyRule::TxCount, 1, t0), "[F] one peer: no alarm");
        CHECK(!alarm.should_log(b1, BodyRule::Header, 3, t0),
              "[F] a c2pool-btc check failing: no alarm (the pool's own error covers it)");
        CHECK(alarm.should_log(b1, BodyRule::TxCount, 2, t0), "[F] two peers, only the count: alarm");
        CHECK(!alarm.should_log(b1, BodyRule::TxCount, 3, t0 + std::chrono::hours(1)),
              "[F] the same block again: no second alarm");
        CHECK(!alarm.should_log(b2, BodyRule::Weight, 2, t0 + std::chrono::seconds(599)),
              "[F] another block within 10 minutes: no alarm");
        CHECK(alarm.should_log(b3, BodyRule::Weight, 2, t0 + std::chrono::seconds(600)),
              "[F] after 10 minutes: alarm, the weight rule");
    }

    std::printf("%s\n", g_fail == 0 ? "bip110_block_body_check_kat PASS" : "bip110_block_body_check_kat FAIL");
    return g_fail;
}
