// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_block_id_kat.cpp
//
// C2a block identity, pinned against monerod.
//
// The golden carries whole block blobs exactly as a peer would send them, with
// the three values the daemon computed for each: the block id, the coinbase
// transaction hash, and the block weight. Nothing in this repository produced
// those numbers, which is what makes the comparison a pin rather than a mirror.
//
//   A. PARSE      -- every blob parses, and the spans the parser reports add up
//                    to the bytes that are there.
//   B. COINBASE   -- the coinbase re-reads: its txin_gen height is the block's
//                    own height, its outputs sum to the reward monerod reports,
//                    and its weight is its blob size.
//   C. IDENTITY   -- miner_tx_hash, tree root, hashing blob and block id, all
//                    four against the daemon's values.
//   D. NEGATIVES  -- a flipped byte anywhere in the header, the coinbase or a
//                    tx hash changes the id; a truncated blob is refused rather
//                    than half-parsed; trailing bytes are refused.
//   E. VARINT     -- the write-side varint this file carries is byte-identical
//                    to the coin tree's vendored writer over a value sweep, so
//                    the duplication that keeps the parser dependency-free
//                    cannot drift.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/coin/xmr_blob.hpp"
#include "impl/xmr/coin/xmr_keccak_midstate.hpp"
#include "xmr_c2a_golden.hpp"

using namespace c2pool::xmr::native;
namespace G = c2pool::xmr::native::golden_c2a;

static int g_checks = 0;
static int g_fail   = 0;

static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 25) {
            va_list ap;
            va_start(ap, fmt);
            std::vfprintf(stderr, fmt, ap);
            va_end(ap);
            std::fputc('\n', stderr);
        }
    }
}

static bool from_hex(const char* hex, std::vector<std::uint8_t>& out) {
    const std::size_t n = std::strlen(hex);
    if (n % 2) return false;
    out.clear();
    out.reserve(n / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i < n; i += 2) {
        const int a = nib(hex[i]), b = nib(hex[i + 1]);
        if (a < 0 || b < 0) return false;
        out.push_back(static_cast<std::uint8_t>((a << 4) | b));
    }
    return true;
}

static std::string to_hex(const BlockHash& h) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(64);
    for (std::uint8_t b : h) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}

int main() {
    std::printf("xmr_block_id_kat: %zu blocks from %s %s (tip %llu)\n",
                G::BLOCKS_COUNT, G::NETWORK, G::MONEROD_VERSION,
                static_cast<unsigned long long>(G::CAPTURE_TIP));

    for (std::size_t i = 0; i < G::BLOCKS_COUNT; ++i) {
        const G::GoldenBlock& gb = G::BLOCKS[i];
        const unsigned long long h = static_cast<unsigned long long>(gb.height);

        std::vector<std::uint8_t> blob;
        checkf(from_hex(gb.blob_hex, blob), "block %llu: blob hex does not decode", h);
        if (blob.empty()) continue;

        // --- A. parse ---------------------------------------------------------
        ParsedBlock pb;
        const BlockParseStatus st = parse_block(blob, pb);
        checkf(st == BlockParseStatus::Ok, "block %llu: parse = %s", h, to_string(st));
        if (st != BlockParseStatus::Ok) continue;

        checkf(pb.header_size + pb.miner_tx_size + (blob.size() - pb.header_size - pb.miner_tx_size)
                   == blob.size(),
               "block %llu: spans do not cover the blob", h);
        checkf(pb.tx_hashes.size() == gb.num_txes,
               "block %llu: %zu tx hashes, monerod says %u", h, pb.tx_hashes.size(), gb.num_txes);
        checkf(pb.total_tx_count() == gb.num_txes + 1u,
               "block %llu: total tx count", h);
        checkf(pb.header.timestamp == gb.timestamp, "block %llu: timestamp", h);

        // --- B. coinbase ------------------------------------------------------
        CoinbaseFields cf;
        checkf(parse_coinbase_fields(blob.data(), pb, cf), "block %llu: coinbase fields", h);
        checkf(cf.height == gb.height, "block %llu: txin_gen height %llu", h,
               static_cast<unsigned long long>(cf.height));
        checkf(cf.output_sum == gb.reward,
               "block %llu: coinbase pays %llu, monerod reports reward %llu", h,
               static_cast<unsigned long long>(cf.output_sum),
               static_cast<unsigned long long>(gb.reward));
        checkf(pb.miner_tx.is_coinbase, "block %llu: miner tx is not a coinbase", h);
        checkf(pb.miner_tx.weight == pb.miner_tx.blob_size,
               "block %llu: coinbase weight != blob size", h);
        if (gb.num_txes == 0) {
            // With no transactions the block weight IS the coinbase blob size.
            checkf(pb.miner_tx.blob_size == gb.block_weight,
                   "block %llu: coinbase size %zu, monerod block_weight %llu", h,
                   pb.miner_tx.blob_size, static_cast<unsigned long long>(gb.block_weight));
        }

        // --- C. identity ------------------------------------------------------
        const BlockIdentity id = block_identity(blob.data(), pb);
        checkf(to_hex(id.id) == std::string(gb.id_hex),
               "block %llu: id %s != monerod %s", h, to_hex(id.id).c_str(), gb.id_hex);
        checkf(to_hex(id.miner_tx_hash) == std::string(gb.miner_tx_hash_hex),
               "block %llu: miner_tx_hash %s != monerod %s", h,
               to_hex(id.miner_tx_hash).c_str(), gb.miner_tx_hash_hex);

        // The hashing blob is header bytes || tree root || varint(n_tx), and its
        // header part must be the ORIGINAL bytes rather than a re-serialization.
        checkf(id.hashing_blob.size() >= pb.header_size + 32 + 1,
               "block %llu: hashing blob too short", h);
        checkf(std::memcmp(id.hashing_blob.data(), blob.data(), pb.header_size) == 0,
               "block %llu: hashing blob header is not the original bytes", h);
        checkf(std::memcmp(id.hashing_blob.data() + pb.header_size, id.tree_root.data(), 32) == 0,
               "block %llu: tree root not at the header boundary", h);
        {
            std::vector<std::uint8_t> tail;
            blob_write_varint(tail, pb.total_tx_count());
            checkf(id.hashing_blob.size() == pb.header_size + 32 + tail.size()
                       && std::memcmp(id.hashing_blob.data() + pb.header_size + 32,
                                      tail.data(), tail.size()) == 0,
                   "block %llu: hashing blob tail varint", h);
        }
        // The length prefix is load-bearing: hashing the bare blob gives a
        // different id, and that wrong id is what a reader of the formula
        // "id = keccak(hashing blob)" would compute.
        {
            const ::xmr::coin::Hash256 bare =
                ::xmr::coin::keccak256(id.hashing_blob.data(), id.hashing_blob.size());
            checkf(std::memcmp(bare.data(), id.id.data(), 32) != 0,
                   "block %llu: the id equals keccak of the UNPREFIXED hashing blob", h);
        }

        // With no transactions the tree root IS the coinbase hash.
        if (gb.num_txes == 0)
            checkf(id.tree_root == id.miner_tx_hash,
                   "block %llu: single-leaf tree root != coinbase hash", h);
        else
            checkf(!(id.tree_root == id.miner_tx_hash),
                   "block %llu: multi-leaf tree root equals the coinbase hash", h);

        // --- D. negatives -----------------------------------------------------
        // A flipped byte anywhere in the region the id commits to changes it.
        for (std::size_t pos : { std::size_t(0), pb.header_size / 2, pb.header_size - 1,
                                 pb.miner_tx_offset, blob.size() - 1 }) {
            if (pos >= blob.size()) continue;
            std::vector<std::uint8_t> bad = blob;
            bad[pos] ^= 0x01;
            ParsedBlock pb2;
            if (parse_block(bad, pb2) != BlockParseStatus::Ok) continue;   // refused: fine
            const BlockIdentity id2 = block_identity(bad.data(), pb2);
            checkf(!(id2.id == id.id),
                   "block %llu: flipping byte %zu did not change the id", h, pos);
        }
        // Truncation is refused, never half-parsed.
        for (std::size_t cut = 1; cut < blob.size(); cut += (blob.size() / 7) + 1) {
            std::vector<std::uint8_t> shorter(blob.begin(), blob.end() - cut);
            ParsedBlock pb3;
            const BlockParseStatus s3 = parse_block(shorter, pb3);
            checkf(s3 != BlockParseStatus::Ok,
                   "block %llu: a blob short by %zu bytes parsed as Ok", h, cut);
        }
        // Trailing bytes are refused.
        {
            std::vector<std::uint8_t> longer = blob;
            longer.push_back(0x00);
            ParsedBlock pb4;
            checkf(parse_block(longer, pb4) == BlockParseStatus::TrailingBytes,
                   "block %llu: trailing byte not refused", h);
        }
    }

    // --- E. the varint writer, against the coin tree's vendored one -----------
    {
        std::vector<std::uint64_t> vals;
        for (std::uint64_t v = 0; v < 300; ++v) vals.push_back(v);
        for (int shift = 6; shift < 64; ++shift) {
            const std::uint64_t base = static_cast<std::uint64_t>(1) << shift;
            vals.push_back(base - 1);
            vals.push_back(base);
            vals.push_back(base + 1);
        }
        vals.push_back(~static_cast<std::uint64_t>(0));
        int mismatches = 0;
        for (std::uint64_t v : vals) {
            std::vector<std::uint8_t> mine;
            blob_write_varint(mine, v);
            ::xmr::coin::BlobWriter w;
            w.put_varint(v);
            const std::vector<unsigned char>& theirs = w.bytes();
            if (mine.size() != theirs.size()
                || std::memcmp(mine.data(), theirs.data(), mine.size()) != 0)
                ++mismatches;
        }
        checkf(mismatches == 0, "varint writer differs from the vendored writer on %d values",
               mismatches);
    }

    std::printf("xmr_block_id_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
