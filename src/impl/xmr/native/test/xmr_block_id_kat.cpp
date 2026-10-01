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
//   F. VERSION 1  -- real mainnet v1 bodies (still valid for unmixable
//                    pre-RingCT spends) parse on the PRUNED path with the
//                    chain's id, size and fee, and a block carrying them
//                    evaluates.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_block_eval.hpp"
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

// ---------------------------------------------------------------------------
// F. VERSION-1 TRANSACTIONS ON MAINNET, PRUNED SYNC.
//
// monerod still accepts version 1 for a spend of unmixable pre-RingCT outputs
// (check_tx_inputs: min_tx_version = n_unmixable > 0 ? 1 : 2), and it never
// prunes one: in a prune=true 2004 the "pruned" blob of a v1 transaction is
// the WHOLE transaction, ring signatures included. The pruned parser used to
// assume prefix + rct base and refused the signatures as TrailingBytes, so
// the first block carrying one never connected and every peer that served it
// was banned (mainnet catch-up from the 3765812 anchor, 2026-09-23: halted at
// 3766004).
//
// These three are the bodies peers actually sent, captured from that run.
// Id, size, fee and height are the public chain's (block explorer, read-only),
// not anything this repository computed.
struct V1Golden {
    const char*   txid;
    std::uint64_t height;
    std::size_t   size;
    std::uint64_t fee;
    std::size_t   n_inputs;
    const char*   blob_hex;
};
static const V1Golden V1_MAINNET[] = {
    {"5324630e03948482dc98bdbdc2dd61cffe8c3ccce5ddc87b057679817d755283", 3766838, 684, 14420000ull, 4,
         "01000402c0a5bdf60f0101f01d49cd526e62a5863c8b9e62bb385356b4c910b4fce2f48a15fe591240351002908187ce"
         "1b0100d36bcd4371d542abd42aec912c1c4b5b5d9f838799363e7e95b7ba4a01035fd302a089fab5020100ad2fe08fb3"
         "ab2172935d731feda9d8f7dd28ca593fe752aea980e5779c10d4c602c0a5bdf60f0100459c6fb5e8a281eaf38df88091"
         "6f73e7c5574ac3b392b7e46f1cbbb1b377a290068095f52a03f9286f8e44429a23e55f902746656514c21fd3b8bdc607"
         "71a86e5b67f7efddab6780c8afa02503c32517b45d732205d1e7578f714a785c346b0356c11bd92f2bf54600d2aea756"
         "c880f882ad16030452446d6c4e9f604b7ae3371ecc4088a259162826162364e5339329c3d8140748c09fab030379fbc7"
         "f86dbe4d2590f01fe1c3b3770b101621e9079efa3270a1235e741ce29f4b80cab5ee0103f7c5f82bf617b2661dfe26cd"
         "39129ecccd688e842ba16c020e4b9bc198e962221ad0860303e5ccf34a3d1e844545932372ff14895346f64a5972e458"
         "8bfe1e12af330f5b59c32101011fad80b5e63820bd01fbd93952bfcc1c169997eba696c5696341c071bfdfbf65e88a1e"
         "b5bb38cd0251a0caa5002a09db00ca8cefb5423c25171840ecd3a40fa463a905649326a2ccebf94ac593529b0b26e10c"
         "749c9e98931260efbb95a1096d0b9a77de309bdfa04ac8e0c08c761c3eacd89bea245db8ef3eb3f30f24c50b9e22aaf9"
         "9ee5b2590ac8270a3e559d29ffa5f2bdc7f060a921d53eb42c2c9f0afbe14511b8a6e74a68a93efa7939ac057f42fb57"
         "1aac8710ee2522bfabf7a806e813e67e308461d0ff7fb7689a65c46f018015b5c261a53fc6e859a69e6fdd0b60d091ca"
         "3ad520a22cb714c2153b22db6a278f4a6acf1d78300017e1acf46c00ad5a3a9f87c2705b56e4c944d81485842256ee54"
         "8810d85f4c473509ab593204"},
    {"b29c1c6c9e0cef56d53a2f7e72ce8c4df28303b055a42982484706b416f35040", 3766841, 787, 16460000ull, 5,
         "01000502d0cf9a9d240100fbfd4380237f65f61c0f9d1afb10074198ffa0cf207f3bfd6d53758a938bdfa2029081eee7"
         "230100dc38d5c32b4fb4f468ebe68a0ed0e8491acea9efb73399ad89c90325019a0b4202e0b48b8d210100d3d5227e97"
         "58593709e3aff96d8ce1cb68ecd1c2463834ead6f5a01b11768c0402c0ece68c140100b035ac68223a34e0c683494e98"
         "7e8676b04589d8417c7d3dd0b6a9440c3511930280f18deb0501004cbf647787b6a6b4969ee8ea1be20c65aef03a0b04"
         "e1734113dd636765f5ec9906e0dc2a03b7e51b3b0a2948c3e493ac37bd4a0dae31b2506e2cdf66774370d84068a7df8d"
         "71c0a8a504030ec43e484955d03396a39ae33c8c80d36e5403f046ab49ddb622881fe3282eb0f8808ece1c03ea72e585"
         "b29723ff29e281e8ee9c25e8348d904f489216ee6f35104fd0e94cbab580c2d72f036e2baa164d1842ee0502008648c2"
         "15caef5bb6f78d9837317b788bd4cc6bee23bc80e497d01203c41aadc15c1a1d508572423c6dae86a382599450fa6f5a"
         "9cac08949f150289ba2680d88ee16f0366171fded726ed499d1cfbf330c807251c59374e99ec145453baf40a811f013e"
         "1521016abd28bdab29e8e6cdcbcb1f4d83f5e45f7589a469c33efcf86ee15ede7ea263dc6e87ea17c777482eec8a643c"
         "35835e7db8742644333a3da21b67996d61ca0a4cb7e670a5dd9a3fdd421f49c19f5c1055bda9cbbe63ee5038e03fc513"
         "6a2e0137286800c9562b602bd4b4d159df4bd25844065cc299aa6da3e1e691c00f1202b1ad382853259f3a7f215dcead"
         "a3825d128d29c6968b47ccc63af16d316e4c0302d1fde1b7048b2264b9e87b119f53568320cca77fee2cee666fb70051"
         "892109e5aa797c9ae22ba997ab92a4d9b5eff0978781c9b5d955819cf1515f7932530cbc3df5f2bf04e983f6cfd4650e"
         "86542aeda70f90e70bf6f43e3bb6f61e5da00b2ef16a746e61fa70d7d50c4d0e7ce69bf84d136ad01e89cf9d52dc391f"
         "8cc20c8b7515afbcdfe54529ef83f0ba9fe105201f2a83c11a589eadf9b2894bdd8a05684ac1e6d7824c869b0403a4ca"
         "2ecbe1f0d16045e30a202690b711c338293a04"},
    {"a3ad4afce02073e60b20e6fdc608c5e6d0e5a270ea9dcd7090a7710f251d92da", 3766839, 966, 19340000ull, 5,
         "01000502f0fafbf90801006a922bd495e20fdaff33d1b2aa24079226bc0cb255bc0d4cd4c62b584e9ef66302b0819fa5"
         "100100316f50c81e7a1fd1d474b214996b82162e864f54219857eabeb804136ff70dad02e0a8dae82401002369ff9117"
         "875feec6ef7a643434a374c8e6df1a7c0db442573b2aba4e65a107029ce1a2d60d01000a842da57dbac47557715b7fe1"
         "da870595e1d47d93d46092767d6f503fa3152402afdbc8c00d010005d5e1a047c8e0f94efef31bfe9e00f2e9b6b203bb"
         "b6cef1744a145f95846ce20b8087a70e035e2d38b123eb68595cef87cf6c67d80153088b130784ed15866aabc79d084d"
         "35c7a0f73603c53a2750b1c6c43e6f6ce27198bb4ed0160c3298e6003940cfba2ea2243352139d8827038c455a49f5ec"
         "f0901b108afbec02e1d32c0b5c82a51299f2f81930937544a99d4780bcc1960b030a91f260030cfaa48e80788a14da0b"
         "4492a676fffe70d963a4126799f70613fe289003033634cb3f0689286cbd80702f483b523306f8630b2a659179c9a4c5"
         "a130a7727db15a03e2cb53223aaa0174116464456218f42832df7e31117a6eaf0019f8eef6e73fa4390903b86e840e37"
         "a4b26a0e4ec654d8099b2114681357edad6b450f760e8b6dd88583f0c096b102033c4a83a06295dbeeecd30215a34e9b"
         "d39381e65a7459bdcd36ac98ee0dcbcad7578090dfc04a0337be4f8fd5ae0f849854a0f6f3d82c7614f3ecafc7822a2a"
         "cbd52ca50bbfd131ce80d293ad030371ac99af2c88915c2654b81e3cd42488359ec9150a1242de656a7289833797144a"
         "904e03d0fdc7c08ef29dcabbec07fcf17923f90e84451c71b01e34787b3ab539d829e11f21014f2b2fd0d3c200232905"
         "8bb4272aa09c7dd9bb4c99a435955b2449ad3177a8631174da691aee6810b7fe74b6b3708b4f4b8c8a1da1b91d4af098"
         "aa93eca4a50146d3cb51d8207878dc019ca61b4cf905cc6ef5e1d97eca06854a4e2ceff3a50c49280c8e112873161d81"
         "1687b3452ee1a8d7c344fa4ae07e836d44f18d7176080ecec7229b56a4751bc39a0a03635551373e4ae2b0cacc6569e2"
         "32f8c2acb90e8e467f16919fb50def7caca463221b2e3fc42c8f104f57fad28ecff9195c99065dca4a9f3bcaa989cdf9"
         "a4d16fa8a8af4da5425f0ee0db26e41da95c5af0c504d96e89fe37d7b64745d11ed716ced0f5092c843d29ddd8903b6f"
         "6abae1097f02806f9a4b889eb81f42bdb64b2254d79c65b1fee71a70d436ef335f32f45fcf0a90844115f404003fcd0b"
         "d2eb3d5b7023f450cffa08e461a895d6b0a6c03b940b74e5bb2641a1ca73feb72753c30a4cc455d5711f147166f4823a"
         "50b87841600a"},
};

static void test_v1_mainnet_pruned() {
    std::vector<std::vector<std::uint8_t>> blobs;
    std::vector<BlockHash>                 ids;
    std::uint64_t                          fee_total = 0;
    std::size_t                            size_total = 0, n_key_images = 0;

    for (const V1Golden& g : V1_MAINNET) {
        const unsigned long long h = static_cast<unsigned long long>(g.height);
        std::vector<std::uint8_t> blob;
        checkf(from_hex(g.blob_hex, blob) && blob.size() == g.size,
               "v1 tx at %llu: blob hex decodes to %zu bytes", h, g.size);

        TxWeightInfo info;
        const TxParseStatus st = parse_tx_pruned(blob, info, /*capture=*/true);
        checkf(st == TxParseStatus::Ok, "v1 tx at %llu: pruned parse = %s", h, to_string(st));
        checkf(info.version == 1, "v1 tx at %llu: version %llu", h,
               static_cast<unsigned long long>(info.version));
        checkf(info.n_inputs == g.n_inputs && info.key_images.size() == g.n_inputs,
               "v1 tx at %llu: %zu inputs", h, info.n_inputs);
        std::size_t ring_total = 0;
        for (std::uint64_t r : info.ring_sizes) ring_total += static_cast<std::size_t>(r);
        checkf(info.prunable_size == 64 * ring_total && !info.prunable_predicted,
               "v1 tx at %llu: signatures measured (%zu bytes)", h, info.prunable_size);
        checkf(info.blob_size == g.size && info.weight == g.size,
               "v1 tx at %llu: weight %llu, the chain says %zu", h,
               static_cast<unsigned long long>(info.weight), g.size);
        checkf(info.fee == g.fee, "v1 tx at %llu: fee %llu, the chain says %llu", h,
               static_cast<unsigned long long>(info.fee), static_cast<unsigned long long>(g.fee));

        // The id is the hash of the whole blob; the wire's prunable hash plays
        // no part for version 1, whatever the peer put there.
        BlockHash junk{};
        junk.fill(0xab);
        const BlockHash id = tx_hash_from_parts(blob.data(), blob.size(), info, junk);
        checkf(to_hex(id) == g.txid, "v1 tx at %llu: id %s, the chain says %s", h,
               to_hex(id).c_str(), g.txid);

        // The full path agrees on every number.
        TxWeightInfo full;
        checkf(parse_tx_full(blob, full) == TxParseStatus::Ok && full.weight == info.weight
                   && full.fee == info.fee
                   && to_hex(tx_hash_full(blob.data(), blob.size(), full)) == g.txid,
               "v1 tx at %llu: full-blob path disagrees", h);

        // Shape is still enforced: a signature short or a byte over is refused.
        std::vector<std::uint8_t> shorter(blob.begin(), blob.end() - 1);
        checkf(parse_tx_pruned(shorter, info) == TxParseStatus::Truncated,
               "v1 tx at %llu: a truncated signature is not refused", h);
        std::vector<std::uint8_t> longer = blob;
        longer.push_back(0x00);
        checkf(parse_tx_pruned(longer, info) == TxParseStatus::TrailingBytes,
               "v1 tx at %llu: a trailing byte is not refused", h);

        fee_total  += g.fee;
        size_total += g.size;
        n_key_images += g.n_inputs;
        ids.push_back(id);
        blobs.push_back(std::move(blob));
    }

    // End to end through the seam that refused them: a block committing to the
    // three ids, served pruned, must evaluate -- weight and fees included, since
    // the coinbase check is exact and a v1 fee left at zero would reject the
    // block one step later.
    std::vector<std::uint8_t> base;
    if (!from_hex(G::BLOCKS[0].blob_hex, base)) { checkf(false, "base block hex"); return; }
    ParsedBlock pb;
    if (parse_block(base, pb) != BlockParseStatus::Ok) { checkf(false, "base block parse"); return; }
    BlockEntry entry;
    entry.pruned = true;
    entry.block_blob.assign(base.begin(),
                            base.begin() + static_cast<std::ptrdiff_t>(pb.miner_tx_offset + pb.miner_tx_size));
    blob_write_varint(entry.block_blob, ids.size());
    for (const BlockHash& id : ids) entry.block_blob.insert(entry.block_blob.end(), id.begin(), id.end());
    for (std::size_t i = 0; i < blobs.size(); ++i) {
        TxBlobEntry te;
        te.blob = blobs[i];
        te.prunable_hash.fill(0);
        te.pruned = true;
        entry.txs.push_back(std::move(te));
    }

    EvaluatedBlock eb;
    std::string why;
    const EvalStatus es = evaluate_block(entry, eb, why);
    checkf(es == EvalStatus::Ok, "a block carrying mainnet v1 bodies evaluates: %s (%s)",
           to_string(es), why.c_str());
    checkf(eb.input.bodies_complete, "and its bodies are complete");
    checkf(eb.input.fees == fee_total, "block fees %llu, the chain's v1 fees sum to %llu",
           static_cast<unsigned long long>(eb.input.fees), static_cast<unsigned long long>(fee_total));
    checkf(eb.input.block_weight == pb.miner_tx.blob_size + size_total,
           "block weight %llu = coinbase + v1 sizes %zu",
           static_cast<unsigned long long>(eb.input.block_weight), pb.miner_tx.blob_size + size_total);
    checkf(eb.key_images.size() == n_key_images, "every v1 key image is surfaced (%zu)",
           eb.key_images.size());
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

    // --- F. version-1 transactions, pruned, against mainnet ------------------
    test_v1_mainnet_pruned();

    std::printf("xmr_block_id_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
