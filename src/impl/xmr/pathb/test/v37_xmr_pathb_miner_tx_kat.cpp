// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_pathb_miner_tx_kat (pathb_miner_tx.hpp, pathb_coinbase_split.hpp;
// C37, C25, C07):
//   (1) Monero mainnet blocks 3,755,897, 3,755,902 and 3,774,472: R_tx == r G;
//       every vout (P_i, vt_i) from r and the payee (B_i, A_i); the prefix
//       re-serialized byte for byte (1,927 / 1,966 / 26,268 B); prefix_hash;
//       tx hash; fold over the coinbase branch == tree_root; the hashing blob
//       and the block id; encode_pbx1(16, ...) == the 74-byte extra of the
//       depth-0 blocks; decode_pbx1 refuses the depth-8 extra (MergeMiningDepth).
//   (2) the canonical path self-golden: r, R_tx, both vouts, prefix 167 B,
//       prefix_hash, tx hash, tree_root; finder-only prefix 127 B and tx hash;
//       the NUL-terminated domain, LE64(h) and an unreduced r give other values
//       or no tx.
//   (3) KeyCache: keys once per (tip, P_r), amounts per R; a Monero race gives
//       two key sets; the finder-only key per payee; a digest difference
//       recomputes; the budget changes no outcome.
//   (4) the coinbase check outcomes: Match, Mismatch, Fused, Defer, Undefined.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_blob.hpp"
#include "impl/xmr/pathb/pathb_coinbase_split.hpp"
#include "impl/xmr/pathb/pathb_miner_tx.hpp"
#include "impl/xmr/pathb/pathb_pbx1.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"
#include "pathb_kat_miner.hpp"
#include "pathb_m2_blocks.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

// v37_xmr_pathb_miner_tx_author.cpp: the author references of record.
int author_refs_of_record_kat();

namespace {

// ---- a KAT-local reader of a miner tx (the chain's bytes) ----
struct ParsedTx {
    bool ok = false;
    std::uint64_t version = 0, unlock = 0, vin = 0, height = 0;
    std::uint8_t gen_tag = 0;
    std::vector<pb::MinerOut> outs;
    std::vector<std::uint8_t> extra;
    std::size_t prefix_len = 0;
    std::uint8_t rct_type = 0xff;
};

bool rd_varint(const std::vector<std::uint8_t>& b, std::size_t& pos, std::uint64_t& v) {
    v = 0;
    for (int shift = 0; shift < 64 && pos < b.size(); shift += 7) {
        const std::uint8_t c = b[pos++];
        v |= static_cast<std::uint64_t>(c & 0x7f) << shift;
        if (!(c & 0x80)) return true;
    }
    return false;
}

ParsedTx parse_miner_tx(const std::vector<std::uint8_t>& b) {
    ParsedTx p;
    std::size_t pos = 0;
    std::uint64_t n = 0;
    if (!rd_varint(b, pos, p.version) || !rd_varint(b, pos, p.unlock) || !rd_varint(b, pos, p.vin)) return p;
    if (pos >= b.size()) return p;
    p.gen_tag = b[pos++];
    if (!rd_varint(b, pos, p.height) || !rd_varint(b, pos, n)) return p;
    for (std::uint64_t i = 0; i < n; ++i) {
        pb::MinerOut o;
        if (!rd_varint(b, pos, o.amount) || pos + 1 + 32 + 1 > b.size()) return p;
        if (b[pos++] != 0x03) return p;
        std::memcpy(o.key.data(), b.data() + pos, 32);
        pos += 32;
        o.view_tag = b[pos++];
        p.outs.push_back(o);
    }
    std::uint64_t ne = 0;
    if (!rd_varint(b, pos, ne) || pos + ne > b.size()) return p;
    p.extra.assign(b.begin() + static_cast<std::ptrdiff_t>(pos), b.begin() + static_cast<std::ptrdiff_t>(pos + ne));
    pos += ne;
    p.prefix_len = pos;
    if (pos + 1 != b.size()) return p;
    p.rct_type = b[pos];
    p.ok = true;
    return p;
}

::xmr::coin::Hash256 coin_hash(const pb::Hash32& h) {
    ::xmr::coin::Hash256 c;
    std::memcpy(c.data(), h.data(), 32);
    return c;
}

pb::Hash32 from_coin(const ::xmr::coin::Bytes32& c) {
    pb::Hash32 h{};
    std::memcpy(h.data(), c.data(), 32);
    return h;
}

pb::Hash32 keccak_of(const std::vector<std::uint8_t>& v) { return pb::keccak256_hash(v); }

std::size_t expected_prefix_bytes(std::uint64_t height) {
    switch (height) {
        case 3755897: return 1927;
        case 3755902: return 1966;
        case 3774472: return 26268;
    }
    return 0;
}

// ---- (1) the real blocks ----
void real_blocks() {
    for (const m2::Block& B : m2::kBlocks) {
        const std::string tag = "block " + std::to_string(B.height);
        const std::vector<std::uint8_t> tx = unhex(B.miner_tx);
        const ParsedTx p = parse_miner_tx(tx);
        check(p.ok, tag + ": the miner tx parses (prefix || RCTTypeNull)");
        if (!p.ok) continue;
        check(p.version == 2 && p.vin == 1 && p.gen_tag == 0xff && p.rct_type == 0x00,
              tag + ": version 2, one txin_gen, RCT type 0");
        check(p.height == B.height && p.unlock == B.height + pb::CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
              tag + ": txin_gen height h, unlock h + 60");
        check(p.outs.size() == B.n_payees, tag + ": " + std::to_string(B.n_payees) + " outputs");
        const std::vector<std::uint8_t> prefix(tx.begin(), tx.begin() + static_cast<std::ptrdiff_t>(p.prefix_len));
        check(prefix.size() == expected_prefix_bytes(B.height), tag + ": prefix " + std::to_string(prefix.size()) + " B");

        // R_tx = r G, carried by tx_extra 0x01.
        const pb::Hash32 r = h32(B.r);
        const std::optional<pb::Hash32> r_tx = pb::tx_public_key(r);
        check(r_tx.has_value() && *r_tx == h32(B.r_tx), tag + ": R_tx == r G (" + std::string(B.r_tx).substr(0, 8) + ")");
        bool extra_r = p.extra.size() >= 33 && p.extra[0] == pb::TX_EXTRA_TAG_PUBKEY && r_tx.has_value()
                       && std::memcmp(p.extra.data() + 1, r_tx->data(), 32) == 0;
        check(extra_r, tag + ": tx_extra 01 R_tx");

        // every (P_i, vt_i) from r and (B_i, A_i).
        std::vector<pb::XmrKeyRef> refs(B.n_payees);
        for (std::size_t i = 0; i < B.n_payees; ++i) {
            refs[i].spend = h32(B.payees[i].spend);
            refs[i].view = h32(B.payees[i].view);
        }
        const std::optional<pb::OutputKeys> keys = pb::derive_output_keys_with_r(r, refs);
        check(keys.has_value() && keys->keys.size() == B.n_payees, tag + ": keys derive for every vout");
        if (!keys || keys->keys.size() != p.outs.size()) continue;
        std::size_t bad = 0;
        std::uint64_t sum = 0;
        std::vector<std::uint64_t> amounts;
        for (std::size_t i = 0; i < p.outs.size(); ++i) {
            if (!(keys->keys[i].key == p.outs[i].key) || keys->keys[i].view_tag != p.outs[i].view_tag) ++bad;
            sum += p.outs[i].amount;
            amounts.push_back(p.outs[i].amount);
        }
        check(bad == 0, tag + ": all " + std::to_string(p.outs.size()) + " (P_i, vt_i) == H_s(8 r A_i || i) G + B_i, "
                                   "view_tag(8 r A_i, i) (" + std::to_string(bad) + " differ)");
        if (B.n_payees > 256) {
            for (std::size_t i : {std::size_t{0}, std::size_t{1}, std::size_t{127}, std::size_t{128}, std::size_t{255},
                                  std::size_t{256}, B.n_payees - 1})
                check(keys->keys[i].key == p.outs[i].key && keys->keys[i].view_tag == p.outs[i].view_tag,
                      tag + ": vout " + std::to_string(i) + " key and view tag");
        }
        check(sum == B.reward, tag + ": Sum(vout) == R " + std::to_string(B.reward));

        // the prefix from the coin layer, byte for byte.
        std::vector<pb::MinerOut> outs;
        for (std::size_t i = 0; i < p.outs.size(); ++i)
            outs.push_back(pb::MinerOut{p.outs[i].amount, keys->keys[i].key, keys->keys[i].view_tag});
        const std::vector<std::uint8_t> pre = pb::serialize_miner_tx_prefix(B.height, outs, p.extra);
        check(pre == prefix, tag + ": serialize_miner_tx_prefix == the chain's prefix byte for byte");
        const pb::Hash32 ph = pb::miner_tx_prefix_hash(pre);
        check(ph == h32(B.prefix_hash), tag + ": prefix_hash " + std::string(B.prefix_hash).substr(0, 8));
        const pb::Hash32 txh = pb::miner_tx_hash(ph);
        check(txh == h32(B.miner_tx_hash), tag + ": tx hash " + std::string(B.miner_tx_hash).substr(0, 8));

        // the tree: leaf-0 fold over the branch; the coin layer's tree and branch.
        std::vector<pb::Hash32> branch;
        for (std::size_t i = 0; i < B.depth; ++i) branch.push_back(h32(B.branch[i]));
        check(pb::tree_root_fold(txh, branch) == h32(B.tree_root),
              tag + ": fold(tx hash, branch) == tree_root (D " + std::to_string(B.depth) + ")");
        std::vector<::xmr::coin::Hash256> leaves{coin_hash(txh)};
        for (std::size_t i = 0; i < B.n_tx; ++i) leaves.push_back(coin_hash(h32(B.tx_hashes[i])));
        const ::xmr::coin::Hash256 root = ::xmr::coin::tree_root(leaves);
        check(from_coin(root) == h32(B.tree_root), tag + ": tree_root over the block's txs");
        ::xmr::coin::TreeBranch tb;
        bool br = ::xmr::coin::make_coinbase_branch(leaves, tb) && tb.depth == B.depth;
        for (std::size_t i = 0; br && i < tb.branch.size(); ++i) br = from_coin(tb.branch[i]) == branch[i];
        check(br, tag + ": the coinbase branch of the block's tree");

        // hashing blob and block id.
        const std::vector<unsigned char> hdr = ::xmr::coin::write_block_header_prefix(
                static_cast<std::uint8_t>(B.major), static_cast<std::uint8_t>(B.minor), B.timestamp,
                coin_hash(h32(B.prev_id)), B.nonce);
        const std::vector<unsigned char> blob = ::xmr::coin::assemble_hashing_blob(hdr, root, B.n_tx + 1);
        const std::vector<std::uint8_t> blob8(blob.begin(), blob.end());
        check(blob8 == unhex(B.hashing_blob), tag + ": hashing blob");
        std::vector<std::uint8_t> id_pre;
        pb::detail::put_varint(id_pre, blob8.size());
        id_pre.insert(id_pre.end(), blob8.begin(), blob8.end());
        check(keccak_of(id_pre) == h32(B.id), tag + ": block id " + std::string(B.id).substr(0, 8));

        // PBX1.
        pb::Pbx1 x;
        const pb::Pbx1Error e = pb::decode_pbx1(16, p.extra.data(), p.extra.size(), x);
        std::array<std::uint8_t, pb::kExtraNonceBytes> nonce{};
        const std::vector<std::uint8_t> nb = unhex(B.extra_nonce);
        for (std::size_t i = 0; i < nonce.size(); ++i) nonce[i] = nb[i];
        if (B.mm_depth_byte == 0) {
            check(e == pb::Pbx1Error::None && x.keys.size() == 1 && r_tx && x.keys[0] == *r_tx
                          && x.extra_nonce == nonce && x.mm_root == h32(B.mm_root),
                  tag + ": decode_pbx1(16) == {R_tx, extra_nonce, mm_root}");
            check(r_tx && pb::canonical_tx_extra_hf16(*r_tx, nonce, h32(B.mm_root)) == p.extra && p.extra.size() == 74,
                  tag + ": encode_pbx1(16, R_tx, " + std::string(B.extra_nonce) + ", mm_root) == the 74-byte extra");
            const std::optional<pb::MinerTx> mt = pb::assemble_miner_tx_hf16(B.height, *keys, amounts, nonce,
                                                                             h32(B.mm_root));
            check(mt && mt->prefix == prefix && mt->tx_hash == txh,
                  tag + ": assemble_miner_tx_hf16 == the chain's miner tx");
        } else {
            check(e == pb::Pbx1Error::MergeMiningDepth, tag + ": merge-mining byte 0x08 -> decode_pbx1 MergeMiningDepth");
        }
    }
}

// ---- (2) the canonical path self-golden ----
void self_golden() {
    const pb::Hash32 pool_id = seq32(0x01), tip = seq32(0x21), p_r = seq32(0x41);
    const std::uint64_t h = 3800000, R = 601482200000ull;
    const std::array<std::uint8_t, pb::kExtraNonceBytes> nonce{1, 2, 3, 4};
    const pb::Hash32 mm = seq32(0x61);
    const pb::XmrKeyRef X = ref_from_secrets(11, 13), Y = ref_from_secrets(17, 19);
    RefBook book;
    const pb::Hash32 idX = book.add(X), idY = book.add(Y);
    check(hex32(idY) == "00d7168d925c7aa7057331468ea6b32388299adc84bfcbec6cd55e72b1107789"
                  && hex32(idX) == "16a6f851b82aad9b0c84eb1b1537734b8020fc24f318b003f14fa6f9793a6dce",
          "golden: identities of X (11, 13) and Y (17, 19)");

    const pb::Hash32 r = pb::derive_r_v3(pool_id, tip, p_r, h);
    check(hex32(r) == "cb6a9259be14e60b3b14dda804928313b81630f74b5deecc863713dc5922cf0a", "golden: r");
    const std::optional<pb::Hash32> r_tx = pb::tx_public_key(r);
    check(r_tx && hex32(*r_tx) == "f245798c953b132d47f1b9ab0a97a95d1cf21c005abd2e6166087ce8d8361fcb",
          "golden: R_tx == r G");

    const pb::Window w = window_of({{idX, 120000}, {idY, 100000}});
    const std::vector<pb::SplitOutput> outs = pb::hf16_outputs(R, w);
    check(outs.size() == 2 && outs[0].payee == idY && outs[0].amount == 273401000000ull && outs[1].payee == idX
                  && outs[1].amount == 328081200000ull,
          "golden: vout 0 = Y 273,401,000,000, vout 1 = X 328,081,200,000");
    std::vector<pb::MinerPayee> payees;
    for (const pb::SplitOutput& o : outs) payees.push_back(pb::MinerPayee{book.refs.at(o.payee), o.amount});
    const std::optional<pb::MinerTx> tx = pb::build_miner_tx_hf16(pool_id, tip, p_r, h, payees, nonce, mm);
    check(tx.has_value(), "golden: build_miner_tx_hf16 builds");
    if (tx) {
        check(tx->outs.size() == 2
                      && hex32(tx->outs[0].key) == "caf15c9a94cc015b5765c659b069108a6696cc3ad82c91364630a8f21ca170b5"
                      && tx->outs[0].view_tag == 0x74
                      && hex32(tx->outs[1].key) == "a02b647c9f57c36d21a786e7022ee5bf3a176dc3479cca00deb540ea959b051b"
                      && tx->outs[1].view_tag == 0xbb,
              "golden: (P_0, vt_0) caf15c9a.. 0x74, (P_1, vt_1) a02b647c.. 0xbb");
        check(tx->prefix.size() == 167
                      && hexv(tx->prefix)
                                 == "02fcf7e70101ffc0f7e70102c0e0e0bffa0703caf15c9a94cc015b5765c659b069108a6696cc3ad82c91"
                                    "364630a8f21ca170b57480a7a799c60903a02b647c9f57c36d21a786e7022ee5bf3a176dc3479cca00"
                                    "deb540ea959b051bbb4a01f245798c953b132d47f1b9ab0a97a95d1cf21c005abd2e6166087ce8d836"
                                    "1fcb0204010203040321006162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e"
                                    "7f80",
              "golden: prefix 167 B");
        check(hex32(tx->prefix_hash) == "521ffec98fcbc128437db1c289c2a277972e44ea6af69787db10cdf56850d184",
              "golden: prefix_hash");
        check(hex32(tx->tx_hash) == "4011ea0878ca51e420772efedff6d8ce079105cb157805c4e0770726283cc3ae",
              "golden: tx hash");
        const std::vector<pb::Hash32> branch{seq32(0x81)};
        check(hex32(pb::tree_root_fold(tx->tx_hash, branch))
                      == "79565fffb9c73e9c8d6c3ff885aeea82147336d34f79504236571d18d03840ad",
              "golden: tree_root over branch [seq32(0x81)]");
        // the order rule: swapping the two payees changes the tx hash.
        std::vector<pb::MinerPayee> swapped{payees[1], payees[0]};
        const std::optional<pb::MinerTx> sw = pb::build_miner_tx_hf16(pool_id, tip, p_r, h, swapped, nonce, mm);
        check(sw && !(sw->tx_hash == tx->tx_hash), "golden: identity order descending -> another tx hash");
    }

    // finder-only (empty window): one output of R to X.
    {
        const std::vector<pb::MinerPayee> one{pb::MinerPayee{X, R}};
        const std::optional<pb::MinerTx> f = pb::build_miner_tx_hf16(pool_id, tip, p_r, h, one, nonce, mm);
        check(f && f->prefix.size() == 127
                      && hex32(f->tx_hash) == "bde51e3ec783cb4418c667fbb3d9152c82578d211c8961a6559308cc0cac88e4",
              "golden: finder-only prefix 127 B, tx hash bde51e3e..");
    }

    // other readings of r give other values: the domain with a terminating NUL,
    // LE64(h); r without sc_reduce32 is refused by secret_key_to_public_key.
    {
        auto pre_of = [&](bool nul, bool le64) {
            std::vector<std::uint8_t> pre(pb::kTxKeyDomain.begin(), pb::kTxKeyDomain.end());
            if (nul) pre.push_back(0);
            pre.insert(pre.end(), pool_id.begin(), pool_id.end());
            pre.insert(pre.end(), tip.begin(), tip.end());
            pre.insert(pre.end(), p_r.begin(), p_r.end());
            if (le64)
                for (int i = 0; i < 8; ++i) pre.push_back(static_cast<std::uint8_t>(h >> (8 * i)));
            else
                pb::detail::put_varint(pre, h);
            return pre;
        };
        auto r_of = [](const std::vector<std::uint8_t>& pre) {
            ::xmr::coin::EcScalar s;
            ::xmr::coin::hash_to_scalar(pre.data(), pre.size(), s);
            return from_coin(s);
        };
        const auto rn = pb::tx_public_key(r_of(pre_of(true, false)));
        const auto rl = pb::tx_public_key(r_of(pre_of(false, true)));
        check(rn && r_tx && hex32(*rn).substr(0, 16) == "803cf649ac8a5520" && !(*rn == *r_tx),
              "golden: domain with a NUL -> R_tx 803cf649ac8a5520 (another value)");
        check(rl && r_tx && hex32(*rl).substr(0, 16) == "91148e49b1a15a00" && !(*rl == *r_tx),
              "golden: LE64(h) -> R_tx 91148e49b1a15a00 (another value)");
        const pb::Hash32 unreduced = keccak_of(pre_of(false, false));
        check(!pb::tx_public_key(unreduced).has_value(), "golden: r without sc_reduce32 -> no R_tx (sc_check)");
        check(!pb::derive_output_keys_with_r(unreduced, std::vector<pb::XmrKeyRef>{X}).has_value(),
              "golden: r without sc_reduce32 -> no keys");
    }
}

// ---- (3) KeyCache ----
void key_cache() {
    RefBook book;
    std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
    for (std::uint8_t s = 0; s < 3; ++s) wts.push_back({book.add(key_ref(static_cast<std::uint8_t>(0x10 + 0x20 * s))), 100000u + 7u * s});
    const pb::Window w = window_of(wts);
    const pb::XmrKeyRef author = kat_author();
    const pb::RefLookup refs = book.lookup();
    const pb::Hash32 tip = seq32(0x21), p_r = seq32(0x41), p_r_race = seq32(0x42);

    auto receipt = [&](std::uint8_t seed, std::uint64_t R, const pb::Hash32& pr) {
        pb::ReceiptBodyV3 r = make_body(2, false, seed);
        r.side.tip = tip;
        r.blob.prev_id = pr;
        r.reward_total = R;
        return r;
    };

    // three receipts on one tip and one P_r with three R: keys once, amounts three times.
    {
        pb::KeyCache cache;
        std::vector<pb::MinerTx> txs;
        bool all_match = true;
        for (std::uint64_t R : {600000000000ull, 601000000000ull, 602000000000ull}) {
            pb::ReceiptBodyV3 r = receipt(0x50, R, p_r);
            commit_miner_tx(r, w, tip, p_r, kKatHeight, book, author);
            all_match = all_match && pb::canonical_coinbase_check(r, at_of(&w, tip, 16), tip, p_r, kKatHeight, 16,
                                                                   cache, refs, author)
                                             == pb::CoinbaseCheck::Match;
            const pb::CanonicalTx c =
                    pb::canonical_miner_tx(r, at_of(&w, tip, 16), tip, p_r, kKatHeight, 16, cache, refs, author);
            if (c.tx) txs.push_back(*c.tx);
        }
        check(txs.size() == 3, "key cache: three canonical miner txs built");
        if (txs.size() != 3) return;
        check(all_match, "key cache: three receipts on (tip, P_r) with R 600e9 / 601e9 / 602e9 -> Match");
        check(cache.computations() == 1, "key cache: keys computed once for one (tip, P_r)");
        bool same_keys = true, amounts_differ = true;
        for (std::size_t i = 0; i < txs[0].outs.size(); ++i) {
            same_keys = same_keys && txs[0].outs[i].key == txs[1].outs[i].key && txs[1].outs[i].key == txs[2].outs[i].key
                        && txs[0].outs[i].view_tag == txs[2].outs[i].view_tag;
            amounts_differ = amounts_differ && txs[0].outs[i].amount != txs[1].outs[i].amount
                             && txs[1].outs[i].amount != txs[2].outs[i].amount;
        }
        check(same_keys && amounts_differ, "key cache: identical keys, three sets of amounts");

        // a Monero race at h: the same tip, another P_r -> another key set.
        pb::ReceiptBodyV3 race = receipt(0x51, 600000000000ull, p_r_race);
        commit_miner_tx(race, w, tip, p_r_race, kKatHeight, book, author);
        check(pb::canonical_coinbase_check(race, at_of(&w, tip, 16), tip, p_r_race, kKatHeight, 16, cache, refs, author)
                      == pb::CoinbaseCheck::Match,
              "key cache: the race receipt (another P_r at h) -> Match");
        check(cache.computations() == 2, "key cache: a second key set for the second P_r");
        const pb::CanonicalTx rt =
                pb::canonical_miner_tx(race, at_of(&w, tip, 16), tip, p_r_race, kKatHeight, 16, cache, refs, author);
        check(rt.tx && !(rt.tx->outs[0].key == txs[0].outs[0].key) && !(rt.tx->r_tx == txs[0].r_tx),
              "key cache: the race keys differ");

        // the same (tip, P_r) with another payee list: recomputed, never a verdict.
        RefBook book2 = book;
        std::vector<std::pair<pb::Hash32, std::uint64_t>> wts2 = wts;
        wts2.push_back({book2.add(key_ref(0x70)), 99999});
        const pb::Window w2 = window_of(wts2);
        pb::ReceiptBodyV3 r2 = receipt(0x52, 600000000000ull, p_r);
        commit_miner_tx(r2, w2, tip, p_r, kKatHeight, book2, author);
        const std::uint64_t before = cache.computations();
        check(pb::canonical_coinbase_check(r2, at_of(&w2, tip, 16), tip, p_r, kKatHeight, 16, cache, book2.lookup(),
                                           author)
                      == pb::CoinbaseCheck::Match,
              "key cache: another payee list on the same (tip, P_r) -> Match");
        check(cache.computations() == before + 1, "key cache: a digest difference recomputes");
    }

    // the genesis tip (empty window), one P_r, payees X != Y: keys per payee.
    {
        const pb::Window empty = finder_only_window();
        pb::KeyCache cache;
        pb::ReceiptBodyV3 rx = receipt(0x60, 600000000000ull, p_r);
        pb::ReceiptBodyV3 ry = receipt(0x61, 600000000000ull, p_r);
        check(!(rx.side.payee == ry.side.payee), "finder-only: payees X != Y");
        commit_miner_tx(rx, empty, tip, p_r, kKatHeight, book, author);
        commit_miner_tx(ry, empty, tip, p_r, kKatHeight, book, author);
        bool all = true;
        for (int round = 0; round < 2; ++round) {
            all = all && pb::canonical_coinbase_check(rx, at_of(&empty, tip, 16), tip, p_r, kKatHeight, 16, cache, refs,
                                                      author)
                                 == pb::CoinbaseCheck::Match;
            all = all && pb::canonical_coinbase_check(ry, at_of(&empty, tip, 16), tip, p_r, kKatHeight, 16, cache, refs,
                                                      author)
                                 == pb::CoinbaseCheck::Match;
        }
        check(all, "finder-only: X, Y, X, Y on one (tip, P_r) -> Match each");
        check(cache.computations() == 2, "finder-only: two key computations (keyed by the payee)");
        const auto tx_x = pb::canonical_miner_tx(rx, at_of(&empty, tip, 16), tip, p_r, kKatHeight, 16, cache, refs, author);
        const auto tx_y = pb::canonical_miner_tx(ry, at_of(&empty, tip, 16), tip, p_r, kKatHeight, 16, cache, refs, author);
        const auto own_x = pb::derive_out_key(pb::derive_r_v3(rx.side.pool_id, tip, p_r, kKatHeight), rx.payee, 0);
        const auto own_y = pb::derive_out_key(pb::derive_r_v3(ry.side.pool_id, tip, p_r, kKatHeight), ry.payee, 0);
        check(tx_x.tx && tx_y.tx && own_x && own_y && tx_x.tx->outs.size() == 1 && tx_x.tx->outs[0].key == own_x->key
                      && tx_y.tx->outs[0].key == own_y->key && !(tx_x.tx->outs[0].key == tx_y.tx->outs[0].key),
              "finder-only: each output key is its own payee's");
    }

    // the budget changes no outcome: one sequence at the default and at 1 byte.
    {
        auto run = [&](std::size_t budget, std::vector<pb::CoinbaseCheck>& seq, std::vector<pb::Hash32>& hashes) {
            pb::KeyCache cache(budget);
            const pb::Window empty = finder_only_window();
            for (int i = 0; i < 6; ++i) {
                const pb::Hash32 pr = (i % 2) ? p_r : p_r_race;
                pb::ReceiptBodyV3 r = receipt(static_cast<std::uint8_t>(0x70 + (i % 3)), 600000000000ull + i, pr);
                const pb::Window& win = (i % 3 == 2) ? empty : w;
                commit_miner_tx(r, win, tip, pr, kKatHeight, book, author);
                if (i == 4) r.blob.tree_root[0] ^= 1;  // one non-canonical receipt
                seq.push_back(pb::canonical_coinbase_check(r, at_of(&win, tip, 16), tip, pr, kKatHeight, 16, cache, refs,
                                                           author));
                const pb::CanonicalTx c =
                        pb::canonical_miner_tx(r, at_of(&win, tip, 16), tip, pr, kKatHeight, 16, cache, refs, author);
                hashes.push_back(c.tx ? c.tx->tx_hash : pb::Hash32{});
            }
            check(cache.bytes() <= cache.budget(), "key cache: bytes <= budget " + std::to_string(budget));
            return cache.computations();
        };
        std::vector<pb::CoinbaseCheck> s_def, s_one;
        std::vector<pb::Hash32> h_def, h_one;
        const std::uint64_t c_def = run(pb::kKeyCacheBytesDefault, s_def, h_def);
        const std::uint64_t c_one = run(1, s_one, h_one);
        check(s_def == s_one && h_def == h_one, "key cache: budget 1 B and 64 MB -> the same outcomes and bytes");
        check(s_def[4] == pb::CoinbaseCheck::Mismatch && s_def[0] == pb::CoinbaseCheck::Match,
              "key cache: the sequence holds a Mismatch and Matches");
        check(c_one > c_def, "key cache: a smaller budget only recomputes");
        check(pb::kKeyCacheBytesDefault == 67108864u && pb::kKeyCacheFlag == "--pathb-key-cache-mb",
              "key cache: policy P-36 default 64 MB, --pathb-key-cache-mb");
    }

    // LRU by bytes: a budget of two entries keeps the two most recent.
    {
        const std::size_t one = pb::KeyCache::entry_bytes(1);
        pb::KeyCache cache(2 * one);
        const pb::Window empty = finder_only_window();
        std::vector<pb::ReceiptBodyV3> rs;
        for (std::uint8_t s = 0; s < 3; ++s) {
            pb::ReceiptBodyV3 r = receipt(static_cast<std::uint8_t>(0x80 + s), 600000000000ull, p_r);
            commit_miner_tx(r, empty, tip, p_r, kKatHeight, book, author);
            rs.push_back(r);
            pb::canonical_coinbase_check(r, at_of(&empty, tip, 16), tip, p_r, kKatHeight, 16, cache, refs, author);
        }
        check(cache.entries() == 2 && cache.bytes() == 2 * one, "LRU: two entries at a two-entry budget");
        const std::uint64_t c = cache.computations();
        pb::canonical_coinbase_check(rs[2], at_of(&empty, tip, 16), tip, p_r, kKatHeight, 16, cache, refs, author);
        check(cache.computations() == c, "LRU: the newest entry is kept");
        pb::canonical_coinbase_check(rs[0], at_of(&empty, tip, 16), tip, p_r, kKatHeight, 16, cache, refs, author);
        check(cache.computations() == c + 1, "LRU: the oldest entry was evicted");
    }
}

// ---- (4) the coinbase check outcomes ----
void outcomes() {
    RefBook book;
    std::vector<std::pair<pb::Hash32, std::uint64_t>> wts;
    for (std::uint8_t s = 0; s < 4; ++s) wts.push_back({book.add(key_ref(static_cast<std::uint8_t>(0x90 + 0x11 * s))), 50000u + s});
    const pb::XmrKeyRef author = kat_author();
    const pb::Hash32 author_id = pb::key_ref_identity(author);
    wts.push_back({author_id, 1234});  // the author is a window payee; its reference is the input
    const pb::Window w = window_of(wts);
    const pb::RefLookup refs = book.lookup();
    pb::ReceiptBodyV3 r = make_body(3, false, 0x40);
    const pb::Hash32 tip = r.side.tip, p_r = r.blob.prev_id;
    check(commit_miner_tx(r, w, tip, p_r, kKatHeight, book, author), "outcomes: the miner builds its coinbase");
    pb::KeyCache cache;
    auto ck = [&](const pb::ReceiptBodyV3& x, const pb::WindowAt& at, std::uint8_t hf, const pb::RefLookup& look) {
        return pb::canonical_coinbase_check(x, at, tip, p_r, kKatHeight, hf, cache, look, author);
    };
    check(ck(r, at_of(&w, tip, 16), 16, refs) == pb::CoinbaseCheck::Match, "outcomes: canonical -> Match");
    {
        pb::ReceiptBodyV3 bad = r;
        bad.blob.tree_root[7] ^= 0x10;
        check(ck(bad, at_of(&w, tip, 16), 16, refs) == pb::CoinbaseCheck::Mismatch, "outcomes: another tree_root -> Mismatch");
        pb::ReceiptBodyV3 more = r;
        more.reward_total += 1;
        check(ck(more, at_of(&w, tip, 16), 16, refs) == pb::CoinbaseCheck::Mismatch, "outcomes: R + 1 -> Mismatch");
    }
    {
        const std::uint64_t c = cache.computations();
        check(ck(r, at_of(&w, tip, 17), 17, refs) == pb::CoinbaseCheck::Fused && cache.computations() == c,
              "outcomes: hf 17 -> Fused, nothing computed");
    }
    check(ck(r, pb::WindowAt{nullptr}, 16, refs) == pb::CoinbaseCheck::Defer, "outcomes: window not held -> Defer");
    {
        // WindowAt is bound to (tip, v): a window evaluated for another tip or
        // another version is not this receipt's window -> Defer, never a verdict.
        const std::uint64_t c = cache.computations();
        pb::Hash32 other = tip;
        other[0] ^= 0x01;
        check(ck(r, at_of(&w, other, 16), 16, refs) == pb::CoinbaseCheck::Defer,
              "outcomes: a window of another tip -> Defer");
        check(ck(r, at_of(&w, tip, 15), 16, refs) == pb::CoinbaseCheck::Defer,
              "outcomes: a window of another version -> Defer");
        check(cache.computations() == c, "outcomes: an unbound window computes no keys");
    }
    {
        // a payee's reference not held -> Defer; held later -> Match.
        RefBook partial = book;
        partial.refs.erase(wts[1].first);
        pb::KeyCache fresh;
        check(pb::canonical_coinbase_check(r, at_of(&w, tip, 16), tip, p_r, kKatHeight, 16, fresh, partial.lookup(), author)
                      == pb::CoinbaseCheck::Defer,
              "outcomes: a payee reference not held -> Defer");
        check(pb::canonical_coinbase_check(r, at_of(&w, tip, 16), tip, p_r, kKatHeight, 16, fresh, refs, author)
                      == pb::CoinbaseCheck::Match,
              "outcomes: the reference arrives -> Match");
        // a reference held under another identity -> Defer, never a verdict.
        RefBook wrong = book;
        wrong.refs[wts[2].first] = key_ref(0xEE);
        pb::KeyCache fresh2;
        check(pb::canonical_coinbase_check(r, at_of(&w, tip, 16), tip, p_r, kKatHeight, 16, fresh2, wrong.lookup(), author)
                      == pb::CoinbaseCheck::Defer,
              "outcomes: a reference of another identity -> Defer");
    }
    {
        // side_data_v3 bound through mm_root: a changed field -> Mismatch.
        pb::ReceiptBodyV3 changed = r;
        changed.side.window_root[3] ^= 0x01;
        check(ck(changed, at_of(&w, tip, 16), 16, refs) == pb::CoinbaseCheck::Mismatch,
              "outcomes: side_data_v3 changed after the coinbase was built -> Mismatch");
        pb::ReceiptBodyV3 un = r;
        un.side.owner = seq32(0x21);  // owner with fee_rate_bp 0
        check(ck(un, at_of(&w, tip, 16), 16, refs) == pb::CoinbaseCheck::Undefined,
              "outcomes: side_data_v3 does not encode -> Undefined");
    }
    {
        pb::Window bad_w = w;
        bad_w.W += pb::Work(1);  // weights != W
        check(ck(r, at_of(&bad_w, tip, 16), 16, refs) == pb::CoinbaseCheck::Undefined,
              "outcomes: window weights != W -> Undefined");
    }
    {
        // finder-only with a payee identity that is not its reference's.
        const pb::Window empty = finder_only_window();
        pb::ReceiptBodyV3 f = make_body(3, false, 0x41);
        commit_miner_tx(f, empty, f.side.tip, f.blob.prev_id, kKatHeight, book, author);
        pb::KeyCache c2;
        check(pb::canonical_coinbase_check(f, at_of(&empty, f.side.tip, 16), f.side.tip, f.blob.prev_id, kKatHeight, 16, c2, refs,
                                           author)
                      == pb::CoinbaseCheck::Match,
              "outcomes: finder-only -> Match");
        f.side.payee[0] ^= 0x01;
        check(pb::canonical_coinbase_check(f, at_of(&empty, f.side.tip, 16), f.side.tip, f.blob.prev_id, kKatHeight, 16, c2, refs,
                                           author)
                      == pb::CoinbaseCheck::Undefined,
              "outcomes: finder-only payee identity != its reference -> Undefined");
    }
    // the tail: Fused / Unbuildable REFUSE, Defer DEFER, Mismatch / Undefined BAN; RandomX only after Match.
    {
        int rx = 0;
        auto tail = [&](pb::CoinbaseCheck c) {
            return pb::admit_coinbase_then_randomx(c, [&] { ++rx; return true; });
        };
        const pb::TailResult f = tail(pb::CoinbaseCheck::Fused), u = tail(pb::CoinbaseCheck::Unbuildable),
                             d = tail(pb::CoinbaseCheck::Defer), m = tail(pb::CoinbaseCheck::Mismatch),
                             n = tail(pb::CoinbaseCheck::Undefined);
        check(f.verdict == pb::AdmitVerdict::Refuse && u.verdict == pb::AdmitVerdict::Refuse
                      && pb::strike_tokens(f.verdict) == 0,
              "tail: Fused / Unbuildable -> REFUSE, no token");
        check(d.verdict == pb::AdmitVerdict::Defer, "tail: Defer -> DEFER");
        check(m.verdict == pb::AdmitVerdict::Ban && n.verdict == pb::AdmitVerdict::Ban, "tail: Mismatch / Undefined -> BAN");
        check(rx == 0, "tail: RandomX not called before Match");
        const pb::TailResult ok = tail(pb::CoinbaseCheck::Match);
        check(ok.verdict == pb::AdmitVerdict::AdmitCarrier && ok.randomx_called && rx == 1, "tail: Match -> RandomX");
    }
}

}  // namespace

int main() {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    real_blocks();
    self_golden();
    key_cache();
    outcomes();
    check(author_refs_of_record_kat() == 0, "author references == the per-network donation keys of record");
    return finish("v37_xmr_pathb_miner_tx_kat");
}
