// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See <https://www.gnu.org/licenses/>.
//
// v37_xmr_light_proof_kat -- Purple Paper §13 on the XMR lane: a device that
// holds only Monero headers verifies one worker's owed balance.
//
//   LP1 merkle_rows OFF: owed_digest is the flat "V37Q" hash, byte for byte.
//   LP2 merkle_rows ON: for ledgers of 1..33 rows, every key's proof
//       reproduces owed_digest; the path has ceil(log2(rows)) hashes at most.
//   LP3 a changed balance, age, key, index, row count, sibling or rest
//       digest does not reproduce it.
//   LP4 end to end: header (hashing blob) -> tx-tree branch -> miner tx ->
//       0x03 root -> owed_digest -> the balance, with 1 and 7 transactions;
//       the block id is keccak(varint(len) || blob).
//   LP5 a forged 0x03 root, another chain id, a proof for another ledger
//       state, or a broken tree branch is refused.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <c2pool/v37/xmr/xmr_light_proof.hpp>

namespace settle = ::c2pool::v37n::settle;
namespace lp = ::c2pool::v37n::xmr::light;
using ::v37::bytes32;

static int g_pass = 0, g_fail = 0;
static void check(bool ok, const std::string& what) {
    (ok ? g_pass : g_fail)++;
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
}
static bytes32 key_of(unsigned i) { bytes32 k{}; k[0] = static_cast<std::uint8_t>(i); k[1] = static_cast<std::uint8_t>(i >> 8); k[31] = 0x5a; return k; }

// A ledger with n finalized non-zero rows (one found + finalized block).
static settle::OwedLedger ledger_with(unsigned n, bool merkle, long long base = 1000) {
    settle::OwedLedgerRules r; r.merkle_rows = merkle;
    settle::OwedLedger L(7, r);
    settle::OwedLedger::Amounts credit;
    for (unsigned i = 0; i < n; ++i) credit[key_of(i)] = base + i * 37;
    L.on_block_found("b1", credit, {});
    L.on_block_finalized("b1", 100);
    return L;
}

// A miner tx prefix whose tx_extra ends in the 0x03 root committing `digest`.
static lp::LightBlockInputs block_committing(const bytes32& digest, std::uint32_t chain, unsigned n_other) {
    lp::LightBlockInputs in;
    in.prev_id[0] = 0xab; in.timestamp = 1790000000; in.nonce = 42;
    const std::uint64_t amt = 600000000000ull;
    ::xmr::coin::PublicKey k{}; k.data()[0] = 9;
    ::xmr::coin::ViewTag vt{};
    in.miner_tx_prefix = ::xmr::coin::write_coinbase_prefix_head(3456789, &amt, &k, &vt, 1);
    std::vector<std::uint8_t> extra = {0x01};
    for (int i = 0; i < 32; ++i) extra.push_back(static_cast<std::uint8_t>(i + 1));   // tx pubkey
    const auto root = ::v37::xmr::settle::mm_commitment_root(chain, digest);
    extra.push_back(0x03); extra.push_back(0x21); extra.push_back(0x00);
    extra.insert(extra.end(), root.data(), root.data() + 32);
    in.miner_tx_prefix.push_back(static_cast<std::uint8_t>(extra.size()));   // varint (< 128)
    in.extra_start = in.miner_tx_prefix.size();
    in.miner_tx_prefix.insert(in.miner_tx_prefix.end(), extra.begin(), extra.end());
    for (unsigned i = 0; i < n_other; ++i) { bytes32 h{}; h[0] = static_cast<std::uint8_t>(0x70 + i); in.other_tx_hashes.push_back(h); }
    return in;
}

int main() {
    std::printf("== v37_xmr_light_proof_kat\n");

    std::printf("-- LP1 merkle_rows off is the flat digest\n");
    {
        const auto L = ledger_with(5, false);
        std::vector<std::uint8_t> pre = {'V', '3', '7', 'Q'};
        for (unsigned i = 0; i < 5; ++i) {
            const bytes32 k = key_of(i);
            pre.insert(pre.end(), k.begin(), k.end());
            const std::uint64_t w = 1000 + i * 37;
            for (int b = 0; b < 8; ++b) pre.push_back(static_cast<std::uint8_t>(w >> (8 * b)));
            const std::uint64_t fe = L.first_eligible_of(k);
            for (int b = 0; b < 8; ++b) pre.push_back(static_cast<std::uint8_t>(fe >> (8 * b)));
        }
        // rows are key-ascending; key_of(i) ascends with i for i < 256
        check(L.owed_digest() == ::v37::sha256d(pre), "off: owed_digest is the flat V37Q hash");
        check(!L.prove_owed(key_of(0)), "off: no proof is offered");
        check(ledger_with(5, true).owed_digest() != L.owed_digest(), "on: the digest changes (a new commitment)");
    }

    std::printf("-- LP2 every key's proof reproduces owed_digest\n");
    {
        bool all = true, short_paths = true;
        for (unsigned n = 1; n <= 33; ++n) {
            const auto L = ledger_with(n, true);
            const bytes32 d = L.owed_digest();
            unsigned depth = 0; while ((1u << depth) < n) ++depth;
            for (unsigned i = 0; i < n; ++i) {
                const auto p = L.prove_owed(key_of(i));
                if (!p || settle::OwedLedger::owed_digest_from_proof(*p) != d) { all = false; std::printf("     n=%u i=%u fails\n", n, i); }
                if (p && p->path.size() > depth) short_paths = false;
            }
        }
        check(all, "rows 1..33: every proof reproduces owed_digest");
        check(short_paths, "every path has at most ceil(log2(rows)) hashes");
        const auto L = ledger_with(1000, true);
        const auto p = L.prove_owed(key_of(517));
        check(p && p->path.size() <= 10 && settle::OwedLedger::owed_digest_from_proof(*p) == L.owed_digest(),
              "1000 rows: a 10-hash path (" + std::to_string(p ? p->path.size() : 0) + ")");
        check(!L.prove_owed(key_of(5000)), "a key with no row has no proof");
    }

    std::printf("-- LP3 any change breaks it\n");
    {
        const auto L = ledger_with(13, true);
        const bytes32 d = L.owed_digest();
        const auto p0 = *L.prove_owed(key_of(6));
        auto bad = [&](auto mut) { auto p = p0; mut(p); const auto r = settle::OwedLedger::owed_digest_from_proof(p); return !r || *r != d; };
        check(bad([](auto& p) { p.finalW += 1; }), "a changed balance");
        check(bad([](auto& p) { p.first_eligible += 1; }), "a changed age");
        check(bad([](auto& p) { p.key[5] ^= 1; }), "a changed key");
        check(bad([](auto& p) { p.index ^= 1; }), "a changed index");
        check(bad([](auto& p) { p.rows += 1; }), "a changed row count");
        check(bad([](auto& p) { p.path[0][0] ^= 1; }), "a changed sibling");
        check(bad([](auto& p) { p.rest[0] ^= 1; }), "a changed rest digest");
        check(bad([](auto& p) { p.path.push_back(bytes32{}); }), "an extra sibling");
    }

    std::printf("-- LP4 end to end: header to balance\n");
    for (unsigned n_other : {0u, 6u}) {
        const auto L = ledger_with(9, true);
        const auto in = block_committing(L.owed_digest(), 7, n_other);
        lp::LightBalanceProof pr; std::string why;
        const bool made = lp::make_light_proof(in, 7, L, key_of(4), pr, &why);
        check(made, "the node builds the proof (" + std::to_string(n_other + 1) + " txs) " + why);
        const auto v = lp::verify_light_balance(pr);
        check(v.ok && v.balance == 1000 + 4 * 37, "the device verifies the balance: " + std::to_string(v.balance) + " " + v.why);
        check(v.block_id == lp::block_id_of(pr.block.hashing_blob.bytes) && v.prev_id == in.prev_id,
              "the verdict names the block id and parent to check in the header chain");
        std::printf("     proof size: blob %zu + midstate 200 + tail %zu + extra %zu + tree %zu*32 + path %zu*32 bytes\n",
                    pr.block.hashing_blob.bytes.size(), pr.block.coinbase_opening.prefix_tail.size(),
                    pr.block.coinbase_opening.tx_extra.size(), pr.block.tree_branch.path.size(), pr.owed.path.size());
    }

    std::printf("-- LP5 forgeries are refused\n");
    {
        const auto L = ledger_with(9, true);
        const auto in = block_committing(L.owed_digest(), 7, 3);
        lp::LightBalanceProof pr;
        lp::make_light_proof(in, 7, L, key_of(2), pr);
        { auto p = pr; p.block.coinbase_opening.tx_extra.back() ^= 1; check(!lp::verify_light_balance(p).ok, "a forged 0x03 root (the tx hash moves too)"); }
        { auto p = pr; p.chain_id = 8; check(!lp::verify_light_balance(p).ok, "another chain id"); }
        { auto p = pr; p.owed.finalW *= 2; check(!lp::verify_light_balance(p).ok, "a doubled balance"); }
        { auto p = pr; if (!p.block.tree_branch.path.empty()) p.block.tree_branch.path[0][0] ^= 1; check(!lp::verify_light_balance(p).ok, "a broken tx-tree branch"); }
        // another ledger state (one more finalized block) is not what this block commits
        auto L2 = ledger_with(9, true);
        L2.on_block_found("b2", {{key_of(2), 5}}, {});
        L2.on_block_finalized("b2", 101);
        lp::LightBalanceProof pr2; std::string why;
        const bool made2 = lp::make_light_proof(in, 7, L2, key_of(2), pr2, &why);
        check(!made2, "the prover refuses a state the block does not commit: " + why);
        { auto p = pr; p.owed = *L2.prove_owed(key_of(2)); check(!lp::verify_light_balance(p).ok, "a proof from another state does not reach the block's root"); }
    }

    std::printf("== v37_xmr_light_proof_kat: %d passed, %d failed -> %s\n", g_pass, g_fail, g_fail ? "FAIL" : "OK");
    return g_fail ? 1 : 0;
}
