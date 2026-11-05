// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// xmr_block_assembly_kat -- the Path B block assembly
// (impl/xmr/template/xmr_block_assembly.hpp):
//   K1  every captured stagenet block of xmr_c2a_golden.hpp (0 to 6
//       transactions) re-assembled from its header, its miner tx prefix and
//       its transaction ids is byte-identical to monerod's block, and
//       block_id_of(its hashing blob) is monerod's id
//   K2  a Path B miner tx (build_miner_tx_hf16, three payees): its tx_extra
//       walks as 01 R[32] | 02 04 nonce | 03 21 00 root[32] (74 B), complete
//   K3  a block assembled from a captured header, the Path B miner tx and that
//       block's transaction ids parses; its miner tx is the Path B prefix and
//       the RCTTypeNull byte, its transaction ids are the block's
// ---------------------------------------------------------------------------
#include <algorithm>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include "impl/xmr/template/xmr_block_assembly.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/test/xmr_c2a_golden.hpp"
#include "impl/xmr/pathb/pathb_miner_tx.hpp"
#include "impl/xmr/pathb/test/pathb_kat_miner.hpp"

namespace native = ::c2pool::xmr::native;
namespace asmb = ::c2pool::xmr::assembly;
namespace pb = ::c2pool::xmr::pathb;

namespace {

int g_fail = 0, g_checks = 0;
void check(bool ok, const std::string& what) {
    ++g_checks;
    std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", what.c_str());
    if (!ok) ++g_fail;
}

std::vector<std::uint8_t> from_hex(const std::string& h) {
    auto nib = [](char c) -> int { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<std::uint8_t>(nib(h[i]) * 16 + nib(h[i + 1])));
    return out;
}

std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* k = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        s.push_back(k[p[i] >> 4]);
        s.push_back(k[p[i] & 15]);
    }
    return s;
}

}  // namespace

int main() {
    std::printf("== xmr_block_assembly_kat: the Path B block assembly ==\n");

    // K1 captured blocks re-assembled
    std::size_t n = 0, ok = 0, tx_max = 0;
    std::size_t with_tx = SIZE_MAX;
    for (std::size_t i = 0; i < std::size(native::golden_c2a::BLOCKS); ++i) {
        const native::golden_c2a::GoldenBlock& gb = native::golden_c2a::BLOCKS[i];
        ++n;
        const std::vector<std::uint8_t> blob = from_hex(gb.blob_hex);
        native::ParsedBlock p;
        native::BlockIdentity id;
        if (native::parse_and_identify(blob, p, id) != native::BlockParseStatus::Ok || p.header_size < 4 ||
            p.miner_tx_size < 1)
            continue;
        const bool rct0 = blob[p.miner_tx_offset + p.miner_tx_size - 1] == 0x00;
        const std::span<const std::uint8_t> prefix(blob.data() + p.miner_tx_offset, p.miner_tx_size - 1);
        const std::vector<std::uint8_t> again = asmb::pathb_block_blob(id.hashing_blob, p.header_size - 4, prefix, p.tx_hashes);
        if (rct0 && again == blob && hex(asmb::block_id_of(id.hashing_blob).data(), 32) == gb.id_hex) ++ok;
        tx_max = std::max(tx_max, p.tx_hashes.size());
        if (with_tx == SIZE_MAX && p.tx_hashes.size() >= 3) with_tx = i;
    }
    check(n > 0 && ok == n && tx_max >= 3,
          "K1 " + std::to_string(ok) + " of " + std::to_string(n) + " captured blocks (up to " + std::to_string(tx_max) +
                  " transactions) re-assembled byte for byte; block_id_of == monerod's id");

    // K2 the Path B miner tx's extra
    const std::vector<pb::MinerPayee> payees = {{pathb_kat::key_ref(0xA1), 1000000},
                                                {pathb_kat::key_ref(0xA2), 2000000},
                                                {pathb_kat::kat_author(), 3}};
    const std::array<std::uint8_t, pb::kExtraNonceBytes> en{0x11, 0x22, 0x33, 0x44};
    const std::optional<pb::MinerTx> mt = pb::build_miner_tx_hf16(pathb_kat::seq32(0x01), pathb_kat::seq32(0x21),
                                                                  pathb_kat::seq32(0x41), 3800000, payees, en,
                                                                  pathb_kat::seq32(0x77));
    bool extra_ok = false;
    if (mt) {
        const asmb::TxExtraWalk w = asmb::walk_tx_extra(mt->extra.data(), mt->extra.size());
        extra_ok = w.complete && mt->extra.size() == 74 && w.fields.size() == 3 &&
                   w.fields[0].tag == ::c2pool::xmr::TX_EXTRA_TAG_PUBKEY && w.fields[0].data_size == 32 &&
                   w.fields[1].tag == ::c2pool::xmr::TX_EXTRA_NONCE && w.fields[1].data_size == 4 &&
                   std::equal(en.begin(), en.end(), mt->extra.begin() + static_cast<std::ptrdiff_t>(w.fields[1].data_offset)) &&
                   w.fields[2].tag == ::c2pool::xmr::TX_EXTRA_MERGE_MINING_TAG && w.fields[2].data_size == 33;
    }
    check(mt.has_value() && extra_ok, "K2 the Path B miner tx's extra walks as 01 R | 02 04 nonce | 03 21 00 root (74 B)");

    // K3 a block of the Path B miner tx
    bool k3 = false;
    if (mt && with_tx != SIZE_MAX) {
        const std::vector<std::uint8_t> blob = from_hex(native::golden_c2a::BLOCKS[with_tx].blob_hex);
        native::ParsedBlock p;
        native::BlockIdentity id;
        if (native::parse_and_identify(blob, p, id) == native::BlockParseStatus::Ok) {
            const std::vector<std::uint8_t> b3 = asmb::pathb_block_blob(id.hashing_blob, p.header_size - 4, mt->prefix, p.tx_hashes);
            native::ParsedBlock q;
            native::BlockIdentity qid;
            if (native::parse_and_identify(b3, q, qid) == native::BlockParseStatus::Ok) {
                std::vector<std::uint8_t> want = mt->prefix;
                want.push_back(0x00);
                const std::vector<std::uint8_t> got(b3.begin() + static_cast<std::ptrdiff_t>(q.miner_tx_offset),
                                                    b3.begin() + static_cast<std::ptrdiff_t>(q.miner_tx_offset + q.miner_tx_size));
                k3 = got == want && q.tx_hashes == p.tx_hashes && q.header_size == p.header_size &&
                     std::equal(b3.begin(), b3.begin() + static_cast<std::ptrdiff_t>(q.header_size), blob.begin());
            }
        }
    }
    check(k3, "K3 a captured header + the Path B miner tx + the block's transaction ids parse as a block with that miner tx");

    std::printf("== xmr_block_assembly_kat: %s (%d/%d) ==\n", g_fail ? "FAIL" : "OK", g_checks - g_fail, g_checks);
    return g_fail ? 1 : 0;
}
