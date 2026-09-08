// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/test/v37_xmr_o2_live_submit_selfcheck.cpp   (X9 O-2, wire 3)
//
// Network-free self-check of xmr/xmr_live_submit.hpp against the monerod STUB
// (MockMonerodTransport): the block-blob assembler (nonce LE at nonce_offset,
// extra_nonce at reserved_offset), the submit_block ack parser INCLUDING
// result.block_id, LiveBlockSubmitter's fail-closed default + the three
// block-id sources (monerod > local keccak > header) + their cross-checks, and
// the IShareSink -> FoundBlockQueue hand-off in XmrStratumServer's call order.
// REAL golden: keccak256(varint(len) || hashing_blob) of the Monero mainnet
// genesis block reproduces its published id, pinning the object-hash framing.
// ===========================================================================
#include <cstdio>
#include <string>
#include <vector>

#include "c2pool/v37/xmr/xmr_live_submit.hpp"

using namespace c2pool::v37n::xmr::submit;
using ::c2pool::xmr::node::MockMonerodTransport;

static int g_fail = 0, g_pass = 0;
#define CHECK(cond, msg) do { if (cond) { ++g_pass; std::printf("  [PASS] %s\n", msg); } \
                              else { ++g_fail; std::printf("  [FAIL] %s\n", msg); } } while (0)

int main() {
    // ---------------------------------------------------------------------
    // G1: Monero MAINNET GENESIS block id pins keccak(varint(len) || hashing_blob).
    //   header: varint(major=1) varint(minor=0) varint(ts=0) prev[32]=0 nonce=10000 LE
    //   tree_root = v1 miner-tx hash = keccak256(GENESIS_TX blob)
    //   hashing blob = header || tree_root || varint(1)
    //   expected id  = 418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3
    // ---------------------------------------------------------------------
    std::printf("== G1: genesis block id (object-hash framing) ==\n");
    {
        const std::string genesis_tx_hex =
            "013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1";
        std::vector<std::uint8_t> tx;
        CHECK(from_hex(genesis_tx_hex, tx), "genesis tx hex decodes");
        const ::xmr::coin::Hash256 txh = ::xmr::coin::keccak256(tx.data(), tx.size());

        std::vector<std::uint8_t> hb;
        hb.push_back(0x01); hb.push_back(0x00); hb.push_back(0x00);   // major=1 minor=0 ts=0
        hb.insert(hb.end(), 32, 0x00);                                // prev_id = null
        const std::uint32_t nonce = 10000;                            // GENESIS_NONCE
        for (int i = 0; i < 4; ++i) hb.push_back(static_cast<std::uint8_t>(nonce >> (8 * i)));
        hb.insert(hb.end(), txh.data(), txh.data() + 32);             // tree_root (1 leaf)
        hb.push_back(0x01);                                           // varint(n_tx = 1)
        CHECK(hb.size() == 72, "genesis hashing blob is 72 bytes");

        const Hash id = block_id_of_hashing_blob(hb);
        const std::string got = mj::hash_to_hex(id);
        std::printf("    computed genesis id = %s\n", got.c_str());
        CHECK(got == "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3",
              "block_id_of_hashing_blob == Monero mainnet genesis id (framing pinned)");

        // Sanity: the same 72 bytes WITHOUT the varint framing must NOT match
        // (proves the varint prefix is load-bearing, not accidental).
        const ::xmr::coin::Hash256 raw = ::xmr::coin::keccak256(hb.data(), hb.size());
        Hash rawh{}; std::memcpy(rawh.data(), raw.data(), 32);
        CHECK(mj::hash_to_hex(rawh) != got, "unframed keccak differs (varint prefix is load-bearing)");

        // And: the framing goes through BlockCandidate + hashing_blob_with_nonce.
        BlockCandidate c;
        c.height = 1; c.template_id = 7;
        c.hashing_blob = hb; c.full_blob = hb;                 // header-identical stand-in
        c.nonce_offset = 35;   // genesis-era header prefix is 3 bytes (varint 1,0,0), NOT the 7-byte v16 prefix
        std::vector<std::uint8_t> zeroed = hb;                  // wipe the nonce, let the API patch it
        for (int i = 0; i < 4; ++i) zeroed[35 + i] = 0;
        c.hashing_blob = zeroed; c.full_blob = zeroed;
        CHECK(validate_candidate(c).empty(), "candidate validates");
        CHECK(mj::hash_to_hex(block_id_of_hashing_blob(hashing_blob_with_nonce(c, nonce))) == got,
              "hashing_blob_with_nonce(cand, 10000) reproduces the genesis id");
        // A WRONG nonce_offset (the v16 default 39 applied to a v1 header) must NOT reproduce it:
        // the offset is the template layer's responsibility (survey: derive it from the
        // hashing/full blob divergence point), and the id would silently differ.
        BlockCandidate wrong = c; wrong.nonce_offset = 39;
        CHECK(mj::hash_to_hex(block_id_of_hashing_blob(hashing_blob_with_nonce(wrong, nonce))) != got,
              "a wrong nonce_offset yields a different id (offset is load-bearing)");
    }

    // ---------------------------------------------------------------------
    // A1: assembly — nonce LE at nonce_offset, extra_nonce at reserved_offset.
    // ---------------------------------------------------------------------
    std::printf("== A1: assemble_block_blob ==\n");
    {
        BlockCandidate c;
        c.height = 5; c.template_id = 1; c.nonce_offset = 39;
        c.full_blob.assign(120, 0xAA);
        c.hashing_blob.assign(76, 0xAA);
        c.reserved_offset = 80; c.reserved_size = 8;
        CHECK(validate_candidate(c).empty(), "candidate with reserve validates");
        auto b = assemble_block_blob(c, 0x11223344u, 0xDEADBEEFu);
        CHECK(b.size() == 120, "assembled size == full_blob size");
        CHECK(b[39] == 0x44 && b[40] == 0x33 && b[41] == 0x22 && b[42] == 0x11, "nonce patched LE at 39");
        CHECK(b[80] == 0xEF && b[81] == 0xBE && b[82] == 0xAD && b[83] == 0xDE, "extra_nonce patched LE at reserved_offset");
        CHECK(b[84] == 0xAA && b[38] == 0xAA && b[43] == 0xAA, "bytes outside the two patches untouched");
        CHECK(c.full_blob[39] == 0xAA, "candidate itself is not mutated");

        BlockCandidate bad = c; bad.hashing_blob[3] = 0x00;
        CHECK(!validate_candidate(bad).empty(), "header-prefix disagreement is refused");
        BlockCandidate bad2 = c; bad2.nonce_offset = 118;
        CHECK(!validate_candidate(bad2).empty(), "nonce_offset past end is refused");
        BlockCandidate bad3 = c; bad3.reserved_offset = 40;
        CHECK(!validate_candidate(bad3).empty(), "reserve overlapping the header is refused");
        BlockCandidate bad4 = c; bad4.height = 0;
        CHECK(!validate_candidate(bad4).empty(), "height 0 is refused");
    }

    // ---------------------------------------------------------------------
    // P1: submit_block response parser incl. block_id.
    // ---------------------------------------------------------------------
    std::printf("== P1: parse_submit_block_ack ==\n");
    {
        const std::string ok = R"({"id":"0","jsonrpc":"2.0","result":{"block_id":"418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3","status":"OK","untrusted":false}})";
        auto a = parse_submit_block_ack(ok.data(), ok.size());
        CHECK(a.accepted && a.status == "OK", "OK accepted");
        CHECK(a.block_id.has_value() && mj::hash_to_hex(*a.block_id).rfind("418015bb", 0) == 0, "block_id parsed");
        const std::string ok_old = R"({"id":"0","jsonrpc":"2.0","result":{"status":"OK"}})";
        auto b = parse_submit_block_ack(ok_old.data(), ok_old.size());
        CHECK(b.accepted && !b.block_id.has_value(), "older monerod (no block_id) still accepted");
        const std::string rej = R"({"id":"0","jsonrpc":"2.0","error":{"code":-7,"message":"Block not accepted"}})";
        auto r = parse_submit_block_ack(rej.data(), rej.size());
        CHECK(!r.accepted && r.rpc_code == -7 && r.error.find("Block not accepted") != std::string::npos, "rpc error -7 surfaced");
        const std::string garbage = "not json";
        auto g = parse_submit_block_ack(garbage.data(), garbage.size());
        CHECK(!g.accepted && !g.error.empty(), "garbage body rejected");
    }

    // ---------------------------------------------------------------------
    // S1: LiveBlockSubmitter over MockMonerodTransport.
    // ---------------------------------------------------------------------
    std::printf("== S1: LiveBlockSubmitter ==\n");
    {
        // A candidate whose local id we can predict: reuse the genesis blob.
        const std::string genesis_tx_hex =
            "013c01ff0001ffffffffffff03029b2e4c0281c0b02e7c53291a94d1d0cbff8883f8024f5142ee494ffbbd08807121017767aafcde9be00dcfd098715ebcf7f410daebc582fda69d24a28e9d0bc890d1";
        std::vector<std::uint8_t> tx; from_hex(genesis_tx_hex, tx);
        const ::xmr::coin::Hash256 txh = ::xmr::coin::keccak256(tx.data(), tx.size());
        std::vector<std::uint8_t> hb;
        hb.push_back(0x01); hb.push_back(0x00); hb.push_back(0x00);
        hb.insert(hb.end(), 32, 0x00);
        hb.insert(hb.end(), 4, 0x00);                       // nonce left zero; API patches
        hb.insert(hb.end(), txh.data(), txh.data() + 32);
        hb.push_back(0x01);
        std::vector<std::uint8_t> full = hb;                 // header-identical stand-in
        full.insert(full.end(), tx.begin(), tx.end());       // "miner_tx" tail, whatever

        BlockCandidate c;
        c.height = 1; c.template_id = 42; c.nonce_offset = 35;   // genesis-era 3-byte header prefix
        c.hashing_blob = hb; c.full_blob = full; c.expected_reward = 17'592'186'044'415ull;
        const std::string GEN = "418015bb9ae982a1975da7d79277c2705727a56894ba0fb246adaabb1f4632e3";

        MockMonerodTransport mock;
        // (i) fail-closed default: nothing is posted.
        {
            LiveBlockSubmitter sub(mock);
            auto o = sub.submit(c, 10000, 0);
            CHECK(o.refused && !o.accepted, "default policy REFUSES (fail-closed)");
            CHECK(mock.posted_bodies().empty(), "nothing posted to monerod when refused");
            CHECK(sub.refused() == 1 && sub.calls() == 1, "refused counter");
        }
        // (ii) enabled; monerod returns OK + block_id; header confirms.
        {
            mock.set_method_body("submit_block",
                R"({"id":"0","jsonrpc":"2.0","result":{"block_id":")" + GEN + R"(","status":"OK"}})");
            mock.set_method_body("get_block_header_by_height",
                R"({"id":"0","jsonrpc":"2.0","result":{"block_header":{"hash":")" + GEN +
                R"(","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","height":1,"timestamp":0,"reward":17592186044415,"difficulty":1,"difficulty_top64":0}},"status":"OK"})");
            SubmitPolicy p; p.network_submit_enabled = true;
            LiveBlockSubmitter sub(mock, p);
            auto o = sub.submit(c, 10000, 0);
            CHECK(o.accepted && !o.refused, "accepted");
            CHECK(o.id_source == IdSource::Monerod, "id source = monerod");
            CHECK(o.block_id_hex() == GEN, "bid == monerod block_id");
            CHECK(o.local_block_id && mj::hash_to_hex(*o.local_block_id) == GEN, "local id computed and equal");
            CHECK(!o.id_mismatch, "no monerod/local mismatch");
            CHECK(o.header_check == HeaderCheck::Confirmed, "header confirms");
            CHECK(sub.ok() == 1 && sub.id_mismatches() == 0, "ok counter");
            // the posted body is the KAT-pinned submit_block shape with the patched blob
            const auto& posted = mock.posted_bodies();
            CHECK(posted.size() == 2, "two RPCs posted (submit_block + header confirm)");
            CHECK(posted[0].find("\"method\":\"submit_block\"") != std::string::npos, "first post is submit_block");
            CHECK(posted[0].find("\"params\":[\"" + o.block_blob_hex + "\"]") != std::string::npos, "params carries the assembled blob hex");
            CHECK(o.block_blob_hex.substr(35 * 2, 8) == "10270000", "posted blob has nonce 10000 LE at the header nonce offset (35 for this v1 header)");
        }
        // (iii) older monerod: no block_id -> local id used, header confirms it.
        {
            mock.set_method_body("submit_block", R"({"id":"0","jsonrpc":"2.0","result":{"status":"OK"}})");
            SubmitPolicy p; p.network_submit_enabled = true;
            LiveBlockSubmitter sub(mock, p);
            auto o = sub.submit(c, 10000, 0);
            CHECK(o.accepted && o.id_source == IdSource::Local && o.block_id_hex() == GEN, "no block_id -> local id");
            CHECK(o.header_check == HeaderCheck::Confirmed, "header confirms the local id");
        }
        // (iv) no block_id, no hashing blob -> header (prev_id matched) supplies the id.
        {
            BlockCandidate c2 = c; c2.hashing_blob.clear();
            SubmitPolicy p; p.network_submit_enabled = true;
            LiveBlockSubmitter sub(mock, p);
            auto o = sub.submit(c2, 10000, 0);
            CHECK(o.accepted && o.id_source == IdSource::Header && o.block_id_hex() == GEN, "header fallback supplies the id");
            // header at H with a DIFFERENT prev -> not ours -> unattributable
            BlockCandidate c3 = c2; c3.prev_id[0] = 0x55;
            auto o3 = sub.submit(c3, 10000, 0);
            CHECK(o3.accepted && !o3.has_block_id() && o3.header_check == HeaderCheck::Mismatch,
                  "prev mismatch -> no id adopted (unattributable, loud)");
            CHECK(sub.unattributable() == 1, "unattributable counter");
        }
        // (v) monerod block_id != local -> monerod wins, mismatch flagged.
        {
            const std::string OTHER = "1111111111111111111111111111111111111111111111111111111111111111";
            mock.set_method_body("submit_block",
                R"({"id":"0","jsonrpc":"2.0","result":{"block_id":")" + OTHER + R"(","status":"OK"}})");
            SubmitPolicy p; p.network_submit_enabled = true; p.confirm_with_header = false;
            LiveBlockSubmitter sub(mock, p);
            auto o = sub.submit(c, 10000, 0);
            CHECK(o.accepted && o.id_mismatch && o.block_id_hex() == OTHER, "monerod id wins; mismatch flagged");
            CHECK(o.header_check == HeaderCheck::NotRun, "header check skipped per policy");
        }
        // (vi) rejection + transport failure paths.
        {
            mock.set_method_body("submit_block", R"({"id":"0","jsonrpc":"2.0","error":{"code":-7,"message":"Block not accepted"}})");
            SubmitPolicy p; p.network_submit_enabled = true;
            LiveBlockSubmitter sub(mock, p);
            auto o = sub.submit(c, 10000, 0);
            CHECK(!o.accepted && !o.refused && o.rpc_code == -7, "rejection surfaced (-7)");
            CHECK(sub.rejected() == 1, "rejected counter");
            mock.fail_next(1);
            auto o2 = sub.submit(c, 10000, 0);
            CHECK(!o2.accepted && o2.error.rfind("transport:", 0) == 0, "transport failure surfaced");
            CHECK(sub.transport_errors() == 1, "transport counter");
            CHECK(sub.last_error() == o2.error, "last_error tracks");
        }
        // (vii) sink -> queue, with the handle_submit ordering (submit first, then on_accepted_share).
        {
            mock.set_method_body("submit_block",
                R"({"id":"0","jsonrpc":"2.0","result":{"block_id":")" + GEN + R"(","status":"OK"}})");
            SubmitPolicy p; p.network_submit_enabled = true;
            LiveBlockSubmitter sub(mock, p);
            FoundBlockQueue q;
            LiveSubmitShareSink sink(sub, q, [&](std::uint32_t tid, std::uint32_t, BlockCandidate& out) {
                if (tid != 42) return false;
                out = c; return true;
            });
            sink.submit_network_block(42, 10000, 3);
            CHECK(q.size() == 1 && q.pushed() == 1, "found event queued on OK");
            strat::AcceptedShare sh; sh.template_id = 42; sh.nonce = 10000; sh.extra_nonce = 3;
            sh.is_network_block = true; sh.worker = "rig1"; sh.address = "4AAAA";
            sink.on_accepted_share(sh);
            FoundBlockEvent ev;
            CHECK(q.pop(ev), "event drained");
            CHECK(ev.height == 1 && ev.block_id_hex() == GEN && ev.reward == c.expected_reward, "event carries height/bid/reward");
            CHECK(ev.worker == "rig1" && ev.address == "4AAAA", "annotate() attached worker/address");
            CHECK(!q.pop(ev), "queue empty after drain");
            sink.submit_network_block(99, 1, 0);
            CHECK(sink.stale_lookups() == 1 && q.size() == 0, "stale template -> nothing queued");
            std::printf("    %s\n", describe(ev).c_str());
            auto amt = single_key_amounts<std::map<std::array<std::uint8_t, 32>, long long>>(ev.block_id, ev.reward);
            CHECK(amt.size() == 1 && amt.begin()->second == static_cast<long long>(c.expected_reward), "single_key_amounts");
        }
    }

    std::printf("== %s (%d passed, %d failed) ==\n", g_fail ? "FAIL" : "OK", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
