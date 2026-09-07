/*
 * This file is part of c2pool <https://github.com/frstrtr/c2pool>
 * Copyright (c) 2024-2026 The c2pool developers
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.  (Full header: xmr_node_types.hpp)
 */

// ===========================================================================
// test/x2_adapter_kat.cpp   (Track X / Family B: XMR lane, X2)
//
// AUTHORED for c2pool (not ported). The light KAT the task asks for and more:
// feed a MOCK monerod (no sockets) get_miner_data + a small reorg through the
// IMonerodTransport seam, assert the MainchainIndex resolves seed_height with
// >= 2112 reach and surfaces the reorg/orphan events. Also exercises the RPC
// request-body builders + parsers, the ZMQ topic decoders, seed-anchor pinning
// under prune, RPC seed backfill, and submit_block -- all single-TU, no RandomX,
// no cmake, runnable on an OOM-pressured host:
//
//   g++ -std=c++20 -O1 -I <leg>/src -I /home/ubuntu/x1-verify/src
//       test/x2_adapter_kat.cpp src/impl/xmr/node/monero_rpc.cpp
//       src/impl/xmr/node/monero_zmq.cpp -o /tmp/x2kat  ;  /tmp/x2kat
// ===========================================================================
#include "impl/xmr/node/mainchain_index.hpp"
#include "impl/xmr/node/minijson.hpp"
#include "impl/xmr/node/monero_node_adapter.hpp"
#include "impl/xmr/node/monero_rpc.hpp"
#include "impl/xmr/node/monero_zmq.hpp"
#include "impl/xmr/node/monerod_transport.hpp"

#include <cstdio>
#include <cstring>
#include <string>

using namespace c2pool::xmr::node;
namespace mj = c2pool::xmr::node::minijson;

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { std::printf("  ok  : %s\n", msg); } \
    else { std::printf("  FAIL: %s\n", msg); ++g_fail; } } while (0)

// Deterministic non-zero pseudo-hash: bytes 0..7 = tag LE, byte 8 = 0xC2 marker,
// byte 9 = salt (so H(0) is not all-zero and distinct tags differ).
static Hash H(std::uint64_t tag, std::uint8_t salt = 0) {
    Hash h{};
    for (int i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>((tag >> (8 * i)) & 0xff);
    h[8] = 0xC2;
    h[9] = salt;
    return h;
}
static std::string hex(const Hash& h) { return mj::hash_to_hex(h); }

// Build a get_miner_data JSON-RPC response body (result-wrapped).
static std::string miner_data_rpc(std::uint64_t height, const Hash& prev, const Hash& seed,
                                  std::uint64_t diff,
                                  const std::string& backlog = "[]") {
    return std::string("{\"id\":\"0\",\"jsonrpc\":\"2.0\",\"result\":{")
         + "\"major_version\":16,"
         + "\"height\":" + std::to_string(height) + ","
         + "\"prev_id\":\"" + hex(prev) + "\","
         + "\"seed_hash\":\"" + hex(seed) + "\","
         + "\"difficulty\":" + std::to_string(diff) + ","
         + "\"difficulty_top64\":0,"
         + "\"median_weight\":300000,"
         + "\"already_generated_coins\":18000000000000000000,"
         + "\"median_timestamp\":1600000000,"
         + "\"tx_backlog\":" + backlog + ","
         + "\"status\":\"OK\"}}";
}

// Build a json-full-miner_data ZMQ payload (top-level object, NO result wrapper).
static std::string miner_data_zmq(std::uint64_t height, const Hash& prev, const Hash& seed,
                                  std::uint64_t diff) {
    return std::string("{")
         + "\"major_version\":16,"
         + "\"height\":" + std::to_string(height) + ","
         + "\"prev_id\":\"" + hex(prev) + "\","
         + "\"seed_hash\":\"" + hex(seed) + "\","
         + "\"difficulty\":" + std::to_string(diff) + ","
         + "\"difficulty_top64\":0,"
         + "\"median_weight\":300000,"
         + "\"already_generated_coins\":18000000000000000000,"
         + "\"median_timestamp\":1600000000,"
         + "\"tx_backlog\":[]}";
}

// A get_block_header_by_height responder body for a given requested height, with
// id = H(height) (so seed backfill lands consistent ids).
static std::string block_header_rpc(std::uint64_t height) {
    return std::string("{\"id\":\"0\",\"jsonrpc\":\"2.0\",\"result\":{\"block_header\":{")
         + "\"height\":" + std::to_string(height) + ","
         + "\"timestamp\":1600000000,"
         + "\"reward\":600000000000,"
         + "\"difficulty\":1000,"
         + "\"difficulty_top64\":0,"
         + "\"hash\":\"" + hex(H(height)) + "\","
         + "\"prev_hash\":\"" + hex(H(height ? height - 1 : 0)) + "\"},\"status\":\"OK\"}}";
}

// Responder that answers get_block_header_by_height using the requested height.
static RpcResponse header_responder(const std::string& method, const std::string& body) {
    RpcResponse r;
    if (method == "get_block_header_by_height") {
        auto p = body.find("\"height\":");
        std::uint64_t h = (p == std::string::npos) ? 0
                          : std::strtoull(body.c_str() + p + 9, nullptr, 10);
        std::string b = block_header_rpc(h);
        r.body.assign(b.begin(), b.end());
    } else {
        r.error = "responder: unhandled method " + method;
    }
    return r;
}

int main() {
    // ======================================================================
    std::printf("== [0] minijson parser sanity ==\n");
    {
        const char* js = R"({"a":1,"b":"xy","c":[10,20,{"d":18446744073709551615}],"e":true})";
        mj::Value v;
        CHECK(mj::parse(js, std::strlen(js), v), "parse nested object");
        CHECK(v["a"].as_u64() == 1, "number a==1");
        CHECK(v["b"].as_string() == "xy", "string b==xy");
        CHECK(v["c"].is_array() && v["c"].arr.size() == 3, "array c size 3");
        CHECK(v["c"].arr[2]["d"].as_u64() == 18446744073709551615ull, "full u64 precision preserved");
        CHECK(v["e"].as_bool() == true, "bool e==true");
        Hash hh;
        CHECK(mj::hex_to_hash(hex(H(3000000)), hh) && hh == H(3000000), "hex<->hash round-trip");
    }

    // ======================================================================
    std::printf("== [1] RPC seam: request bodies + get_miner_data end-to-end ==\n");
    {
        CHECK(MoneroDaemonRpc::body_get_miner_data() ==
              R"({"jsonrpc":"2.0","id":"0","method":"get_miner_data"})",
              "body_get_miner_data() exact");
        CHECK(MoneroDaemonRpc::body_submit_block("deadbeef").find("\"submit_block\"") != std::string::npos,
              "body_submit_block names submit_block");
        CHECK(MoneroDaemonRpc::body_submit_block("deadbeef").find("[\"deadbeef\"]") != std::string::npos,
              "body_submit_block carries blob hex in params array");

        MockMonerodTransport mock;
        const Hash prev = H(3000000), seed = H(2998272);
        mock.set_method_body("get_miner_data", miner_data_rpc(3000001, prev, seed, 123456789ull,
            "[{\"id\":\"" + hex(H(0xAA)) + "\",\"weight\":1500,\"fee\":30000,\"blob_size\":1400},"
            "{\"id\":\"" + hex(H(0xBB)) + "\",\"weight\":2000,\"fee\":80000,\"blob_size\":1900}]"));

        MoneroDaemonRpc rpc(mock);
        std::optional<MinerData> got; std::string gotErr;
        rpc.get_miner_data([&](std::optional<MinerData> md, const std::string& e){ got = md; gotErr = e; });

        CHECK(mock.posted_bodies().size() == 1, "one RPC body posted through the seam");
        CHECK(mock.posted_bodies()[0] == MoneroDaemonRpc::body_get_miner_data(), "posted body is get_miner_data");
        CHECK(got.has_value(), "get_miner_data parsed a MinerData");
        CHECK(got && got->height == 3000001, "parsed height==3000001");
        CHECK(got && got->major_version == 16, "parsed major_version==16");
        CHECK(got && got->prev_id == prev, "parsed prev_id");
        CHECK(got && got->seed_hash == seed, "parsed seed_hash");
        CHECK(got && got->difficulty.lo == 123456789ull && got->difficulty.hi == 0, "parsed 128-bit difficulty");
        CHECK(got && got->tx_backlog.size() == 2, "parsed 2 tx_backlog entries");
        CHECK(got && got->tx_backlog[1].fee == 80000 && got->tx_backlog[1].id == H(0xBB), "backlog entry fields");
        CHECK(got && got->valid(), "MinerData::valid()");
    }

    // ======================================================================
    std::printf("== [1b] fee estimate + submit_block parse ==\n");
    {
        std::vector<char> fee;
        std::string fb = R"({"id":"0","jsonrpc":"2.0","result":{"fee":20000,"fees":[20000,80000,320000,4000000],"quantization_mask":10000,"status":"OK"}})";
        fee.assign(fb.begin(), fb.end());
        auto fe = MoneroDaemonRpc::parse_fee_estimate(fee);
        CHECK(fe.has_value() && fe->fee_per_byte == 20000, "get_fee_estimate fee/byte");
        CHECK(fe && fe->fees[3] == 4000000 && fe->quantization_mask == 10000, "fee tiers + quantization_mask");

        std::vector<char> ok;
        std::string ob = R"({"id":"0","jsonrpc":"2.0","result":{"status":"OK"}})";
        ok.assign(ob.begin(), ob.end());
        auto sb = MoneroDaemonRpc::parse_submit_block(ok);
        CHECK(sb.accepted && sb.status == "OK", "submit_block accepted");
        std::vector<char> bad;
        std::string bb = R"({"id":"0","jsonrpc":"2.0","error":{"code":-7,"message":"Block not accepted"}})";
        bad.assign(bb.begin(), bb.end());
        auto sb2 = MoneroDaemonRpc::parse_submit_block(bad);
        CHECK(!sb2.accepted && sb2.error.find("Block not accepted") != std::string::npos, "submit_block rejection surfaced");
    }

    // ======================================================================
    std::printf("== [2] adapter: get_miner_data drives tip + seed resolves ==\n");
    {
        MockMonerodTransport mock;
        mock.set_responder(header_responder);
        const Hash prev = H(3000000), seed = H(2998272);
        mock.set_method_body("get_miner_data", miner_data_rpc(3000001, prev, seed, 123456789ull));

        MonerodAdapter adapter(mock);
        adapter.start();
        adapter.initial_sync(); // pulls get_miner_data, drives on_miner_data

        CHECK(adapter.index().best_height() == 3000000, "tip height == miner_data.height-1");
        CHECK(adapter.index().best_id() == prev, "tip id == miner_data.prev_id");
        CHECK(adapter.latest_miner_data().has_value(), "latest_miner_data cached for W5");
        // rx_seed_height(3000001) == 2998272 == rx_seed_height(3000000).
        CHECK(rx_seed_height(3000001) == 2998272, "rx_seed_height(3000001)==2998272 (X1 primitive)");
        auto s = adapter.index().seed_hash_for_height(3000000);
        CHECK(s.has_value() && *s == seed, "seed_hash_for_height(tip)==miner_data.seed_hash (no RPC needed)");
    }

    // ======================================================================
    std::printf("== [3] adapter: small reorg via miner_data surfaces Orphan+Reorg ==\n");
    {
        std::vector<MainchainEvent> log;
        MockMonerodTransport mock;
        mock.set_responder(header_responder);
        MonerodAdapter adapter(mock);
        adapter.set_event_sink([&](const MainchainEvent& e){ log.push_back(e); });

        // Extend tips 1..20 by feeding miner_data for heights 2..21.
        for (std::uint64_t tip = 1; tip <= 20; ++tip) {
            MinerData md;
            md.major_version = 16;
            md.height   = tip + 1;
            md.prev_id  = H(tip);
            md.seed_hash = H(rx_seed_height(md.height));
            md.difficulty = Difficulty128{1000 + tip, 0};
            adapter.on_miner_data(md);
        }
        CHECK(adapter.index().best_height() == 20, "best_height==20 after 20 extends");
        log.clear();

        // monerod reorgs: the new tip is 19' (salt 1). A miner_data mining block 20
        // on the competing branch has prev_id == id(19'), height == 20 <= best.
        {
            MinerData md;
            md.major_version = 16;
            md.height   = 20;                 // mining block 20 again, new branch
            md.prev_id  = H(19, /*salt*/1);   // new tip id at height 19
            md.seed_hash = H(rx_seed_height(20));
            md.difficulty = Difficulty128{2000, 0};
            adapter.on_miner_data(md);
        }
        int orphans = 0, reorgs = 0; std::uint64_t depth = 0;
        for (auto& e : log) {
            if (e.kind == MainchainEventKind::Orphan) ++orphans;
            if (e.kind == MainchainEventKind::Reorg) { ++reorgs; depth = e.depth; }
        }
        CHECK(orphans == 2, "2 Orphan events (old heights 20 and 19)");
        CHECK(reorgs == 1 && depth == 2, "1 Reorg event, depth==2");
        CHECK(adapter.index().best_height() == 19, "best_height rolled back to 19");
        CHECK(adapter.index().best_id() == H(19, 1), "best tip is the competitor 19'");
        CHECK(adapter.index().confirmation_depth(H(20)) == 0, "orphaned old tip 20 depth==0");
        CHECK(adapter.index().confirmation_depth(H(19)) == 0, "orphaned old 19 depth==0");
        CHECK(adapter.index().confirmation_depth(H(19, 1)) == 1, "new tip 19' depth==1");
        CHECK(adapter.index().confirmation_depth(H(18)) == 2, "common-ancestor 18 survived, depth==2");
    }

    // ======================================================================
    std::printf("== [4] >= 2112 seed reach + anchor pinning under prune + RPC backfill ==\n");
    {
        MockMonerodTransport mock;
        mock.set_responder(header_responder); // backfills any missing anchor by height
        MonerodAdapter adapter(mock, {}, /*retain_recent*/720);

        for (std::uint64_t tip = 1; tip <= 4880; ++tip) {
            MinerData md;
            md.major_version = 16;
            md.height    = tip + 1;
            md.prev_id   = H(tip);
            md.seed_hash = H(rx_seed_height(md.height)); // hands the epoch anchor directly
            md.difficulty = Difficulty128{1000 + tip, 0};
            adapter.on_miner_data(md);
        }
        auto& idx = adapter.index();
        CHECK(idx.best_height() == 4880, "best_height==4880");
        CHECK(SEED_REACH_MIN == 2112, "SEED_REACH_MIN==2112 (from X1 epoch+lag)");
        CHECK(idx.by_height(2048).has_value() && idx.by_height(2048)->id == H(2048), "seed anchor 2048 pinned below the 720 window");
        CHECK(idx.by_height(4096).has_value() && idx.by_height(4096)->id == H(4096), "seed anchor 4096 pinned");
        auto s = idx.seed_hash_for_height(4160);
        CHECK(s.has_value() && *s == H(2048), "seed_hash_for_height(4160)==id(2048)");
        CHECK(4160 - 2048 == 2112, "verified reach depth from window bottom == 2112");
        CHECK(idx.seed_reach_satisfied() && idx.missing_seed_heights().empty(), "seed reach satisfied");
        CHECK(!idx.by_height(100).has_value(), "old non-anchor height 100 pruned");
        CHECK(idx.by_height(4200).has_value(), "recent height 4200 retained");
    }

    // ======================================================================
    std::printf("== [5] ZMQ end-to-end through the seam (3 topics) ==\n");
    {
        MockMonerodTransport mock;
        mock.set_responder(header_responder);
        MonerodAdapter adapter(mock);
        adapter.start();
        CHECK(mock.subscribed(ZMQ_TOPIC_MINER_DATA), "subscribed json-full-miner_data");
        CHECK(mock.subscribed(ZMQ_TOPIC_TXPOOL_ADD), "subscribed json-minimal-txpool_add");
        CHECK(mock.subscribed(ZMQ_TOPIC_CHAIN_MAIN), "subscribed json-full-chain_main");

        // (a) json-full-miner_data advances the tip.
        const Hash prev = H(555000), seed = H(rx_seed_height(555001));
        mock.push_zmq(ZMQ_TOPIC_MINER_DATA, miner_data_zmq(555001, prev, seed, 987654321ull));
        CHECK(adapter.index().best_height() == 555000, "ZMQ miner_data set tip==555000");
        CHECK(adapter.index().best_id() == prev, "ZMQ tip id==prev_id");

        // (b) json-minimal-txpool_add grows the backlog.
        std::string txpool = "[{\"id\":\"" + hex(H(0x11)) + "\",\"blob_size\":1200,\"weight\":1300,\"fee\":50000},"
                             "{\"id\":\"" + hex(H(0x22)) + "\",\"blob_size\":900,\"weight\":900,\"fee\":12000}]";
        mock.push_zmq(ZMQ_TOPIC_TXPOOL_ADD, txpool);
        CHECK(adapter.index().backlog().size() == 2, "ZMQ txpool_add added 2 backlog txs");
        CHECK(adapter.index().backlog()[0].fee == 50000, "backlog tx fee decoded");

        // (c) json-full-chain_main annotates the tip's plaintext coinbase reward.
        std::string chain = "[{\"major_version\":16,\"minor_version\":16,\"timestamp\":1601234567,"
                            "\"prev_id\":\"" + hex(H(554999)) + "\",\"nonce\":42,"
                            "\"miner_tx\":{\"vin\":[{\"gen\":{\"height\":555000}}],"
                            "\"vout\":[{\"amount\":300000000000},{\"amount\":300000000000}]},"
                            "\"tx_hashes\":[\"" + hex(H(0x33)) + "\"]}]";
        mock.push_zmq(ZMQ_TOPIC_CHAIN_MAIN, chain);
        auto row = adapter.index().by_height(555000);
        CHECK(row.has_value() && row->reward == 600000000000ull, "chain_main annotated coinbase reward (0.6 XMR)");
        CHECK(row.has_value() && row->timestamp == 1601234567ull, "chain_main annotated timestamp");
    }

    // ======================================================================
    std::printf("== [6] submit_block round-trip through the seam ==\n");
    {
        MockMonerodTransport mock;
        mock.set_method_body("submit_block", R"({"id":"0","jsonrpc":"2.0","result":{"status":"OK"}})");
        MonerodAdapter adapter(mock);
        bool accepted = false; std::string err;
        adapter.submit_block("0f0f0fbeef", [&](std::optional<SubmitBlockResult> r, const std::string& e){
            if (r) { accepted = r->accepted; }
            err = e;
        });
        CHECK(accepted, "submit_block accepted through adapter");
        CHECK(!mock.posted_bodies().empty() &&
              mock.posted_bodies().back().find("0f0f0fbeef") != std::string::npos,
              "submit_block posted the blob hex through the seam");
    }

    // ======================================================================
    std::printf("== [7] live-wire regression: monerod v0.18 hex-string difficulty ==\n");
    {
        // VERBATIM get_miner_data response body captured from monerod v0.18.5.1
        // (stagenet, 2026-09-07, height 2202216), CRLF pretty-print included.
        // "difficulty" is a "0x..." hex STRING, not a number: before this vector
        // the parsers read it as 0, MinerData::valid() rejected every frame and
        // the live c2pool-v37-xmr daemon never applied a tip (hw_height stayed 0).
        static const char* kWire =
            "{\r\n  \"id\": \"0\",\r\n  \"jsonrpc\": \"2.0\",\r\n  \"result\": {\r\n"
            "    \"already_generated_coins\": 18162842501536847281,\r\n"
            "    \"difficulty\": \"0x36de33\",\r\n"
            "    \"height\": 2202216,\r\n"
            "    \"major_version\": 16,\r\n"
            "    \"median_weight\": 300000,\r\n"
            "    \"prev_id\": \"914d16a7fb163667e7837ea728ed326d7fbf483d8f364388c00814294559d2a5\",\r\n"
            "    \"seed_hash\": \"9bde15898b36a6b811fa85bb4fb403aed61006318a7762b33b87a0be333976dc\",\r\n"
            "    \"status\": \"OK\",\r\n"
            "    \"tx_backlog\": [{\r\n"
            "      \"fee\": 121920000,\r\n"
            "      \"id\": \"80f854da409ddb7b49b792a91c48f87f541b271128228a7abdf0442a535b2fa7\",\r\n"
            "      \"weight\": 1524\r\n"
            "    }],\r\n"
            "    \"untrusted\": false\r\n"
            "  }\r\n}";

        // (a) the hex_to_u128 primitive.
        std::uint64_t hi = 1, lo = 1;
        CHECK(mj::hex_to_u128("0x36de33", hi, lo) && hi == 0 && lo == 0x36de33ull,
              "hex_to_u128(\"0x36de33\") == (0, 0x36de33)");
        CHECK(mj::hex_to_u128("0x1ffffffffffffffff", hi, lo) && hi == 1 && lo == 0xffffffffffffffffull,
              "hex_to_u128 crosses the 64-bit boundary into hi");
        CHECK(mj::hex_to_u128("36DE33", hi, lo) && hi == 0 && lo == 0x36de33ull,
              "hex_to_u128 accepts no-prefix upper-case hex");
        CHECK(!mj::hex_to_u128("0x", hi, lo) && !mj::hex_to_u128("", hi, lo) &&
              !mj::hex_to_u128("0xzz", hi, lo) &&
              !mj::hex_to_u128("0x123456789012345678901234567890123", hi, lo),
              "hex_to_u128 rejects empty / non-hex / > 128-bit");

        // (b) RPC path: MoneroDaemonRpc::get_miner_data through the seam.
        MockMonerodTransport mock;
        mock.set_method_body("get_miner_data", kWire);
        MoneroDaemonRpc rpc(mock);
        std::optional<MinerData> got;
        rpc.get_miner_data([&](std::optional<MinerData> md, const std::string&){ got = md; });
        CHECK(got.has_value(), "RPC: live stagenet get_miner_data body parses");
        CHECK(got && got->difficulty.lo == 0x36de33ull && got->difficulty.hi == 0,
              "RPC: hex-string difficulty == 0x36de33");
        CHECK(got && got->valid() && got->height == 2202216 && got->major_version == 16,
              "RPC: MinerData::valid() holds on the live body");
        CHECK(got && got->tx_backlog.size() == 1 && got->tx_backlog[0].fee == 121920000ull &&
              got->tx_backlog[0].weight == 1524,
              "RPC: live tx_backlog entry decoded");
        CHECK(got && got->already_generated_coins == 18162842501536847281ull,
              "RPC: already_generated_coins > 2^63 preserved");

        // (c) poll-fallback path: the live transport (xmr_live_transport.hpp
        //     pump_poll) forwards this SAME result-wrapped body as a
        //     json-full-miner_data frame; the ZMQ decoder must accept it too.
        std::vector<char> payload(kWire, kWire + std::strlen(kWire));
        auto md2 = ZmqSubscriber::parse_miner_data_payload(payload);
        CHECK(md2.has_value() && md2->valid() && md2->difficulty.lo == 0x36de33ull,
              "ZMQ/poll: result-wrapped live body parses with hex difficulty");

        // (d) numeric difficulty (mock / older wire shape) still parses.
        const Hash prev = H(3000000), seed = H(2998272);
        MockMonerodTransport mock_num;
        mock_num.set_method_body("get_miner_data", miner_data_rpc(3000001, prev, seed, 123456789ull));
        MoneroDaemonRpc rpc_num(mock_num);
        std::optional<MinerData> got_num;
        rpc_num.get_miner_data([&](std::optional<MinerData> md, const std::string&){ got_num = md; });
        CHECK(got_num && got_num->difficulty.lo == 123456789ull && got_num->difficulty.hi == 0,
              "RPC: numeric difficulty + difficulty_top64 still parse");

        // (e) end-to-end: the adapter applies the live tip from the wire body.
        MonerodAdapter adapter(mock);
        adapter.start();
        adapter.initial_sync();
        CHECK(adapter.index().best_height() == 2202215, "adapter: live body drives tip == 2202215");
        Hash want_tip;
        CHECK(mj::hex_to_hash("914d16a7fb163667e7837ea728ed326d7fbf483d8f364388c00814294559d2a5", want_tip) &&
              adapter.index().best_id() == want_tip,
              "adapter: tip id == live prev_id");
    }

    std::printf("\n%s (%d failure%s)\n", g_fail ? "RESULT: FAIL" : "RESULT: PASS",
                g_fail, g_fail == 1 ? "" : "s");
    return g_fail ? 1 : 0;
}
