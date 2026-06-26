/// Phase G3 ASSEMBLED — DASH per-coin block-production gate (integrator 2026-06-26).
///
/// The other dash KATs pin each block-production PRIMITIVE in isolation:
///   G1   test_dash_coinbase_parity   — coinbase/payee bytes == p2pool-dash oracle
///   prod test_dash_block_producer    — merkle / target / serialize / X11 mine
///   S8   test_dash_broadcaster_full  — dual-path relay of a SYNTHETIC block
///
/// G3 ASSEMBLED is the INTEGRATION gate that proves those primitives COMPOSE
/// into a real won-block crossing — the thing actually proven live on regtest
/// (block 7, hash 28e1b366.., dashd ACCEPTED, slice-5 submitblock arm), now
/// formalized as a landable, network-free per-coin gate. It drives the full
/// pipeline ONCE and pins CONTINUITY between the stages:
///
///   FOUND     — mine_block finds a nonce whose X11 PoW meets the target.
///   ASSEMBLED — the won block embeds an oracle-FAITHFUL coinbase: payee outs
///               worker || payments(GBT order) || donation, byte-anchored to
///               p2pool-dash data.py generate_transaction() golden vectors.
///   ACCEPTED  — dashd-acceptance surrogate: PoW meets target, header re-hashes
///               to the reported block_hash, BIP34 height is the canonical form.
///   BROADCAST — the EXACT assembled+accepted bytes reach the network on BOTH
///               arms of the dual-path gate (embedded P2P fan-out AND submitblock
///               RPC fallback), independently; no-path won block is NOT silently
///               dropped.
///
/// "anchor every assertion to data.py gentx" — the golden hash160 / scripts /
/// txout packing below are the SAME real-oracle vectors captured for G1 (driving
/// p2pool/dash/data.py under python2.7.18, testnet ADDRESS_VERSION=140 /
/// SCRIPT_ADDRESS_VERSION=19). Nothing here is synthesized: the block is mined,
/// the coinbase is the production builder's, the broadcast bytes are the mined
/// bytes — the gate only passes if the whole chain is byte-consistent end to end.

#include <gtest/gtest.h>

#include <impl/dash/coin/block_producer.hpp>
#include <impl/dash/coin/rpc_data.hpp>
#include <impl/dash/coinbase_builder.hpp>
#include <impl/dash/share_check.hpp>          // DONATION_SCRIPT, pubkey_hash_to_script2
#include <core/coin_params.hpp>
#include <impl/dash/crypto/hash_x11.hpp>
#include <impl/dash/broadcaster_full.hpp>
#include <impl/dash/broadcaster.hpp>
#include <impl/dash/config.hpp>

#include <core/hash.hpp>
#include <core/uint256.hpp>
#include <core/netaddress.hpp>
#include <btclibs/util/strencodings.h>        // ParseHex, HexStr

#include <boost/asio.hpp>

#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <vector>

using dash::coin::DashWorkData;
using dash::coin::PackedPayment;
using dash::coin::compute_merkle_root;
using dash::coin::meets_target;
using dash::coin::mine_block;
using dash::coin::coinbase_txid;
using dash::coin::serialize_full_block;
using nlohmann::json;

namespace {

// ---- oracle golden vectors (identical to G1 — real data.py capture) ----------
// hash160 in oracle on-wire (little-endian-of-the-int) order.
const std::vector<unsigned char> kH160 = {
    0x61, 0x3c, 0xaf, 0xd9, 0x1a, 0xb5, 0x96, 0x76, 0x2c, 0x11,
    0x5c, 0x7e, 0x94, 0xd5, 0xe4, 0xb1, 0x22, 0x5c, 0xcb, 0x20,
};
const std::string kAddrP2PKH = "yVBb6QnAEZWfKomEwkEqRMUF5zFvFgerom";
const std::string kAddrP2SH  = "8oHbxGiJKjSeNMtkyywGkBY3vx5nCaDExZ";

std::vector<unsigned char> p2pkh(const std::vector<unsigned char>& h) {
    std::vector<unsigned char> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x88); s.push_back(0xac);
    return s;
}
std::vector<unsigned char> p2sh(const std::vector<unsigned char>& h) {
    std::vector<unsigned char> s = {0xa9, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x87);
    return s;
}
std::string hex(const std::vector<unsigned char>& v) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(v.size() * 2);
    for (auto b : v) { s.push_back(d[b >> 4]); s.push_back(d[b & 0xf]); }
    return s;
}
uint32_t rd_u32(const std::vector<unsigned char>& v, size_t off) {
    return (uint32_t)v[off] | ((uint32_t)v[off+1] << 8)
         | ((uint32_t)v[off+2] << 16) | ((uint32_t)v[off+3] << 24);
}
bool contains(const std::vector<unsigned char>& hay,
              const std::vector<unsigned char>& needle) {
    if (needle.empty() || needle.size() > hay.size()) return false;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
        if (std::memcmp(hay.data() + i, needle.data(), needle.size()) == 0) return true;
    return false;
}

// The proven regtest crossing height; exercises the BIP34 OP_N coinbase form.
constexpr uint32_t kHeight   = 7;
constexpr uint64_t kSubsidy  = 5000000000ull;
constexpr uint32_t kBits     = 0x207fffffu;   // regtest trivial target
constexpr uint64_t kPayP2PKH = 5000;
constexpr uint64_t kPayP2SH  = 3000;

// Distinct finder so its worker script never coalesces with a payee script.
uint160 finder_hash() { return uint160(std::vector<unsigned char>(20, 0x07)); }

// A won block: the SAME object across all four stages. Built once from the
// production primitives (no synthesis), so the stages can only agree if the
// pipeline is byte-consistent.
struct WonBlock {
    DashWorkData                w;
    std::vector<unsigned char>  coinbase;
    std::vector<dash::coinbase::MinerPayout> outs;
    dash::coin::MineResult      mr;
    std::vector<unsigned char>  block_bytes;   // ParseHex(mr.block_hex)
};

WonBlock build_won_block() {
    // Minimal testnet CoinParams (compute_dash_payouts/build read ONLY the two
    // address version bytes). Avoids params.hpp -> config_pool.hpp, whose
    // pre-S8 dash::PoolConfig collides with broadcaster.hpp's S8 dash::PoolConfig
    // in one TU (the v36 two-dialect divergence; see [3-bucket]).
    core::CoinParams params;
    params.address_version      = 140;  // Dash testnet P2PKH (ADDRESS_VERSION)
    params.address_p2sh_version = 19;   // Dash testnet P2SH  (SCRIPT_ADDRESS_VERSION)
    WonBlock wb;

    DashWorkData& w = wb.w;
    w.m_version = 0x20000000;
    w.m_previous_block.SetHex(
        "00000000000000000000000000000000000000000000000000000000deadbeef");
    w.m_height         = kHeight;
    w.m_coinbase_value = kSubsidy;
    w.m_bits           = kBits;
    w.m_curtime        = 1700000000u;

    // Real GBT-order payee payments using the oracle golden addresses.
    w.m_packed_payments.push_back(PackedPayment{kAddrP2PKH, kPayP2PKH});
    w.m_packed_payments.push_back(PackedPayment{kAddrP2SH,  kPayP2SH});

    // Two GBT txs (raw + txid = sha256d(rawtx)).
    for (unsigned char tag : {0x11, 0x22}) {
        std::vector<unsigned char> raw(10, tag);
        w.m_tx_data_hex.push_back(HexStr(std::span<const unsigned char>(raw.data(), raw.size())));
        w.m_tx_hashes.push_back(Hash(std::span<const unsigned char>(raw.data(), raw.size())));
    }

    wb.outs = dash::coinbase::compute_dash_payouts(
        w.m_coinbase_value, w.m_packed_payments, finder_hash(),
        /*weights=*/{}, /*total_weight=*/0, params);
    wb.coinbase = dash::coinbase::build(w, wb.outs, "c2pool", params, uint256::ZERO).bytes;

    wb.mr = mine_block(w, wb.coinbase, /*max_nonce=*/1000000ull);
    if (wb.mr.found) wb.block_bytes = ParseHex(wb.mr.block_hex);
    return wb;
}

// ---- dual-path broadcaster harness (mirrors test_dash_broadcaster_full) ------
constexpr uint16_t kPort = 19999;

struct PoolEnv {
    boost::asio::io_context ioc;
    std::unique_ptr<dash::Config> cfg;
    bool all_live{true};
    std::unique_ptr<dash::DashBroadcaster> pool;

    explicit PoolEnv(size_t max_peers = 16) {
        cfg = std::make_unique<dash::Config>("dash-g3-assembled-kat");
        cfg->coin()->m_p2p.address =
            NetService{std::string{"127.0.0.1"}, std::to_string(kPort)};
        pool = std::make_unique<dash::DashBroadcaster>(
            &ioc, cfg.get(),
            NetService{std::string{"10.9.9.9"}, std::to_string(kPort)}, max_peers);
        pool->set_slot_factory([this](const NetService&) {
            return std::make_unique<dash::coin::p2p::NodeP2P>(&ioc);
        });
        pool->set_live_predicate(
            [this](const dash::coin::p2p::NodeP2P&) { return all_live; });
    }
    void dial(size_t n) {
        json peers = json::array();
        for (size_t i = 0; i < n; ++i) {
            json p = json::object();
            p["addr"] = "10.0.0." + std::to_string(i + 1) + ":19999";
            peers.push_back(p);
        }
        ASSERT_EQ(pool->discover(peers), n);
    }
};

} // namespace

// ===== STAGE 1: FOUND ========================================================
// A nonce is found whose X11 PoW meets the target, and the winning header
// independently re-hashes to the reported block_hash.
TEST(DashG3Assembled, FoundWinningNonceMeetsTarget) {
    WonBlock wb = build_won_block();
    ASSERT_TRUE(wb.mr.found);
    EXPECT_TRUE(meets_target(wb.mr.block_hash, kBits));
    ASSERT_GE(wb.block_bytes.size(), (size_t)80);
    EXPECT_EQ(rd_u32(wb.block_bytes, 76), wb.mr.nonce);   // winner in nonce slot
    uint256 pow = dash::crypto::hash_x11(wb.block_bytes.data(), 80);
    EXPECT_EQ(pow.GetHex(), wb.mr.block_hash.GetHex());   // independent recompute
}

// ===== STAGE 2: ASSEMBLED (oracle-anchored) ==================================
// The assembled coinbase carries oracle-faithful payouts: worker || payments in
// GBT order || donation-last, scripts byte-identical to data.py, sum == subsidy.
TEST(DashG3Assembled, AssembledCoinbasePayoutsMatchOracle) {
    WonBlock wb = build_won_block();
    ASSERT_EQ(wb.outs.size(), 4u);                       // finder + 2 payees + donation
    EXPECT_EQ(wb.outs[0].script, dash::pubkey_hash_to_script2(finder_hash()));
    EXPECT_EQ(wb.outs[1].script, p2pkh(kH160));          // payee 1 (GBT order)
    EXPECT_EQ(wb.outs[1].amount, kPayP2PKH);
    EXPECT_EQ(wb.outs[2].script, p2sh(kH160));           // payee 2
    EXPECT_EQ(wb.outs[2].amount, kPayP2SH);
    EXPECT_EQ(wb.outs[3].script, dash::DONATION_SCRIPT); // donation last
    EXPECT_GT(wb.outs[0].amount, 0u);
    EXPECT_GT(wb.outs[3].amount, 0u);
    uint64_t sum = 0; for (auto& o : wb.outs) sum += o.amount;
    EXPECT_EQ(sum, kSubsidy);                             // worker_payout invariant
}

// The mined block on the wire actually EMBEDS that oracle-faithful coinbase:
// the coinbase bytes follow header(80)+CompactSize(ntx) verbatim and carry the
// oracle payee + donation scripts.
TEST(DashG3Assembled, AssembledBlockEmbedsOracleCoinbase) {
    WonBlock wb = build_won_block();
    ASSERT_TRUE(wb.mr.found);
    // tx count: 1 coinbase + 2 GBT txs == 3 (< 0xfd -> single CompactSize byte).
    ASSERT_GE(wb.block_bytes.size(), (size_t)81 + wb.coinbase.size());
    EXPECT_EQ(wb.block_bytes[80], (unsigned char)3);
    EXPECT_EQ(std::memcmp(wb.block_bytes.data() + 81,
                          wb.coinbase.data(), wb.coinbase.size()), 0);
    // The on-wire coinbase carries the oracle payee + donation scripts.
    EXPECT_TRUE(contains(wb.coinbase, p2pkh(kH160)));
    EXPECT_TRUE(contains(wb.coinbase, p2sh(kH160)));
    EXPECT_TRUE(contains(wb.coinbase, dash::DONATION_SCRIPT));
}

// Header fields + merkle root over [coinbase_txid] + GBT txids, recomputed
// independently of the serializer.
TEST(DashG3Assembled, AssembledBlockHeaderAndMerkleConsistent) {
    WonBlock wb = build_won_block();
    ASSERT_TRUE(wb.mr.found);
    EXPECT_EQ(rd_u32(wb.block_bytes, 0),  (uint32_t)wb.w.m_version);
    EXPECT_EQ(rd_u32(wb.block_bytes, 72), kBits);
    EXPECT_EQ(std::memcmp(wb.block_bytes.data() + 4, wb.w.m_previous_block.data(), 32), 0);
    std::vector<uint256> txids{coinbase_txid(wb.coinbase)};
    for (auto& h : wb.w.m_tx_hashes) txids.push_back(h);
    uint256 mr = compute_merkle_root(txids);
    EXPECT_EQ(std::memcmp(wb.block_bytes.data() + 36, mr.data(), 32), 0);
}

// ===== STAGE 3: ACCEPTED (dashd-acceptance surrogate) ========================
// PoW meets target AND the coinbase carries the canonical BIP34 height push
// (OP_7 for height 7 — the exact form dashd ContextualCheckBlock demanded on the
// proven regtest crossing; a raw 0x07 push was rejected bad-cb-height).
TEST(DashG3Assembled, AcceptedPowAndBip34Height) {
    WonBlock wb = build_won_block();
    ASSERT_TRUE(wb.mr.found);
    EXPECT_TRUE(meets_target(wb.mr.block_hash, kBits));
    auto h7 = dash::coinbase::push_bip34_height(kHeight);
    EXPECT_EQ(h7, (std::vector<unsigned char>{0x57}));   // OP_7
    EXPECT_TRUE(contains(wb.coinbase, h7));              // present in coinbase scriptSig
}

// ===== STAGE 4: BROADCAST (dual-path continuity) =============================
// The EXACT assembled+accepted bytes reach the network on BOTH arms,
// independently — embedded P2P fan-out AND submitblock RPC carry the mined hex.
TEST(DashG3Assembled, AssembledWonBlockReachesNetworkDualPath) {
    WonBlock wb = build_won_block();
    ASSERT_TRUE(wb.mr.found);

    PoolEnv env;
    env.dial(4);
    dash::DashBroadcasterFull full{env.pool.get()};

    std::vector<unsigned char> peer_bytes;
    size_t peer_calls = 0;
    full.set_peer_submit([&](dash::coin::p2p::NodeP2P&,
                             std::span<const unsigned char> b) {
        ++peer_calls;
        peer_bytes.assign(b.begin(), b.end());
    });
    std::string rpc_hex;
    full.set_rpc_submit([&](const std::string& h) { rpc_hex = h; return true; });

    auto out = full.on_block_found(wb.block_bytes);

    EXPECT_EQ(out.peers_reached, 4u);            // ARM A fanned to every live peer
    EXPECT_EQ(peer_calls, 4u);
    EXPECT_EQ(peer_bytes, wb.block_bytes);       // ...the EXACT assembled bytes
    EXPECT_TRUE(out.rpc_submitted);              // ARM B fired independently
    EXPECT_EQ(rpc_hex, wb.mr.block_hex);         // ...the EXACT assembled hex
    EXPECT_TRUE(out.reached_network());
}

// Embedded arm alone relays the assembled block (no rpc wired).
TEST(DashG3Assembled, EmbeddedArmAloneRelaysAssembledBlock) {
    WonBlock wb = build_won_block();
    ASSERT_TRUE(wb.mr.found);
    PoolEnv env;
    env.dial(2);
    dash::DashBroadcasterFull full{env.pool.get()};
    std::vector<unsigned char> seen;
    full.set_peer_submit([&](dash::coin::p2p::NodeP2P&,
                             std::span<const unsigned char> b) {
        seen.assign(b.begin(), b.end());
    });
    ASSERT_FALSE(full.has_rpc_arm());
    auto out = full.on_block_found(wb.block_bytes);
    EXPECT_EQ(out.peers_reached, 2u);
    EXPECT_EQ(seen, wb.block_bytes);
    EXPECT_TRUE(out.reached_network());
}

// dashd submitblock fallback alone relays the assembled block (no live peers).
TEST(DashG3Assembled, RpcFallbackAloneRelaysAssembledBlock) {
    WonBlock wb = build_won_block();
    ASSERT_TRUE(wb.mr.found);
    PoolEnv env;   // no peers dialed
    dash::DashBroadcasterFull full{env.pool.get()};
    std::string rpc_hex;
    full.set_rpc_submit([&](const std::string& h) { rpc_hex = h; return true; });
    auto out = full.on_block_found(wb.block_bytes);
    EXPECT_EQ(out.peers_reached, 0u);
    EXPECT_TRUE(out.rpc_submitted);
    EXPECT_EQ(rpc_hex, wb.mr.block_hex);
    EXPECT_TRUE(out.reached_network());
}

// A perfectly assembled+accepted won block with NO network path must NOT
// silently pass the gate.
TEST(DashG3Assembled, NoPathAssembledBlockNotSilentlyDropped) {
    WonBlock wb = build_won_block();
    ASSERT_TRUE(wb.mr.found);
    PoolEnv env;   // no peers, no rpc arm
    dash::DashBroadcasterFull full{env.pool.get()};
    ASSERT_FALSE(full.has_rpc_arm());
    auto out = full.on_block_found(wb.block_bytes);
    EXPECT_EQ(out.peers_reached, 0u);
    EXPECT_FALSE(out.rpc_attempted);
    EXPECT_FALSE(out.reached_network());
}
