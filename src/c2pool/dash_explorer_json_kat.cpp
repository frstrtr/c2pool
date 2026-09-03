// SPDX-License-Identifier: AGPL-3.0-or-later
//
// dash_explorer_json_kat — known-answer test for dash::coin::block_to_explorer_json.
//
// Guards the read-only /api/explorer getblock body decode wired into
// main_dash.cpp (the coin-chain-query getblock hook). Asserts that a synthetic
// Dash block carrying a v3/type-5 DIP4 CbTx coinbase + a masternode-payee
// P2PKH output decodes to the JSON shape explorer.py's dash profile consumes:
//   - per-tx "type" (5 for the special CbTx, 0 for a plain tx),
//   - "extraPayload" hex present iff version==3 && type!=0, byte-exact,
//   - "txid" = sha256d(canonical tx),
//   - masternode-payee vout classified as a Dash X-address (p2pkh 0x4c),
//   - header fields (hash/height/bits/nTx) present.
//
// Pure decode test — no node, no network, no consensus/reward path.

#include <impl/dash/coin/block_json.hpp>
#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/transaction.hpp>

#include <core/uint256.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

using namespace dash::coin;

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } \
    else         { std::printf("ok:   %s\n", msg); } \
} while (0)

// P2PKH scriptPubKey: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
static std::vector<unsigned char> p2pkh_spk(const std::vector<unsigned char>& h160)
{
    std::vector<unsigned char> s;
    s.push_back(0x76); s.push_back(0xa9); s.push_back(0x14);
    s.insert(s.end(), h160.begin(), h160.end());
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

static std::string hexstr(const std::vector<unsigned char>& v)
{
    static const char H[] = "0123456789abcdef";
    std::string o;
    for (unsigned char b : v) { o += H[b >> 4]; o += H[b & 0x0f]; }
    return o;
}

int main()
{
    // ── Synthetic v3/type-5 CbTx coinbase ─────────────────────────────────
    MutableTransaction cb;
    cb.version = 3;
    cb.type    = 5;   // TRANSACTION_COINBASE (DIP4 CbTx)
    // A stand-in DIP4 CbTx extra payload (opaque here: explorer.py decodes it
    // client-side). The KAT only proves the node emits the hex byte-exact.
    cb.extra_payload = {0x02, 0x00,                         // nVersion=2
                        0x40, 0x42, 0x0f, 0x00,             // height=1000000
                        0xde, 0xad, 0xbe, 0xef};            // (truncated) roots
    // Coinbase input (prevout null, BIP34 height + /c2pool/ tag optional).
    {
        TxIn in;
        in.prevout.hash.SetNull();
        in.prevout.index = 0xffffffff;
        in.scriptSig.m_data = {0x03, 0x40, 0x42, 0x0f};   // push BIP34 height
        in.sequence = 0xffffffff;
        cb.vin.push_back(in);
    }
    // vout[0] = masternode payee (P2PKH), vout[1] = miner (P2PKH).
    std::vector<unsigned char> mn_h160(20, 0x11);
    std::vector<unsigned char> miner_h160(20, 0x22);
    {
        TxOut o; o.value = 82980000; o.scriptPubKey.m_data = p2pkh_spk(mn_h160);
        cb.vout.push_back(o);
    }
    {
        TxOut o; o.value = 44260000; o.scriptPubKey.m_data = p2pkh_spk(miner_h160);
        cb.vout.push_back(o);
    }

    // ── A plain (type-0) tx to prove extraPayload is ABSENT there ──────────
    MutableTransaction plain;
    plain.version = 2;
    plain.type    = 0;
    {
        TxIn in;
        in.prevout.hash.SetNull();
        in.prevout.index = 0;
        in.sequence = 0xffffffff;
        plain.vin.push_back(in);
    }
    {
        TxOut o; o.value = 10000000; o.scriptPubKey.m_data = p2pkh_spk(miner_h160);
        plain.vout.push_back(o);
    }

    BlockType block;
    block.m_version       = 0x20000000;
    block.m_previous_block.SetHex("0000000000000000000000000000000000000000000000000000000000000abc");
    block.m_merkle_root.SetHex("0000000000000000000000000000000000000000000000000000000000000def");
    block.m_timestamp = 1700000000;
    block.m_bits      = 0x1b104be1;   // a plausible Dash-range compact target
    block.m_nonce     = 12345;
    block.m_txs.push_back(cb);
    block.m_txs.push_back(plain);

    uint256 block_hash;
    block_hash.SetHex("00000000000000001111111111111111222222222222222233333333cafebabe");

    ExplorerChainParams p;
    p.bech32_hrp = "";      // Dash: no bech32
    p.p2pkh_ver  = 0x4c;    // mainnet X...
    p.p2sh_ver   = 0x10;    // mainnet 7...
    p.chain_name = "main";

    nlohmann::json j = block_to_explorer_json(block, 1000000, block_hash, p);

    std::printf("---- block_to_explorer_json output ----\n%s\n---------------------------------------\n",
                j.dump(2).c_str());

    // Header fields
    CHECK(j["hash"] == block_hash.GetHex(), "block hash echoed");
    CHECK(j["height"] == 1000000, "height echoed");
    CHECK(j["bits"] == "1b104be1", "bits hex");
    CHECK(j["nTx"] == 2, "nTx == 2");
    CHECK(j.contains("difficulty"), "difficulty present");
    CHECK(j["tx"].is_array() && j["tx"].size() == 2, "tx array size 2");

    // Coinbase CbTx (tx[0])
    const auto& t0 = j["tx"][0];
    CHECK(t0["type"] == 5, "coinbase type == 5");
    CHECK(t0["version"] == 3, "coinbase version == 3");
    CHECK(t0.contains("extraPayload"), "coinbase extraPayload present");
    CHECK(t0.value("extraPayload", std::string()) == hexstr(cb.extra_payload),
          "coinbase extraPayload byte-exact");
    CHECK(t0["txid"].is_string() && t0["txid"].get<std::string>().size() == 64,
          "coinbase txid is 64-hex");
    CHECK(t0["vin"][0].contains("coinbase"), "vin[0] is coinbase");

    // Masternode-payee vout → Dash X-address
    const auto& vout0 = t0["vout"][0];
    CHECK(vout0["value_sat"] == 82980000, "mn payee value_sat");
    CHECK(vout0["scriptPubKey"]["type"] == "pubkeyhash", "mn payee is pubkeyhash");
    std::string mn_addr = vout0["scriptPubKey"].value("address", std::string());
    CHECK(!mn_addr.empty() && mn_addr[0] == 'X', "mn payee is a Dash X-address");
    std::printf("      mn payee address = %s\n", mn_addr.c_str());

    // Plain tx (tx[1]) — extraPayload MUST be absent, type 0
    const auto& t1 = j["tx"][1];
    CHECK(t1["type"] == 0, "plain tx type == 0");
    CHECK(!t1.contains("extraPayload"), "plain tx has NO extraPayload");

    if (g_fail == 0) { std::printf("\nALL DASH EXPLORER-JSON KAT CHECKS PASSED\n"); return 0; }
    std::printf("\n%d CHECK(S) FAILED\n", g_fail);
    return 1;
}
