// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// nmc::coin::Mempool — Namecoin name-operation relay KATs (P1 PB).
//
// PB adds the one NMC tx-class with no BTC/DOGE analog: the name operations
// (name_new / name_firstupdate / name_update). c2pool is a merge-miner, not a
// name registry, so it RELAYS name txs into the block template WITHOUT name-db
// consensus validation (SPV-trust in the configured namecoind backend; namecoind
// owns name-db consensus). These KATs pin:
//   * classify_name_op() — the version-marker + leading-opcode classifier, and
//     its false-positive guard (a bare OP_1 segwit/taproot output in a plain
//     Bitcoin-version tx is NOT a name op);
//   * Mempool admission — a name tx is admitted (not rejected), counted, and
//     carries its daemon-vs-peer-relay provenance (SPV-trust boundary);
//   * fee accounting — a name tx's fee flows through get_sorted_txs_with_fees
//     into the template coinbasevalue exactly like any other tx (Bitcoin
//     subsidy schedule), i.e. name ops are NOT special-cased in payout.
//
// The §4 PF caveats (bind trust to daemon source; v36 short-circuit; aux-slot
// distinctness) are PF KAT items, not exercised here.
//
// Per-coin isolation: src/impl/nmc/ only; btc tree consumed READ-ONLY. MUST
// appear in BOTH test/CMakeLists.txt AND the build.yml --target allowlist or it
// becomes a NOT_BUILT sentinel that reds master.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <ctime>
#include <optional>
#include <vector>

#include <core/hash.hpp>
#include <core/uint256.hpp>

#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include "../coin/template_builder.hpp"

namespace {

using nmc::coin::Mempool;
using nmc::coin::MempoolEntry;
using nmc::coin::MutableTransaction;
using nmc::coin::TxIn;
using nmc::coin::TxOut;
using nmc::coin::NameOp;
using nmc::coin::TxSource;
using nmc::coin::classify_name_op;
using nmc::coin::compute_txid;
using nmc::coin::NAMECOIN_TX_VERSION;
using nmc::coin::HeaderChain;
using nmc::coin::NMCChainParams;
using nmc::coin::BlockHeaderType;
using nmc::coin::TemplateBuilder;
using nmc::coin::block_hash;
using nmc::coin::get_block_subsidy;

// Full nVersion of a Namecoin name tx: marker in the high 16 bits, base
// version 2 in the low 16 (namecoin-core getNamecoinVersion()/getBaseVersion()).
static constexpr int32_t NMC_NAME_VERSION =
    (NAMECOIN_TX_VERSION << 16) | 2;

// Build a tx with a unique input (so txids differ by `salt`). When
// `name_prefix` is one of the name opcodes, the first output is a structurally
// plausible name script (<op> <push20> OP_2DROP <p2pkh>); when 0x00, the output
// is a plain P2PKH. `extra_first_byte`, if non-zero, prepends a raw leading byte
// to the first output script (used to forge a taproot-shaped output).
static MutableTransaction make_tx(int32_t version, unsigned char name_prefix,
                                  uint32_t salt)
{
    MutableTransaction tx;
    tx.version  = version;
    tx.locktime = 0;

    TxIn in;
    in.prevout.hash.SetNull();
    *(in.prevout.hash.begin()) = static_cast<uint8_t>(salt & 0xff);
    *(in.prevout.hash.begin() + 1) = static_cast<uint8_t>((salt >> 8) & 0xff);
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);

    TxOut out;
    out.value = 1000000;  // 0.01 NMC
    auto& d = out.scriptPubKey.m_data;
    if (name_prefix != 0x00) {
        d.push_back(name_prefix);   // OP_NAME_*
        d.push_back(0x14);          // push 20
        for (int i = 0; i < 20; ++i) d.push_back(0xab);
        d.push_back(0x6d);          // OP_2DROP
    }
    // address part: P2PKH OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    d.push_back(0x76); d.push_back(0xa9); d.push_back(0x14);
    for (int i = 0; i < 20; ++i) d.push_back(0xcd);
    d.push_back(0x88); d.push_back(0xac);
    tx.vout.push_back(out);
    return tx;
}

static BlockHeaderType plain_header(const uint256& prev, uint32_t bits,
                                    uint32_t nonce, uint32_t ts)
{
    BlockHeaderType h{};
    h.m_version        = 1;
    h.m_previous_block = prev;
    h.m_bits           = bits;
    h.m_nonce          = nonce;
    h.m_timestamp      = ts;
    return h;
}

static NMCChainParams params_pinned()
{
    NMCChainParams p = NMCChainParams::mainnet();
    p.aux_chain_id = 1;
    p.auxpow_activation_height = 19200;  // TEST-only pin
    return p;
}

// ── classify_name_op ────────────────────────────────────────────────────────

TEST(NmcNameClassify, NameNewFirstUpdateUpdate)
{
    EXPECT_EQ(classify_name_op(make_tx(NMC_NAME_VERSION, 0x51, 1)), NameOp::New);
    EXPECT_EQ(classify_name_op(make_tx(NMC_NAME_VERSION, 0x52, 2)), NameOp::FirstUpdate);
    EXPECT_EQ(classify_name_op(make_tx(NMC_NAME_VERSION, 0x53, 3)), NameOp::Update);
}

TEST(NmcNameClassify, PlainTxIsNotName)
{
    // Bitcoin-version tx with a plain P2PKH output -> not a name op.
    EXPECT_EQ(classify_name_op(make_tx(2, 0x00, 4)), NameOp::None);
}

TEST(NmcNameClassify, NameOpcodeButWrongVersionIsNotName)
{
    // Output starts with OP_NAME_NEW(0x51) but the tx carries a plain Bitcoin
    // version -> the version gate rejects it (no false-positive). This is the
    // taproot/segwit-v1/bare-multisig case: those start with OP_1..OP_16 too.
    EXPECT_EQ(classify_name_op(make_tx(2, 0x51, 5)), NameOp::None);
}

TEST(NmcNameClassify, NameVersionButNoNameScriptIsNotName)
{
    // Name version marker present, but no output begins with a name opcode.
    EXPECT_EQ(classify_name_op(make_tx(NMC_NAME_VERSION, 0x00, 6)), NameOp::None);
}

// ── Mempool admission (relay without name-db validation) ─────────────────────

TEST(NmcNameRelay, NameTxIsAdmittedCountedAndTagged)
{
    Mempool pool;
    auto tx = make_tx(NMC_NAME_VERSION, 0x52, 10);  // name_firstupdate

    // Relayed (peer) name tx: admitted but NOT daemon-trusted.
    ASSERT_TRUE(pool.add_tx(tx, nullptr, TxSource::PeerRelay));
    EXPECT_EQ(pool.size(), 1u);
    EXPECT_EQ(pool.name_op_count(), 1u);
    EXPECT_EQ(pool.trusted_name_op_count(), 0u);

    auto entry = pool.get_entry(compute_txid(tx));
    ASSERT_TRUE(entry.has_value());
    EXPECT_TRUE(entry->is_name());
    EXPECT_EQ(entry->name_op, NameOp::FirstUpdate);
    EXPECT_EQ(entry->source, TxSource::PeerRelay);
}

TEST(NmcNameRelay, DaemonSourcedNameTxIsTrusted)
{
    Mempool pool;
    auto tx = make_tx(NMC_NAME_VERSION, 0x53, 11);  // name_update from daemon
    ASSERT_TRUE(pool.add_tx(tx, nullptr, TxSource::Daemon));
    EXPECT_EQ(pool.name_op_count(), 1u);
    EXPECT_EQ(pool.trusted_name_op_count(), 1u);
}

TEST(NmcNameRelay, PlainTxLeavesNameCountsZero)
{
    Mempool pool;
    ASSERT_TRUE(pool.add_tx(make_tx(2, 0x00, 12), nullptr, TxSource::PeerRelay));
    EXPECT_EQ(pool.size(), 1u);
    EXPECT_EQ(pool.name_op_count(), 0u);
}

// ── Fee accounting: name-tx fee flows into the template coinbasevalue ─────────

TEST(NmcNameFee, NameTxFeeIsSelectedIntoTotalFees)
{
    Mempool pool;
    auto tx = make_tx(NMC_NAME_VERSION, 0x51, 20);  // name_new
    ASSERT_TRUE(pool.add_tx(tx, nullptr, TxSource::Daemon));

    // No UTXO set in this harness; pin the fee directly (as the template-builder
    // suite does). 5000 sat fee.
    pool.set_tx_fee(compute_txid(tx), 5000);

    auto [selected, total_fees] = pool.get_sorted_txs_with_fees(4'000'000);
    EXPECT_EQ(selected.size(), 1u);
    EXPECT_EQ(total_fees, 5000u);
    EXPECT_EQ(pool.total_fees(), 5000u);
}

TEST(NmcNameFee, NameTxFeeReachesTemplateCoinbaseValue)
{
    HeaderChain chain(params_pinned());
    Mempool pool;

    // Seed a fresh two-header chain (tip height 1 -> next block height 2).
    auto now = static_cast<uint32_t>(std::time(nullptr));
    uint256 z; z.SetNull();
    BlockHeaderType g = plain_header(z, 0x1d00ffffu, 1, now - 100);
    ASSERT_TRUE(chain.add_header(g));
    BlockHeaderType c = plain_header(block_hash(g), 0x1d00ffffu, 2, now - 50);
    ASSERT_TRUE(chain.add_header(c));
    ASSERT_EQ(chain.height(), 1u);

    // Admit a daemon-sourced name_update with a known fee.
    auto tx = make_tx(NMC_NAME_VERSION, 0x53, 21);
    ASSERT_TRUE(pool.add_tx(tx, nullptr, TxSource::Daemon));
    pool.set_tx_fee(compute_txid(tx), 7000);

    auto wd = TemplateBuilder::build_template(chain, pool, /*is_testnet=*/false);
    ASSERT_TRUE(wd.has_value());
    const auto& d = wd->m_data;

    // coinbasevalue = subsidy(2) + the name tx fee. Name ops are NOT special-
    // cased: their fee is counted exactly like any other tx.
    EXPECT_EQ(d.at("coinbasevalue").get<int64_t>(),
              static_cast<int64_t>(get_block_subsidy(2u)) + 7000);
    EXPECT_EQ(d.at("transactions").size(), 1u);
}

} // namespace