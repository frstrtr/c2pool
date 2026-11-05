// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// ltc_mempool_mweb_admission (rides share_test) -- what the embedded LTC
// mempool admits.
//
// Embedded c2pool emits an empty-body mw::Block and a one-in/one-out HogEx,
// so (litecoind mweb_node.cpp ContextualCheckBlock / ValidateMWEBBlock) its
// blocks can hold no peg-in output, no peg-out and no kernel, and no block tx
// may carry an mw::Transaction. A tx that needs any of that can never be in
// its template, so it never enters the pool:
//   - any tx with an MWEB part: mweb-pegin / mweb-pegout / mweb-only /
//     mweb-mixed (malformed when the part does not walk);
//   - a pegin output without its kernel (litecoind kernel-mismatch);
//   - empty vin or vout outside MWEB-only txs (CheckTransaction), which also
//     catches the 10-byte stub a SERIALIZE_NO_MWEB relay would give;
//   - a loose HogEx;
//   - with a view: a premature coinbase spend (inputs_invalid) and, with a
//     set built from genesis, a tx whose input is in neither the set nor the
//     pool (missing_inputs: an orphan, outside the pool).
// Real bytes: the peg-in and peg-out mempool txs and 3200601's HogEx
// (ltc_mweb_tx_fixtures.hpp). Refusals are counted by code, with the kernel
// fees given up -- per delivery, and once per tx by its kernel id
// (mweb_txs_seen_distinct, #2137 S3).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <optional>
#include <random>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>
#include <core/coin/utxo_view_db.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/transaction.hpp>

#include "ltc_mweb_tx_fixtures.hpp"

namespace {

using namespace ltc::coin;
namespace fx = ltc_mweb_tx_fixture;
using Code = Mempool::Reject::Code;
using Bytes = std::vector<unsigned char>;

MutableTransaction parse_tx(const std::string& hex)
{
    auto bytes = ParseHex(hex);
    PackStream ps(bytes);
    MutableTransaction tx;
    ps >> TX_WITH_WITNESS(tx);
    return tx;
}

MutableTransaction pay(uint8_t tag, int64_t value, std::vector<unsigned char> spk = {0x51})
{
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    TxIn in;
    std::memset(in.prevout.hash.data(), tag, 32);
    in.prevout.index = 0;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = value;
    out.scriptPubKey.m_data = std::move(spk);
    tx.vout.push_back(out);
    return tx;
}

Bytes cat(std::initializer_list<Bytes> parts)
{
    Bytes out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

// An mw::Transaction with one plain kernel (features 0: no fee, no peg-in,
// no peg-out) and no inputs or outputs.
Bytes plain_mw_tx()
{
    return cat({Bytes(32, 0x11), Bytes(32, 0x22), {0x00, 0x00, 0x01, 0x00}, Bytes(33, 0x08),
                Bytes(64, 0x55)});
}

} // namespace

TEST(LtcMempoolMwebAdmission, RealMwebTxsAndHogexAreRefused)
{
    Mempool pool;

    const MutableTransaction pegout = parse_tx(fx::kPegoutTxHex);
    auto r = pool.admit(pegout, nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::mweb_pegout);
    EXPECT_EQ(r->txid.GetHex(), fx::kPegoutTxid);
    EXPECT_EQ(HexStr(std::span<const unsigned char>(r->kernel_id.data(), 32)), fx::kPegoutKernelId);
    EXPECT_EQ(r->mweb_fee, fx::kPegoutKernelFee);
    EXPECT_EQ(r->n_pegins, 0u);

    const MutableTransaction pegin = parse_tx(fx::kPeginTxHex);
    r = pool.admit(pegin, nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::mweb_pegin);
    EXPECT_EQ(r->txid.GetHex(), fx::kPeginTxid);
    EXPECT_EQ(HexStr(std::span<const unsigned char>(r->kernel_id.data(), 32)), fx::kPeginKernelId);
    EXPECT_EQ(r->mweb_fee, fx::kPeginKernelFee);
    EXPECT_EQ(r->n_pegins, 1u);

    const MutableTransaction hogex = parse_tx(fx::kBlock3200601HogexHex);
    ASSERT_TRUE(hogex.m_hogEx);
    r = pool.admit(hogex, nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::hogex);
    EXPECT_EQ(r->txid.GetHex(), fx::kBlock3200601HogexTxid);

    // The stub the old parser made of the peg-out (and what a relay without
    // MWEB data gives): no inputs, no outputs.
    const MutableTransaction stub = parse_tx(fx::kPegoutStubHex);
    ASSERT_TRUE(stub.vin.empty());
    r = pool.admit(stub, nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::vin_empty);

    EXPECT_FALSE(pool.add_tx(pegout, nullptr));
    EXPECT_FALSE(pool.add_tx(pegin));
    EXPECT_EQ(pool.size(), 0u);
    EXPECT_FALSE(pool.contains(compute_txid(pegin)));
    EXPECT_FALSE(pool.contains(compute_txid(pegout)));

    const auto& st = pool.reject_stats();
    EXPECT_EQ(st.by_code[Code::mweb_pegout].load(), 2u);
    EXPECT_EQ(st.by_code[Code::mweb_pegin].load(), 2u);
    EXPECT_EQ(st.by_code[Code::hogex].load(), 1u);
    EXPECT_EQ(st.by_code[Code::vin_empty].load(), 1u);
    EXPECT_EQ(st.mweb_txs_seen.load(), 4u);
    EXPECT_EQ(st.mweb_fee_skipped_sat.load(),
              static_cast<uint64_t>(2 * (fx::kPegoutKernelFee + fx::kPeginKernelFee)));
    EXPECT_EQ(st.pegins_seen.load(), 2u);
    EXPECT_EQ(st.pegouts_seen.load(), 2u);
    EXPECT_EQ(st.admitted.load(), 0u);
}

TEST(LtcMempoolMwebAdmission, EveryRefusalCode)
{
    Mempool pool;

    // A canonical tx paying to a pegin script, without the MWEB part that
    // would carry its kernel.
    std::vector<unsigned char> pegin_spk(34, 0xab);
    pegin_spk[0] = 0x59;
    pegin_spk[1] = 0x20;
    auto r = pool.admit(pay(0x01, 1000, pegin_spk), nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::pegin_output_no_kernel);

    // A HogAddr-shaped output is not a pegin (witness v8, not v9).
    std::vector<unsigned char> hogaddr_spk = pegin_spk;
    hogaddr_spk[0] = 0x58;
    EXPECT_FALSE(pool.admit(pay(0x02, 1000, hogaddr_spk), nullptr));

    MutableTransaction no_out = pay(0x03, 1000);
    no_out.vout.clear();
    r = pool.admit(no_out, nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::vout_empty);

    // MWEB-to-MWEB (no canonical data, no peg kernel).
    MutableTransaction mweb_only;
    mweb_only.mweb_tx_raw = plain_mw_tx();
    ASSERT_TRUE(mweb_only.IsMWEBOnly());
    r = pool.admit(mweb_only, nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::mweb_only);
    EXPECT_EQ(r->txid, r->kernel_id) << "an MWEB-only tx is identified by its kernel id";

    // Canonical data plus an MWEB part with no peg kernel.
    MutableTransaction mixed = pay(0x04, 1000);
    mixed.mweb_tx_raw = plain_mw_tx();
    r = pool.admit(mixed, nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::mweb_mixed);

    // An MWEB part that does not walk.
    MutableTransaction broken = pay(0x05, 1000);
    broken.mweb_tx_raw = Bytes(40, 0xff);
    r = pool.admit(broken, nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::malformed);

    // Admitted once, then a duplicate.
    const MutableTransaction ok = pay(0x06, 1000);
    EXPECT_FALSE(pool.admit(ok, nullptr));
    r = pool.admit(ok, nullptr);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Code::duplicate);

    // A coinbase 5 blocks deep (maturity 100): refused, not pooled.
    {
        core::coin::UTXOViewCache view(nullptr);
        core::coin::Coin cb;
        cb.value = 5000000000LL;
        cb.scriptPubKey.m_data = {0x51};
        cb.height = 95;
        cb.coinbase = true;
        view.add_coin(core::coin::Outpoint(pay(0x08, 1000).vin[0].prevout.hash, 0), cb);
        pool.set_tip_height(100);
        r = pool.admit(pay(0x08, 1000), &view);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, Code::inputs_invalid);
        pool.set_tip_height(0);
    }

    // A HogAddr input (a HogEx output 0, which only the next block's HogEx
    // spends): refused, not pooled.
    {
        core::coin::UTXOViewCache view(nullptr);
        core::coin::Coin hog;
        hog.value = 5000000000LL;
        hog.scriptPubKey.m_data = hogaddr_spk;
        hog.height = 99;
        view.add_coin(core::coin::Outpoint(pay(0x0a, 1000).vin[0].prevout.hash, 0), hog);
        r = pool.admit(pay(0x0a, 1000), &view);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, Code::hogaddr_spend);
    }

    // An input in neither the set nor the pool, the set built from genesis:
    // an orphan (outside the pool).
    {
        std::mt19937_64 rng(std::random_device{}());
        const auto dir = std::filesystem::temp_directory_path() / ("ltc_admission_" + std::to_string(rng()));
        {
            core::coin::UTXOViewDB db(dir.string());
            ASSERT_TRUE(db.open());
            core::coin::UTXOViewCache full(&db);
            core::coin::SyncState s;
            s.anchor_height = 0;
            s.strict = 1;
            ASSERT_TRUE(full.set_sync_state(s));
            r = pool.admit(pay(0x09, 1000), &full);
            ASSERT_TRUE(r);
            EXPECT_EQ(r->code, Code::missing_inputs);
            EXPECT_EQ(pool.orphan_count(), 1u);
        }
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    // Not final in the next block (CheckFinalTx): locked to its height.
    {
        pool.set_lock_time_cutoff(1001, 1'600'000'000);
        MutableTransaction locked = pay(0x0a, 1000);
        locked.locktime = 1001;
        locked.vin[0].sequence = 0xfffffffe;
        r = pool.admit(locked, nullptr);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, Code::non_final);
        pool.set_lock_time_cutoff(0, 0);
    }

    // Relative lock-times the next block does not satisfy (CheckSequenceLocks):
    // a height lock of 2 on a coin at the tip's height.
    {
        core::coin::UTXOViewCache view(nullptr);
        core::coin::Coin coin;
        coin.value = 5000;
        coin.scriptPubKey.m_data = {0x51};
        coin.height = 1000;
        MutableTransaction locked = pay(0x0b, 1000);
        locked.vin[0].sequence = 2;
        view.add_coin(core::coin::Outpoint(locked.vin[0].prevout.hash, 0), coin);
        pool.set_lock_time_cutoff(1001, 1'600'000'000);
        r = pool.admit(locked, &view);
        ASSERT_TRUE(r);
        EXPECT_EQ(r->code, Code::non_bip68_final);
        pool.set_lock_time_cutoff(0, 0);
    }

    // The rules key on MWEB data only: an ordinary legacy tx (any coin
    // sharing this pool, e.g. DOGE) is admitted as before.
    MutableTransaction legacy = pay(0x07, 5000, {0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
                                                 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac});
    legacy.version = 1;
    EXPECT_TRUE(pool.add_tx(legacy));
    EXPECT_TRUE(pool.contains(compute_txid(legacy)));

    EXPECT_EQ(pool.size(), 3u) << "the HogAddr-paying tx, the plain tx, the legacy tx";
    const auto& st = pool.reject_stats();
    EXPECT_EQ(st.admitted.load(), 3u);
    EXPECT_EQ(st.mweb_txs_seen.load(), 3u);
    EXPECT_EQ(st.mweb_fee_skipped_sat.load(), 0u);
    for (int c = 0; c < Code::count; ++c) {
        const auto code = static_cast<Code>(c);
        const uint64_t want = (code == Code::mweb_pegin || code == Code::mweb_pegout
                               || code == Code::hogex || code == Code::vin_empty) ? 0u : 1u;
        EXPECT_EQ(st.by_code[c].load(), want) << Mempool::reject_code_name(code);
    }

    const nlohmann::json j = pool.reject_stats_json();
    EXPECT_EQ(j["admitted"], 3);
    EXPECT_EQ(j["rejected"]["pegin_output_no_kernel"], 1);
    EXPECT_EQ(j["rejected"]["mweb_only"], 1);
    EXPECT_EQ(j["rejected"]["duplicate"], 1);
    EXPECT_EQ(j["mweb_txs_seen"], 3);
}

namespace {

// An MWEB-only tx: no canonical part, one kernel (fee, excess `tag`).
MutableTransaction mweb_only(uint32_t tag, int64_t fee)
{
    std::vector<unsigned char> mw(64, 0);  // kernel_offset, stealth_offset
    mw.push_back(0x00);                    // inputs
    mw.push_back(0x00);                    // outputs
    mw.push_back(0x01);                    // one kernel
    mw.push_back(0x01);                    // features: fee
    // VARINT fee (MSB base-128, serialize.h WriteVarInt).
    std::vector<unsigned char> v;
    uint64_t n = static_cast<uint64_t>(fee);
    while (true) {
        v.push_back(static_cast<unsigned char>((n & 0x7F) | (v.empty() ? 0x00 : 0x80)));
        if (n <= 0x7F)
            break;
        n = (n >> 7) - 1;
    }
    mw.insert(mw.end(), v.rbegin(), v.rend());
    std::vector<unsigned char> excess(33, 0x08);
    std::memcpy(excess.data() + 1, &tag, sizeof(tag));
    mw.insert(mw.end(), excess.begin(), excess.end());
    mw.insert(mw.end(), 64, 0x11);         // signature
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    tx.mweb_tx_raw = mw;
    return tx;
}

} // namespace

// The delivery counters repeat a refused MWEB tx once per announcing peer;
// mweb_txs_seen_distinct / mweb_fee_skipped_distinct_sat count it once
// (keyed by its first kernel id over the last 4096 distinct txs).
TEST(LtcMempoolMwebAdmission, DistinctRefusedMwebDeliveries)
{
    Mempool pool;
    const MutableTransaction pegin = parse_tx(fx::kPeginTxHex);
    const MutableTransaction pegout = parse_tx(fx::kPegoutTxHex);
    for (int peer = 0; peer < 3; ++peer) {
        ASSERT_TRUE(pool.admit(pegin, nullptr));
        ASSERT_TRUE(pool.admit(pegout, nullptr));
    }
    auto j = pool.reject_stats_json();
    EXPECT_EQ(j["mweb_txs_seen"], 6u);
    EXPECT_EQ(j["mweb_fee_skipped_sat"], 3u * (fx::kPeginKernelFee + fx::kPegoutKernelFee));
    EXPECT_EQ(j["mweb_txs_seen_distinct"], 2u);
    EXPECT_EQ(j["mweb_fee_skipped_distinct_sat"], static_cast<uint64_t>(fx::kPeginKernelFee + fx::kPegoutKernelFee));

    // The window: 4096 distinct kernels; the oldest is forgotten first.
    Mempool w;
    const MutableTransaction first = mweb_only(0, 1000);
    ASSERT_TRUE(w.admit(first, nullptr));
    for (uint32_t i = 1; i < Mempool::MWEB_SEEN_DISTINCT_KEPT; ++i)
        ASSERT_TRUE(w.admit(mweb_only(i, 1000), nullptr));
    EXPECT_EQ(w.reject_stats_json()["mweb_txs_seen_distinct"], Mempool::MWEB_SEEN_DISTINCT_KEPT);
    ASSERT_TRUE(w.admit(first, nullptr));
    EXPECT_EQ(w.reject_stats_json()["mweb_txs_seen_distinct"], Mempool::MWEB_SEEN_DISTINCT_KEPT)
        << "still remembered";
    ASSERT_TRUE(w.admit(mweb_only(Mempool::MWEB_SEEN_DISTINCT_KEPT, 1000), nullptr));  // pushes out `first`
    ASSERT_TRUE(w.admit(first, nullptr));
    EXPECT_EQ(w.reject_stats_json()["mweb_txs_seen_distinct"], Mempool::MWEB_SEEN_DISTINCT_KEPT + 2)
        << "forgotten after 4096 newer ones, counted again";
    EXPECT_EQ(w.reject_stats_json()["mweb_txs_seen"], Mempool::MWEB_SEEN_DISTINCT_KEPT + 3);
}
