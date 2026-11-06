// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// BIP68 relative lock-times in the embedded LTC mempool and template
// (Litecoin Core 0.21.4 consensus/tx_verify.cpp CalculateSequenceLocks /
// EvaluateSequenceLocks, validation.cpp CheckSequenceLocks; #2138, #2137;
// rides share_test):
//   - the lock pair at its boundaries: a height lock valid from the coin's
//     height + value (not at one below), a time lock valid once the block's
//     median time past is value x 512 s past the coin time (not one second
//     earlier), the bits outside the 16-bit value ignored, the disable flag,
//     version 1 (and 0) not enforced, version -1 enforced (compared
//     unsigned), several inputs, an unknown coin or coin time;
//   - admission (the next block: tip + 1 and the tip's median time past)
//     refuses non_bip68_final, counted, before inputs_invalid; an in-pool
//     parent's coin is at the next block's height, so only a zero lock on
//     it passes; the next tip admits what it satisfies;
//   - the template's selection (a REAL HeaderChain and TemplateBuilder)
//     takes only txs whose locks its own block satisfies, a parent in the
//     template at the template's height, and re-evaluates as the tip
//     advances; template_bip68_skipped counts what it left out;
//   - DOGE: its CSV deployment never activated (Dogecoin Core 1.14.9), so
//     neither admission nor the selection checks BIP68 there;
//   - TemplateBuilder::median_time_past_at: exact on a chain from genesis;
//     after a fast-start checkpoint, below the first exact value, that value
//     (no lower than the true one).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <core/uint256.hpp>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/coin/utxo.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <impl/ltc/coin/header_chain.hpp>
#include <impl/ltc/coin/mempool.hpp>
#include <impl/ltc/coin/template_builder.hpp>
#include <impl/ltc/test/ltc_mined_headers.hpp>

namespace {

using namespace ltc::coin;

constexpr uint32_t kFinal   = 0xffffffff;
constexpr uint32_t kType    = SEQUENCE_LOCKTIME_TYPE_FLAG;
constexpr uint32_t kDisable = SEQUENCE_LOCKTIME_DISABLE_FLAG;
constexpr int64_t  kT0      = 1'600'000'000;

// A median time past per height, rising 600 s a block.
int64_t fake_mtp(uint32_t h) { return kT0 + 600 * static_cast<int64_t>(h); }

LockTimeCutoff block_at(uint32_t height)
{
    return LockTimeCutoff{height, fake_mtp(height - 1), [](uint32_t h) { return std::optional<int64_t>(fake_mtp(h)); }};
}

uint256 fund(uint32_t n)
{
    uint256 v;
    v.SetHex(std::to_string(0xb000 + n));
    return v;
}

MutableTransaction tx_seq(int32_t version, const std::vector<uint32_t>& seqs, const uint256& prev = fund(0),
                          int64_t out_value = 99'000)
{
    MutableTransaction tx;
    tx.version = version;
    tx.locktime = 0;
    for (size_t i = 0; i < seqs.size(); ++i) {
        TxIn in;
        in.prevout.hash = prev;
        in.prevout.index = static_cast<uint32_t>(i);
        in.sequence = seqs[i];
        tx.vin.push_back(in);
    }
    TxOut out;
    out.value = out_value;
    out.scriptPubKey.m_data = {0x51};
    tx.vout.push_back(out);
    return tx;
}

// A parent of three inputs (fund(n):0..2) and three outputs of 96,000.
MutableTransaction parent_of(const uint256& prev)
{
    MutableTransaction tx = tx_seq(2, {kFinal, kFinal, kFinal}, prev, 96'000);
    tx.vout.push_back(tx.vout.front());
    tx.vout.push_back(tx.vout.front());
    return tx;
}

// The block's verdict on `tx` whose inputs' coins are at `heights`.
std::optional<bool> ok_in(const MutableTransaction& tx, const std::vector<uint32_t>& heights,
                          const LockTimeCutoff& block)
{
    const auto l = calculate_sequence_locks(tx, [&](size_t i) { return std::optional<uint32_t>(heights[i]); }, block);
    if (!l)
        return std::nullopt;
    return evaluate_sequence_locks(block, *l);
}

core::coin::Coin coin_at(uint32_t height, int64_t value = 100'000)
{
    core::coin::Coin c;
    c.value = value;
    c.scriptPubKey.m_data = {0x51};
    c.height = height;
    return c;
}

int64_t median_of(std::vector<int64_t> v)
{
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

BlockHeaderType testnet_genesis() { return ltc_test::easy_testnet_genesis(); }

BlockHeaderType next_header(const uint256& prev, uint32_t ts, uint32_t n)
{
    BlockHeaderType h;
    h.m_version = 0x20000000;
    h.m_previous_block = prev;
    h.m_merkle_root.SetHex(std::to_string(7000 + n));
    h.m_timestamp = ts;
    h.m_bits = ltc_test::kEasyBits;
    h.m_nonce = n << 16;
    ltc_test::mine(h);
    return h;
}

uint256 hash_of(const BlockHeaderType& h) { return Hash(pack(h).get_span()); }

// Genesis then `n` headers 600 s apart; times[h] is height h's timestamp.
struct Chain {
    HeaderChain chain{ltc_test::easy_testnet_params()};
    std::vector<int64_t> times;
    BlockHeaderType tip;

    explicit Chain(uint32_t n)
    {
        EXPECT_TRUE(chain.init());
        EXPECT_TRUE(chain.add_header(testnet_genesis()));
        times.push_back(testnet_genesis().m_timestamp);
        tip = testnet_genesis();
        for (uint32_t i = 0; i < n; ++i)
            grow();
    }
    void grow()
    {
        const uint32_t ts = static_cast<uint32_t>(times.back() + 600);
        const BlockHeaderType h = next_header(hash_of(tip), ts, static_cast<uint32_t>(times.size()));
        EXPECT_TRUE(chain.add_header(h));
        times.push_back(ts);
        tip = h;
    }
    // litecoind GetMedianTimePast of height h, from the timestamps.
    int64_t mtp(uint32_t h) const
    {
        std::vector<int64_t> v;
        for (uint32_t k = h + 1; k-- > 0 && v.size() < 11;)
            v.push_back(times[k]);
        return median_of(v);
    }
};

void clean_for(Mempool& pool, const BlockHeaderType& hdr)
{
    BlockType b;
    static_cast<BlockHeaderType&>(b) = hdr;
    pool.remove_for_block(b);
}

std::vector<std::string> txids_of(const rpc::WorkData& wd)
{
    std::vector<std::string> out;
    for (const auto& t : wd.m_data["transactions"])
        out.push_back(t["txid"].get<std::string>());
    return out;
}

bool has(const std::vector<std::string>& v, const MutableTransaction& tx)
{
    return std::find(v.begin(), v.end(), compute_txid(tx).GetHex()) != v.end();
}

} // namespace

TEST(LtcMempoolBip68, SequenceLocksMatchLitecoind)
{
    // A height lock of 10 on a coin at height 100: valid from height 110.
    const auto h10 = tx_seq(2, {10});
    EXPECT_EQ(ok_in(h10, {100}, block_at(110)), std::optional<bool>(true)) << "height N";
    EXPECT_EQ(ok_in(h10, {100}, block_at(109)), std::optional<bool>(false)) << "height N - 1";
    const auto l = calculate_sequence_locks(h10, [](size_t) { return std::optional<uint32_t>(100); }, block_at(110));
    ASSERT_TRUE(l);
    EXPECT_EQ(l->height, 109) << "the last invalid height";
    EXPECT_EQ(l->time, -1);
    // A zero lock: any block after the coin's.
    EXPECT_EQ(ok_in(tx_seq(2, {0}), {100}, block_at(101)), std::optional<bool>(true));

    // A time lock of 3 (1,536 s) on a coin at height 100: its time is the
    // median time past of height 99; the block's is its parent's.
    const int64_t coin_time = fake_mtp(99);
    const auto t3 = tx_seq(2, {kType | 3});
    auto block_mtp = [](int64_t mtp) {
        return LockTimeCutoff{200, mtp, [](uint32_t h) { return std::optional<int64_t>(fake_mtp(h)); }};
    };
    EXPECT_EQ(ok_in(t3, {100}, block_mtp(coin_time + 3 * 512)), std::optional<bool>(true)) << "3 x 512 s";
    EXPECT_EQ(ok_in(t3, {100}, block_mtp(coin_time + 3 * 512 - 1)), std::optional<bool>(false)) << "one second short";
    // The 512 s granularity: 2 units are 1,024 s, 1,535 s still 2 units' worth.
    const auto t2 = tx_seq(2, {kType | 2});
    EXPECT_EQ(ok_in(t2, {100}, block_mtp(coin_time + 1024)), std::optional<bool>(true));
    EXPECT_EQ(ok_in(t2, {100}, block_mtp(coin_time + 1023)), std::optional<bool>(false));
    EXPECT_EQ(ok_in(t3, {100}, block_mtp(coin_time + 1535)), std::optional<bool>(false));
    // Only the low 16 bits are the value; bits 16-21 and 23-30 are ignored.
    const auto t3_noise = tx_seq(2, {kType | (1u << 16) | (1u << 21) | (1u << 23) | (1u << 30) | 3});
    EXPECT_EQ(ok_in(t3_noise, {100}, block_mtp(coin_time + 1536)), std::optional<bool>(true));
    EXPECT_EQ(ok_in(t3_noise, {100}, block_mtp(coin_time + 1535)), std::optional<bool>(false));
    const auto h10_noise = tx_seq(2, {(1u << 16) | (1u << 30) | 10});
    EXPECT_EQ(ok_in(h10_noise, {100}, block_at(109)), std::optional<bool>(false));
    EXPECT_EQ(ok_in(h10_noise, {100}, block_at(110)), std::optional<bool>(true));

    // The disable flag: no lock, whatever the value.
    EXPECT_EQ(ok_in(tx_seq(2, {kDisable | 0xffff}), {100}, block_at(101)), std::optional<bool>(true));
    EXPECT_EQ(ok_in(tx_seq(2, {kDisable | kType | 0xffff}), {100}, block_at(101)), std::optional<bool>(true));
    EXPECT_FALSE(has_sequence_locks(tx_seq(2, {kDisable | 5, kFinal})));
    EXPECT_TRUE(has_sequence_locks(tx_seq(2, {kFinal, 5})));

    // Version 1 and 0: not enforced. Version -1 is 0xffffffff unsigned: enforced.
    EXPECT_EQ(ok_in(tx_seq(1, {0xffff}), {100}, block_at(101)), std::optional<bool>(true));
    EXPECT_EQ(ok_in(tx_seq(0, {0xffff}), {100}, block_at(101)), std::optional<bool>(true));
    EXPECT_FALSE(has_sequence_locks(tx_seq(1, {5})));
    EXPECT_EQ(ok_in(tx_seq(-1, {10}), {100}, block_at(109)), std::optional<bool>(false));
    EXPECT_TRUE(has_sequence_locks(tx_seq(-1, {5})));

    // Several inputs: the strictest lock of each kind; a disabled input adds none.
    const auto multi = tx_seq(2, {5, 10, kDisable | 0xffff});
    EXPECT_EQ(ok_in(multi, {104, 99, 0}, block_at(109)), std::optional<bool>(true)) << "108 and 108";
    EXPECT_EQ(ok_in(multi, {105, 99, 0}, block_at(109)), std::optional<bool>(false)) << "5 on 105: 109";
    EXPECT_EQ(ok_in(multi, {104, 100, 0}, block_at(109)), std::optional<bool>(false)) << "10 on 100: 109";
    const auto mixed = tx_seq(2, {10, kType | 1});
    EXPECT_EQ(ok_in(mixed, {100, 100}, block_mtp(coin_time + 512)), std::optional<bool>(true)) << "height 200, 512 s";
    EXPECT_EQ(ok_in(mixed, {100, 100}, block_mtp(coin_time + 511)), std::optional<bool>(false));

    // A coin at height 0: its time is the median time past of height 0.
    EXPECT_EQ(ok_in(tx_seq(2, {kType | 1}), {0}, block_mtp(fake_mtp(0) + 512)), std::optional<bool>(true));
    EXPECT_EQ(ok_in(tx_seq(2, {kType | 1}), {0}, block_mtp(fake_mtp(0) + 511)), std::optional<bool>(false));

    // Unknown: the coin's height, or (time locks only) its time.
    EXPECT_FALSE(calculate_sequence_locks(h10, [](size_t) { return std::optional<uint32_t>(); }, block_at(110)));
    EXPECT_TRUE(calculate_sequence_locks(tx_seq(2, {kDisable}), [](size_t) { return std::optional<uint32_t>(); },
                                         block_at(110)))
        << "a disabled input needs no coin";
    const LockTimeCutoff no_history{110, fake_mtp(109), {}};
    EXPECT_FALSE(calculate_sequence_locks(t3, [](size_t) { return std::optional<uint32_t>(100); }, no_history));
    EXPECT_EQ(ok_in(h10, {100}, no_history), std::optional<bool>(true)) << "a height lock needs no time";
    EXPECT_EQ(ok_in(tx_seq(2, {kType | 1}), {110}, no_history), std::optional<bool>(false))
        << "a coin in the block itself: its time is the parent's median time past";
}

TEST(LtcMempoolBip68, AdmissionRefusesNonBip68Final)
{
    core::coin::UTXOViewCache view(nullptr);
    for (uint32_t i = 0; i < 4; ++i)
        view.add_coin(core::coin::Outpoint(fund(1), i), coin_at(100));
    for (uint32_t n = 2; n < 12; ++n)
        view.add_coin(core::coin::Outpoint(fund(n), 0), coin_at(100));
    Mempool pool;
    ASSERT_TRUE(pool.bip68());
    pool.set_utxo(&view);
    pool.set_tip_height(100);
    // The next block: height 101 on the tip (100), whose median time past is
    // fake_mtp(100); a coin at 100 has the time fake_mtp(99), 600 s earlier.
    pool.set_lock_time_cutoff(101, fake_mtp(100), [](uint32_t h) { return std::optional<int64_t>(fake_mtp(h)); });

    // Height: a lock of 1 on a coin at 100 is satisfied at 101, one of 2 is not.
    EXPECT_FALSE(pool.admit(tx_seq(2, {1}, fund(2)), &view));
    auto r = pool.admit(tx_seq(2, {2}, fund(3)), &view);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::non_bip68_final);
    // Time: 600 s have passed: 1 unit (512 s) is satisfied, 2 (1,024 s) are not.
    EXPECT_FALSE(pool.admit(tx_seq(2, {kType | 1}, fund(4)), &view));
    r = pool.admit(tx_seq(2, {kType | 2}, fund(5)), &view);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::non_bip68_final);
    // The disable flag, and version 1: not checked.
    EXPECT_FALSE(pool.admit(tx_seq(2, {kDisable | 0xffff}, fund(6)), &view));
    EXPECT_FALSE(pool.admit(tx_seq(1, {0xffff}, fund(7)), &view));
    // litecoind checks the sequence locks before CheckTxInputs: a locked tx
    // whose outputs are above its inputs is non_bip68_final.
    r = pool.admit(tx_seq(2, {0xffff}, fund(8), 200'000), &view);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::non_bip68_final);
    r = pool.admit(tx_seq(2, {1}, fund(8), 200'000), &view);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::inputs_invalid) << "satisfied locks: the inputs are checked";

    // An in-pool parent's coin is at the next block's height (litecoind:
    // an in-mempool coin confirms in the next block): only a zero lock on it
    // passes.
    const MutableTransaction parent = parent_of(fund(1));
    ASSERT_FALSE(pool.admit(parent, &view));
    MutableTransaction c0 = tx_seq(2, {0}, compute_txid(parent), 90'000);
    EXPECT_FALSE(pool.admit(c0, &view)) << "a zero height lock";
    MutableTransaction c1 = tx_seq(2, {1}, compute_txid(parent), 90'000);
    c1.vin[0].prevout.index = 1;
    r = pool.admit(c1, &view);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::non_bip68_final) << "a height lock of 1";
    MutableTransaction c2 = tx_seq(2, {kType | 1}, compute_txid(parent), 90'000);
    c2.vin[0].prevout.index = 2;
    r = pool.admit(c2, &view);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::non_bip68_final) << "a time lock of 1";
    MutableTransaction c3 = tx_seq(2, {kType}, compute_txid(parent), 90'000);
    c3.vin[0].prevout.index = 2;
    EXPECT_FALSE(pool.admit(c3, &view)) << "a zero time lock";

    const auto j = pool.reject_stats_json();
    EXPECT_EQ(j["rejected"]["non_bip68_final"], 5);
    EXPECT_EQ(std::string(Mempool::reject_code_name(Mempool::Reject::non_bip68_final)), "non_bip68_final");

    // The next tip: height 102 and fake_mtp(101) satisfy both refused locks.
    pool.set_lock_time_cutoff(102, fake_mtp(101), [](uint32_t h) { return std::optional<int64_t>(fake_mtp(h)); });
    EXPECT_FALSE(pool.admit(tx_seq(2, {2}, fund(3)), &view));
    EXPECT_FALSE(pool.admit(tx_seq(2, {kType | 2}, fund(5)), &view));

    // Without a cutoff (before the first tip) nothing is checked.
    Mempool unset;
    unset.set_utxo(&view);
    EXPECT_FALSE(unset.admit(tx_seq(2, {0xffff}, fund(9)), &view));
}

// The template's block: tip 20 (genesis + 20 headers, 600 s apart), next 21.
// The selection takes only txs whose locks that block satisfies; the next
// tip satisfies more.
TEST(LtcMempoolBip68, TemplateSelectsOnlyBip68FinalTxs)
{
    Chain c(20);
    ASSERT_EQ(c.chain.height(), 20u);
    core::coin::UTXOViewCache view(nullptr);
    view.add_coin(core::coin::Outpoint(fund(1), 0), coin_at(15));
    view.add_coin(core::coin::Outpoint(fund(2), 0), coin_at(15));
    view.add_coin(core::coin::Outpoint(fund(3), 0), coin_at(10));
    view.add_coin(core::coin::Outpoint(fund(4), 0), coin_at(10));
    for (uint32_t i = 0; i < 3; ++i)
        view.add_coin(core::coin::Outpoint(fund(5), i), coin_at(1));

    // Time locks on a coin at 10: its time is MTP(9), the block's MTP(20).
    const int64_t elapsed = c.mtp(20) - c.mtp(9);
    const uint32_t units = static_cast<uint32_t>(elapsed / 512);
    ASSERT_GT(units, 0u);
    ASSERT_GT(static_cast<int64_t>(units + 1) * 512, elapsed);

    Mempool pool;
    const MutableTransaction h6 = tx_seq(2, {6}, fund(1));            // 15 + 6 - 1 = 20 < 21
    const MutableTransaction h7 = tx_seq(2, {7}, fund(2));            // 21: not before 22
    const MutableTransaction t_ok = tx_seq(2, {kType | units}, fund(3));
    const MutableTransaction t_late = tx_seq(2, {kType | (units + 1)}, fund(4));
    const MutableTransaction parent = parent_of(fund(5));
    MutableTransaction q0 = tx_seq(2, {0}, compute_txid(parent), 90'000);
    MutableTransaction q1 = tx_seq(2, {1}, compute_txid(parent), 90'000);
    q1.vin[0].prevout.index = 1;
    MutableTransaction v1 = tx_seq(1, {0xffff}, compute_txid(parent), 90'000);
    v1.vin[0].prevout.index = 2;
    // Fees as the inputs give them: 1,000 on a coin; 12,000 for the parent;
    // 6,000 on a parent's output.
    for (const MutableTransaction* t : std::vector<const MutableTransaction*>{&h6, &h7, &t_ok, &t_late, &parent, &q0, &q1, &v1}) {
        ASSERT_TRUE(pool.add_tx_unchecked(*t));
        const uint64_t fee = t == &parent ? 12'000 : (t->vin[0].prevout.hash == compute_txid(parent) ? 6'000 : 1'000);
        pool.set_tx_fee(compute_txid(*t), fee);
    }
    pool.set_utxo(&view);
    clean_for(pool, c.tip);

    auto wd = TemplateBuilder::build_template(c.chain, pool, /*is_testnet=*/true);
    ASSERT_TRUE(wd);
    auto ids = txids_of(*wd);
    EXPECT_TRUE(has(ids, h6)) << "height N";
    EXPECT_FALSE(has(ids, h7)) << "height N - 1";
    EXPECT_TRUE(has(ids, t_ok)) << units << " x 512 s within " << elapsed << " s";
    EXPECT_FALSE(has(ids, t_late));
    EXPECT_TRUE(has(ids, parent));
    EXPECT_TRUE(has(ids, q0)) << "a zero lock on a parent in the template";
    EXPECT_FALSE(has(ids, q1)) << "a parent in the template is at the template's height";
    EXPECT_TRUE(has(ids, v1)) << "version 1";
    EXPECT_EQ(ids.size(), 5u);
    EXPECT_EQ(pool.reject_stats_json()["template_bip68_skipped"], 3);

    // Without a cutoff the selection is unchanged (other callers).
    EXPECT_EQ(pool.get_sorted_txs_with_fees(TemplateBuilder::MAX_BLOCK_WEIGHT).first.size(), 8u);

    // The next tip (21, next 22): the height lock of 7 and the later time
    // lock are satisfied; a parent still in the template keeps q1 out.
    c.grow();
    ASSERT_LE(static_cast<int64_t>(units + 1) * 512, c.mtp(21) - c.mtp(9)) << "the next tip satisfies one more";
    clean_for(pool, c.tip);
    wd = TemplateBuilder::build_template(c.chain, pool, /*is_testnet=*/true);
    ASSERT_TRUE(wd);
    ids = txids_of(*wd);
    EXPECT_TRUE(has(ids, h7));
    EXPECT_TRUE(has(ids, t_late));
    EXPECT_FALSE(has(ids, q1));
    EXPECT_EQ(ids.size(), 7u);
}

// Dogecoin Core 1.14.9: CSV is a BIP9 deployment (bit 0, May 2016 to May
// 2017) that never activated, since Dogecoin Core mines version 4 with the
// AuxPoW chain id and the BIP9 condition needs the top bits 001. ConnectBlock
// sets LOCKTIME_VERIFY_SEQUENCE only when it is ACTIVE: no BIP68 on DOGE.
TEST(LtcMempoolBip68, DogeDoesNotEnforceBip68)
{
    EXPECT_TRUE(Mempool::bip68_for(core::coin::LTC_LIMITS));
    EXPECT_FALSE(Mempool::bip68_for(core::coin::DOGE_LIMITS));

    core::coin::UTXOViewCache view(nullptr);
    view.add_coin(core::coin::Outpoint(fund(1), 0), coin_at(100));
    Mempool doge(core::coin::DOGE_LIMITS);
    EXPECT_FALSE(doge.bip68());
    doge.set_utxo(&view);
    doge.set_tip_height(100);
    doge.set_lock_time_cutoff(101, fake_mtp(100), [](uint32_t h) { return std::optional<int64_t>(fake_mtp(h)); });
    const MutableTransaction locked = tx_seq(2, {0xffff}, fund(1));
    EXPECT_FALSE(doge.admit(locked, &view)) << "admitted on DOGE";
    const auto sel = doge.get_sorted_txs_with_fees(4'000'000, block_at(101));
    ASSERT_EQ(sel.first.size(), 1u) << "selected on DOGE";
    EXPECT_EQ(doge.reject_stats_json()["template_bip68_skipped"], 0);

    Mempool ltc;
    ltc.set_utxo(&view);
    ltc.set_tip_height(100);
    ltc.set_lock_time_cutoff(101, fake_mtp(100), [](uint32_t h) { return std::optional<int64_t>(fake_mtp(h)); });
    auto r = ltc.admit(locked, &view);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->code, Mempool::Reject::non_bip68_final);
    ASSERT_TRUE(ltc.add_tx_unchecked(locked));
    ltc.set_tx_fee(compute_txid(locked), 1'000);
    EXPECT_EQ(ltc.get_sorted_txs_with_fees(4'000'000, block_at(101)).first.size(), 0u);
}

TEST(LtcMempoolBip68, MedianTimePastAtIsExactOrNoLower)
{
    // From genesis: exact at every height (fewer than 11 blocks near genesis).
    Chain c(20);
    for (uint32_t h = 0; h <= 20; ++h)
        EXPECT_EQ(TemplateBuilder::median_time_past_at(c.chain, h), std::optional<int64_t>(c.mtp(h))) << h;
    EXPECT_EQ(TemplateBuilder::median_time_past_at(c.chain, 20),
              std::optional<int64_t>(TemplateBuilder::median_time_past(c.chain, *c.chain.tip())));
    EXPECT_FALSE(TemplateBuilder::median_time_past_at(c.chain, 21)) << "above the tip";

    // After a fast-start checkpoint at 1000 (a root: no header, no history):
    // exact from 1011 (11 known blocks), and below it that value.
    auto p = ltc_test::easy_testnet_params();
    LTCChainParams::Checkpoint cp;
    cp.height = 1000;
    cp.hash.SetHex("00000000000000000000000000000000000000000000000000000000000a1000");
    p.fast_start_checkpoint = cp;
    HeaderChain chain(p);
    ASSERT_TRUE(chain.init());
    std::map<uint32_t, int64_t> ts;
    uint256 prev = cp.hash;
    for (uint32_t h = 1001; h <= 1030; ++h) {
        ts[h] = kT0 + 600 * static_cast<int64_t>(h - 1000);
        const BlockHeaderType hdr = next_header(prev, static_cast<uint32_t>(ts[h]), h);
        ASSERT_TRUE(chain.add_header(hdr)) << h;
        prev = hash_of(hdr);
    }
    ASSERT_EQ(chain.height(), 1030u);
    auto exact = [&](uint32_t h) {
        std::vector<int64_t> v;
        for (uint32_t k = h - 10; k <= h; ++k)
            v.push_back(ts[k]);
        return median_of(v);
    };
    EXPECT_EQ(TemplateBuilder::median_time_past_at(chain, 1011), std::optional<int64_t>(exact(1011)));
    EXPECT_EQ(TemplateBuilder::median_time_past_at(chain, 1030), std::optional<int64_t>(exact(1030)));
    for (uint32_t h : {990u, 999u, 1000u, 1001u, 1005u, 1010u})
        EXPECT_EQ(TemplateBuilder::median_time_past_at(chain, h), std::optional<int64_t>(exact(1011))) << h;
    EXPECT_FALSE(TemplateBuilder::median_time_past_at(chain, 1031));
}
