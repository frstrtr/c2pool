// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Variant B (#143, wf wtrv69elc) — CreditPool INDEX follower KATs.
//
// The five properties the task demands, each pinned red/green:
//   (1) FLAG OFF ⇒ BYTE-IDENTICAL EXCLUDE-ALL TEMPLATE. The admission seam at
//       nullptr AND at an empty admission produces a template equal field-by-
//       field (txs, hashes, fees, values, payments, coinbase payload) to a
//       build with the seam absent; try_admit_unlocks(flag_off) refuses.
//   (2) A GAP IN THE FOLLOWER'S INPUT ⇒ FAIL CLOSED: apply_block on a
//       non-contiguous height refuses, latches proven_complete=0, WIPES, and
//       the admission predicate refuses — the template stays exclude-all
//       (valid); no wrong balance can be served because the wiped follower
//       reports nothing.
//   (3) DUPLICATE INDEX ⇒ EXCLUDED: a contiguous synthetic v20→tip fold that
//       mined index 5 refuses a candidate carrying index 5 (and a duplicate
//       ON CHAIN hard-fails the fold itself, mirroring the dashd throw).
//   (4) VALID NON-DUPLICATE TYPE-9 + FRESH WINDOW + VERIFIED quorumSig ⇒
//       INCLUDED, and the committed creditPoolBalance equals the value the
//       cbTx of the built block must commit (prev + platformReward − gross).
//       [real BLS — #ifdef C2POOL_DASH_BLS]
//   (5) BAD quorumSig ⇒ REJECTED (fail-closed BLS): a single flipped byte in
//       the signature excludes the candidate. [real BLS — #ifdef; the
//       stub-build variant asserts the backend-absent path also refuses.]
//
// Plus the load-bearing pieces underneath: the CRangesSet port (add/dup/
// merge/contains), the dashd request-id preimage (byte-exact against an
// independently assembled buffer), the era-laddered LimitAmount arithmetic
// (creditpool.cpp:192-212 all three arms), the 576-block latelyUnlocked
// window (slide + missing-row refusal), and the CreditPoolIdxDb schema
// round-trip + torn-namespace adjudication + persist/restore/wipe.
//
// Folded into the test_dash_chainlock_verify target (NOT a new
// add_executable): that target is in the build.yml --target allowlist AND
// links dash_bls_verify — a new target would be a NOT_BUILT sentinel (#143
// trap), and no other allowlisted dash target links the BLS backend.

#include <gtest/gtest.h>

#include <impl/dash/coin/credit_pool_idx.hpp>
#include <impl/dash/coin/credit_pool_idx_db.hpp>
#include <impl/dash/coin/asset_unlock_verify.hpp>
#include <impl/dash/coin/asset_unlock_admission.hpp>
#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/vendor/cbtx.hpp>
#include <impl/dash/coin/vendor/assetlock.hpp>
#include <impl/dash/coin/vendor/bls_verify.hpp>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include <unistd.h>   // getpid (temp DB paths)

#ifdef C2POOL_DASH_BLS
#include <dashbls/bls.hpp>
#include <dashbls/schemes.hpp>
#include <dashbls/elements.hpp>
#endif

using dash::coin::AssetUnlockAdmission;
using dash::coin::BlockType;
using dash::coin::CRangesSet;
using dash::coin::CpIdxCursor;
using dash::coin::CpIdxDeploySchedule;
using dash::coin::CpIdxEra;
using dash::coin::CpIdxSeedProvenance;
using dash::coin::CpIdxWindowRowRec;
using dash::coin::CreditPoolIdxDb;
using dash::coin::CreditPoolIdxFollower;
using dash::coin::COIN_SAT;
using dash::coin::Mempool;
using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::MutableTransaction;
using dash::coin::QuorumManager;
using dash::coin::build_embedded_workdata;
using dash::coin::chainlock::QuorumCandidate;
using dash::coin::cp_idx_current_limit;
using dash::coin::cp_idx_era_at;
using dash::coin::kCpIdxNeverActive;
using dash::coin::kCpLimitAmountHigh;
using dash::coin::kCpLimitAmountLow;
using dash::coin::kCpLimitAmountV22;
using dash::coin::kCpLimitAmountV24;
using dash::coin::kLlmq100_67;
using dash::coin::vendor::CAssetLockPayload;
using dash::coin::vendor::CAssetUnlockPayload;
using dash::coin::vendor::CCbTx;
using dash::coin::vendor::parse_cbtx;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;
using ::core::coin::Coin;
using ::core::coin::Outpoint;
using ::core::coin::UTXOViewCache;

namespace unlockverify = dash::coin::unlockverify;

// ─── fixtures ───────────────────────────────────────────────────────────────

static constexpr uint8_t DASH_PUBKEY_VER = 76;
static constexpr uint8_t DASH_P2SH_VER   = 16;

// Template height: past V20 + MN_RR (mainnet), matching the gbt capstone.
static constexpr uint32_t H = 2'400'000;

static uint256 raw256(uint8_t base) {
    uint256 h;
    for (size_t i = 0; i < 32; ++i) h.data()[i] = static_cast<uint8_t>(base + i);
    return h;
}

static std::vector<unsigned char> p2pkh_script(uint8_t hashseed) {
    std::vector<unsigned char> s;
    s.push_back(0x76); s.push_back(0xa9); s.push_back(0x14);
    for (int i = 0; i < 20; ++i) s.push_back(static_cast<unsigned char>(hashseed + i));
    s.push_back(0x88); s.push_back(0xac);
    return s;
}

static MnStateMachine single_mn() {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = p2pkh_script(0x30);
    s.payoutSplitProvenance = MNState::SPLIT_KNOWN;
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}});
    return m;
}

template <typename T>
static std::vector<unsigned char> pack_bytes(const T& v) {
    ::PackStream s;
    s << v;
    auto sp = s.get_span();
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
}

// Coinbase carrying a v3 CCbTx committing `balance` at `height`.
static MutableTransaction make_cbtx_coinbase(uint32_t height, int64_t balance) {
    CCbTx c;
    c.nVersion = CCbTx::VERSION_CLSIG_AND_BALANCE;
    c.nHeight  = static_cast<int32_t>(height);
    c.creditPoolBalance = balance;
    MutableTransaction cb;
    cb.version = 3;
    cb.type = 5;
    cb.extra_payload = pack_bytes(c);
    return cb;
}

// Type-8 asset lock crediting `amount` (payload total_credit — the term the
// scalar machine folds, credit_pool.hpp:79-85).
static MutableTransaction make_lock_tx(int64_t amount) {
    CAssetLockPayload p;
    p.nVersion = 1;
    TxOut credit; credit.value = amount;
    p.creditOutputs.push_back(credit);
    MutableTransaction tx;
    tx.version = 3;
    tx.type = CAssetLockPayload::SPECIALTX_TYPE;
    tx.extra_payload = pack_bytes(p);
    return tx;
}

// Type-9 asset unlock: one withdrawal vout of `vout_value`, payload fee
// `fee`, dedup index `index`. Gross pool deduction = vout_value + fee.
static MutableTransaction make_unlock_tx(
    uint64_t index, uint32_t fee, int64_t vout_value,
    uint32_t requested_height, const uint256& quorum_hash,
    const std::array<uint8_t, 96>& sig = {}) {
    CAssetUnlockPayload p;
    p.nVersion = 1;
    p.index = index;
    p.fee = fee;
    p.requestedHeight = requested_height;
    p.quorumHash = quorum_hash;
    p.quorumSig = sig;
    MutableTransaction tx;
    tx.version = 3;
    tx.type = CAssetUnlockPayload::SPECIALTX_TYPE;
    TxOut o; o.value = vout_value;
    tx.vout.push_back(o);
    tx.extra_payload = pack_bytes(p);
    return tx;
}

static BlockType make_block(const uint256& prev_hash,
                            std::vector<MutableTransaction> txs) {
    BlockType b;
    b.m_previous_block = prev_hash;
    b.m_txs = std::move(txs);
    return b;
}

// Synthetic chain hash naming: hash(h) = raw256 of the low byte + a marker.
static uint256 chain_hash(uint32_t h) {
    uint256 x;
    x.data()[0] = static_cast<uint8_t>(h & 0xFF);
    x.data()[1] = static_cast<uint8_t>((h >> 8) & 0xFF);
    x.data()[2] = static_cast<uint8_t>((h >> 16) & 0xFF);
    x.data()[3] = static_cast<uint8_t>((h >> 24) & 0xFF);
    x.data()[31] = 0xC7;   // namespace marker so it never collides with raw256
    return x;
}

// A follower schedule whose v20 floor sits just below the template height so
// KATs fold a handful of blocks to reach freshness. WITHDRAWALS active from
// genesis (era V22: limit = min(pool, 2000 DASH)); V24 never.
static CpIdxDeploySchedule test_schedule(uint32_t floor_h) {
    return CpIdxDeploySchedule{floor_h, 0u, kCpIdxNeverActive, 576u};
}

// Fold a synthetic v20→tip chain into `f`:
//   floor+1: type-8 lock of 1000 DASH        (pool: 0 → 1000 DASH)
//   floor+2: type-9 unlock index 5, 10 DASH+190 duff fee (pool −= gross)
//   floor+3 .. tip: empty blocks (balance carries)
// The tip block's hash is `tip_hash` so a template on that parent is fresh.
// Every block's cbTx commits the running balance (reward_fn pinned to 0).
struct FoldResult { int64_t balance; uint32_t tip; };
static FoldResult fold_synthetic_chain(CreditPoolIdxFollower& f,
                                       uint32_t floor_h, uint32_t tip_h,
                                       const uint256& tip_hash) {
    f.set_reward_fn([](uint32_t) { return 0; });
    f.arm(chain_hash(floor_h), /*floor_balance=*/0);

    int64_t balance = 0;
    for (uint32_t h = floor_h + 1; h <= tip_h; ++h) {
        std::vector<MutableTransaction> txs;
        if (h == floor_h + 1) {
            balance += 1000 * COIN_SAT;
            txs.push_back(make_cbtx_coinbase(h, balance));
            txs.push_back(make_lock_tx(1000 * COIN_SAT));
        } else if (h == floor_h + 2) {
            balance -= 10 * COIN_SAT + 190;
            txs.push_back(make_cbtx_coinbase(h, balance));
            txs.push_back(make_unlock_tx(/*index=*/5, /*fee=*/190,
                                         /*vout=*/10 * COIN_SAT,
                                         /*requested*/ h - 1, raw256(0x77)));
        } else {
            txs.push_back(make_cbtx_coinbase(h, balance));
        }
        const uint256 hash = h == tip_h ? tip_hash : chain_hash(h);
        EXPECT_TRUE(f.apply_block(h, hash,
                                  make_block(h == floor_h + 1
                                                 ? chain_hash(floor_h)
                                                 : chain_hash(h - 1),
                                             std::move(txs))))
            << "fold refused at h=" << h << ": " << f.fail_cause();
    }
    f.mark_proven_complete();
    return {balance, tip_h};
}

// Template-building fixture (mirrors the gbt capstone's minimal shape).
struct GbtFixture {
    UTXOViewCache utxo{nullptr};
    Mempool mp;
    MnStateMachine mnstates{single_mn()};
    uint256 prev_hash{raw256(0xAB)};
    dash::coin::vendor::CSimplifiedMNList sml;
    QuorumManager qmgr;

    GbtFixture() {
        mp.set_utxo(&utxo);
        dash::coin::vendor::CSimplifiedMNListEntry e1;
        e1.proRegTxHash = raw256(0x11);
        e1.isValid = true;
        e1.confirmedHash = raw256(0x12);   // non-null: rollover projection trivial
        sml = dash::coin::vendor::CSimplifiedMNList(
            std::vector<dash::coin::vendor::CSimplifiedMNListEntry>{e1});
    }

    dash::coin::DashWorkData build(int64_t credit_pool,
                                   const AssetUnlockAdmission* adm) const {
        return build_embedded_workdata(
            /*prev_height=*/H - 1, prev_hash, mnstates, mp,
            /*bits=*/0x1b104be3u, /*mtp=*/1'700'000'000u,
            DASH_PUBKEY_VER, DASH_P2SH_VER,
            /*curtime=*/1'700'000'123u, /*version=*/0x20000000u,
            /*underfill_tripped=*/nullptr,
            &sml, &qmgr,
            /*best_cl_height=*/0, dash::coin::k_zero_cl_sig, credit_pool,
            /*qc_commitments=*/nullptr, /*quorum_root_override=*/nullptr,
            dash::coin::DASH_MN_RR_HEIGHT_MAINNET,
            /*superblock_payments=*/nullptr,
            dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET,
            /*suppress_mempool_txs=*/false,
            /*txset_empty_cause=*/"utxo-immature-serving",
            /*pinned_local_txs=*/nullptr,
            /*accrue_pending_asset_locks=*/false,
            adm);
    }
};

// Field-by-field template equality — every byte a miner or verifier consumes.
static void expect_workdata_identical(const dash::coin::DashWorkData& a,
                                      const dash::coin::DashWorkData& b) {
    EXPECT_EQ(a.m_height, b.m_height);
    EXPECT_EQ(a.m_previous_block, b.m_previous_block);
    EXPECT_EQ(a.m_coinbase_value, b.m_coinbase_value);
    EXPECT_EQ(a.m_payment_amount, b.m_payment_amount);
    ASSERT_EQ(a.m_txs.size(), b.m_txs.size());
    for (size_t i = 0; i < a.m_txs.size(); ++i)
        EXPECT_EQ(pack_bytes(MutableTransaction(a.m_txs[i])),
                  pack_bytes(MutableTransaction(b.m_txs[i]))) << "tx[" << i << "]";
    EXPECT_EQ(a.m_tx_hashes, b.m_tx_hashes);
    EXPECT_EQ(a.m_tx_fees, b.m_tx_fees);
    EXPECT_EQ(a.m_tx_data_hex, b.m_tx_data_hex);
    ASSERT_EQ(a.m_packed_payments.size(), b.m_packed_payments.size());
    for (size_t i = 0; i < a.m_packed_payments.size(); ++i) {
        EXPECT_EQ(a.m_packed_payments[i].payee,  b.m_packed_payments[i].payee);
        EXPECT_EQ(a.m_packed_payments[i].amount, b.m_packed_payments[i].amount);
    }
    EXPECT_EQ(a.m_coinbase_payload, b.m_coinbase_payload);
}

// ════════════════════════════════════════════════════════════════════════
// CRangesSet — the dashd util/ranges_set port.
// ════════════════════════════════════════════════════════════════════════

TEST(DashCreditPoolIdx, RangesSetAddContainsDuplicateAndMerge) {
    CRangesSet s;
    EXPECT_TRUE(s.IsEmpty());
    EXPECT_TRUE(s.Add(5));
    EXPECT_FALSE(s.Add(5));            // duplicate ⇒ false (the dashd throw)
    EXPECT_TRUE(s.Contains(5));
    EXPECT_FALSE(s.Contains(4));
    // adjacency merges: 4,5,6 becomes ONE range [4,7)
    EXPECT_TRUE(s.Add(6));
    EXPECT_TRUE(s.Add(4));
    EXPECT_EQ(s.Size(), 3u);
    auto r = s.export_ranges();
    ASSERT_EQ(r.size(), 1u);
    EXPECT_EQ(r[0].first, 4u);
    EXPECT_EQ(r[0].second, 7u);
    // a gap stays two ranges
    EXPECT_TRUE(s.Add(100));
    EXPECT_EQ(s.export_ranges().size(), 2u);
    // bridge the hole 4..7 + 8 + [8? no: add 7 bridges [4,7)+[8,..)?]
    EXPECT_TRUE(s.Add(8));
    EXPECT_TRUE(s.Add(7));             // merges [4,7)+7+[8,9) → [4,9)
    auto r2 = s.export_ranges();
    ASSERT_EQ(r2.size(), 2u);
    EXPECT_EQ(r2[0].first, 4u);
    EXPECT_EQ(r2[0].second, 9u);
    // import/export round-trip
    CRangesSet t;
    EXPECT_TRUE(t.import_ranges(r2));
    EXPECT_TRUE(t.Contains(8));
    EXPECT_FALSE(t.Contains(9));
    EXPECT_TRUE(t.Contains(100));
    // malformed imports refused: empty range, overlap, adjacency
    CRangesSet u;
    EXPECT_FALSE(u.import_ranges({{3, 3}}));
    EXPECT_FALSE(u.import_ranges({{3, 5}, {4, 6}}));
    EXPECT_FALSE(u.import_ranges({{3, 5}, {5, 6}}));   // adjacent = non-canonical
}

// ════════════════════════════════════════════════════════════════════════
// Request-id preimage + era ladder arithmetic.
// ════════════════════════════════════════════════════════════════════════

TEST(DashCreditPoolIdx, UnlockRequestIdPreimageByteExact) {
    // dashd: SerializeHash(make_pair("plwdtx", index)) — preimage is exactly
    // CompactSize(6) || "plwdtx" || u64le(index). Assemble it independently.
    const uint64_t index = 0x0123456789ABCDEFull;
    std::vector<unsigned char> pre;
    pre.push_back(0x06);
    for (char ch : std::string("plwdtx")) pre.push_back(static_cast<unsigned char>(ch));
    for (int i = 0; i < 8; ++i) pre.push_back(static_cast<unsigned char>((index >> (8 * i)) & 0xFF));
    ASSERT_EQ(pre.size(), 15u);
    const uint256 expect = ::Hash(std::span<const unsigned char>(pre.data(), pre.size()));
    EXPECT_EQ(unlockverify::unlock_request_id(index), expect);
    // and it is index-sensitive
    EXPECT_NE(unlockverify::unlock_request_id(index + 1), expect);
}

TEST(DashCreditPoolIdx, EraLadderLimitArithmetic) {
    // V24: max(0, min(pool, 4000 − lately))
    EXPECT_EQ(*cp_idx_current_limit(10'000 * COIN_SAT, 500 * COIN_SAT, CpIdxEra::V24),
              kCpLimitAmountV24 - 500 * COIN_SAT);
    EXPECT_EQ(*cp_idx_current_limit(10'000 * COIN_SAT, 5000 * COIN_SAT, CpIdxEra::V24),
              0);                                            // clamped, not negative
    EXPECT_EQ(*cp_idx_current_limit(100 * COIN_SAT, 0, CpIdxEra::V24),
              100 * COIN_SAT);                               // pool-bound
    // V22: min(pool, 2000) — no lately subtraction in this arm (creditpool.cpp:197)
    EXPECT_EQ(*cp_idx_current_limit(10'000 * COIN_SAT, 1500 * COIN_SAT, CpIdxEra::V22),
              kCpLimitAmountV22);
    EXPECT_EQ(*cp_idx_current_limit(700 * COIN_SAT, 0, CpIdxEra::V22),
              700 * COIN_SAT);
    // pre-v22: max(100, pool/10) − lately, capped at 1000 − lately
    //   pool = 20'000 DASH, lately = 0: pool/10 = 2000 → capped at 1000
    EXPECT_EQ(*cp_idx_current_limit(20'000 * COIN_SAT, 0, CpIdxEra::PreV22),
              kCpLimitAmountHigh);
    //   pool = 5'000 DASH, lately = 200: 500 − 200 = 300
    EXPECT_EQ(*cp_idx_current_limit(5'000 * COIN_SAT, 200 * COIN_SAT, CpIdxEra::PreV22),
              300 * COIN_SAT);
    //   tiny pool (≤ 100 incl. lately): limit = pool itself
    EXPECT_EQ(*cp_idx_current_limit(60 * COIN_SAT, 0, CpIdxEra::PreV22),
              60 * COIN_SAT);
    //   negative ⇒ nullopt (the dashd throw → fail closed)
    EXPECT_FALSE(cp_idx_current_limit(5'000 * COIN_SAT, 1100 * COIN_SAT,
                                      CpIdxEra::PreV22).has_value());
    // era resolution against the schedule
    CpIdxDeploySchedule s{100, 500, 900, 576};
    EXPECT_EQ(cp_idx_era_at(s, 499), CpIdxEra::PreV22);
    EXPECT_EQ(cp_idx_era_at(s, 500), CpIdxEra::V22);
    EXPECT_EQ(cp_idx_era_at(s, 900), CpIdxEra::V24);
}

// ════════════════════════════════════════════════════════════════════════
// Follower fold: cross-check, dedup hard-fail, window slide.
// ════════════════════════════════════════════════════════════════════════

TEST(DashCreditPoolIdx, FoldCrossChecksEveryBlockAndTracksWindow) {
    CreditPoolIdxFollower f(test_schedule(1000));
    f.set_reward_fn([](uint32_t) { return 0; });
    f.arm(chain_hash(1000), 0);
    ASSERT_TRUE(f.armed());

    // lock 1000 DASH at 1001
    EXPECT_TRUE(f.apply_block(1001, chain_hash(1001),
        make_block(chain_hash(1000),
                   {make_cbtx_coinbase(1001, 1000 * COIN_SAT),
                    make_lock_tx(1000 * COIN_SAT)})));
    EXPECT_EQ(f.balance(), 1000 * COIN_SAT);
    EXPECT_EQ(f.lately_unlocked(), 0);

    // unlock 10 DASH + 190 duff fee at 1002 (index 5)
    const int64_t gross = 10 * COIN_SAT + 190;
    EXPECT_TRUE(f.apply_block(1002, chain_hash(1002),
        make_block(chain_hash(1001),
                   {make_cbtx_coinbase(1002, 1000 * COIN_SAT - gross),
                    make_unlock_tx(5, 190, 10 * COIN_SAT, 1001, raw256(0x77))})));
    EXPECT_EQ(f.balance(), 1000 * COIN_SAT - gross);
    EXPECT_EQ(f.lately_unlocked(), gross);
    EXPECT_TRUE(f.indexes().Contains(5));

    // a WRONG committed balance ⇒ fail closed + wipe
    CreditPoolIdxFollower g(test_schedule(1000));
    g.set_reward_fn([](uint32_t) { return 0; });
    g.arm(chain_hash(1000), 0);
    EXPECT_FALSE(g.apply_block(1001, chain_hash(1001),
        make_block(chain_hash(1000),
                   {make_cbtx_coinbase(1001, 999 * COIN_SAT),   // lies by 1 DASH
                    make_lock_tx(1000 * COIN_SAT)})));
    EXPECT_FALSE(g.armed());
    EXPECT_FALSE(g.proven_complete());
    EXPECT_NE(g.fail_cause().find("MISMATCH"), std::string::npos);
}

TEST(DashCreditPoolIdx, DuplicateOnChainIndexHardFailsTheFold) {
    CreditPoolIdxFollower f(test_schedule(1000));
    f.set_reward_fn([](uint32_t) { return 0; });
    f.arm(chain_hash(1000), 0);
    const int64_t gross = 10 * COIN_SAT + 190;
    ASSERT_TRUE(f.apply_block(1001, chain_hash(1001),
        make_block(chain_hash(1000),
                   {make_cbtx_coinbase(1001, 1000 * COIN_SAT),
                    make_lock_tx(1000 * COIN_SAT)})));
    ASSERT_TRUE(f.apply_block(1002, chain_hash(1002),
        make_block(chain_hash(1001),
                   {make_cbtx_coinbase(1002, 1000 * COIN_SAT - gross),
                    make_unlock_tx(5, 190, 10 * COIN_SAT, 1001, raw256(0x77))})));
    // the SAME index mined again ⇒ the dashd throw, ported: hard fail + wipe
    EXPECT_FALSE(f.apply_block(1003, chain_hash(1003),
        make_block(chain_hash(1002),
                   {make_cbtx_coinbase(1003, 1000 * COIN_SAT - 2 * gross),
                    make_unlock_tx(5, 190, 10 * COIN_SAT, 1002, raw256(0x77))})));
    EXPECT_FALSE(f.armed());
    EXPECT_NE(f.fail_cause().find("index-duplicated"), std::string::npos);
}

TEST(DashCreditPoolIdx, WindowSlidesAndLatelyUnlockedDecays) {
    // Tiny window (3) to exercise the slide without 576 blocks.
    CpIdxDeploySchedule s{100, 0, kCpIdxNeverActive, 3};
    CreditPoolIdxFollower f(s);
    f.set_reward_fn([](uint32_t) { return 0; });
    f.arm(chain_hash(100), 0);
    int64_t bal = 0;
    // 101: lock 100 DASH
    bal += 100 * COIN_SAT;
    ASSERT_TRUE(f.apply_block(101, chain_hash(101),
        make_block(chain_hash(100),
                   {make_cbtx_coinbase(101, bal), make_lock_tx(100 * COIN_SAT)})));
    // 102: unlock gross g1
    const int64_t g1 = 1 * COIN_SAT + 100;
    bal -= g1;
    ASSERT_TRUE(f.apply_block(102, chain_hash(102),
        make_block(chain_hash(101),
                   {make_cbtx_coinbase(102, bal),
                    make_unlock_tx(1, 100, 1 * COIN_SAT, 101, raw256(0x77))})));
    EXPECT_EQ(f.lately_unlocked(), g1);
    // 103, 104: empty
    ASSERT_TRUE(f.apply_block(103, chain_hash(103),
        make_block(chain_hash(102), {make_cbtx_coinbase(103, bal)})));
    ASSERT_TRUE(f.apply_block(104, chain_hash(104),
        make_block(chain_hash(103), {make_cbtx_coinbase(104, bal)})));
    EXPECT_EQ(f.lately_unlocked(), g1);   // 102 still inside (105-3=102)
    // 105: the 102 row slides OUT (105 − 3 = 102) → lately decays to 0
    ASSERT_TRUE(f.apply_block(105, chain_hash(105),
        make_block(chain_hash(104), {make_cbtx_coinbase(105, bal)})));
    EXPECT_EQ(f.lately_unlocked(), 0);
}

// ════════════════════════════════════════════════════════════════════════
// KAT 2 — GAP ⇒ FAIL CLOSED (refuses type-9, template stays valid exclude-all).
// ════════════════════════════════════════════════════════════════════════

TEST(DashCreditPoolIdx, Kat2_GapFailsClosedAndTemplateStaysExcludeAll) {
    GbtFixture gbt;
    CreditPoolIdxFollower f(test_schedule(H - 6));
    f.set_reward_fn([](uint32_t) { return 0; });
    f.arm(chain_hash(H - 6), 0);
    ASSERT_TRUE(f.apply_block(H - 5, chain_hash(H - 5),
        make_block(chain_hash(H - 6), {make_cbtx_coinbase(H - 5, 0)})));

    // GAP: skip H-4, feed H-3 ⇒ refuse + latch + wipe.
    EXPECT_FALSE(f.apply_block(H - 3, chain_hash(H - 3),
        make_block(chain_hash(H - 4), {make_cbtx_coinbase(H - 3, 0)})));
    EXPECT_FALSE(f.armed());
    EXPECT_FALSE(f.proven_complete());
    EXPECT_NE(f.fail_cause().find("gap"), std::string::npos);

    // The predicate refuses even with the flag ON…
    EXPECT_FALSE(f.accrual_permitted(/*flag_on=*/true, H, gbt.prev_hash));
    AssetUnlockAdmission adm;
    EXPECT_FALSE(f.try_admit_unlocks(true, H, gbt.prev_hash, {}, {},
                                     kLlmq100_67, adm));
    EXPECT_TRUE(adm.empty());

    // …and the served template is the valid exclude-all one: the caller
    // passes nullptr, which is EXACTLY the baseline build. No balance from
    // the wiped follower can reach the coinbase — the caller still uses its
    // own scalar last_observed_credit_pool, unchanged.
    auto baseline = gbt.build(/*credit_pool=*/12'345, nullptr);
    auto after    = gbt.build(/*credit_pool=*/12'345, nullptr);
    expect_workdata_identical(baseline, after);
    for (const auto& tx : baseline.m_txs)
        EXPECT_NE(tx.type, CAssetUnlockPayload::SPECIALTX_TYPE);
}

// Lineage variant of KAT 2: right height, WRONG parent hash ⇒ same latch.
TEST(DashCreditPoolIdx, Kat2b_LineageMismatchFailsClosed) {
    CreditPoolIdxFollower f(test_schedule(1000));
    f.set_reward_fn([](uint32_t) { return 0; });
    f.arm(chain_hash(1000), 0);
    EXPECT_FALSE(f.apply_block(1001, chain_hash(1001),
        make_block(/*WRONG parent*/ raw256(0xEE),
                   {make_cbtx_coinbase(1001, 0)})));
    EXPECT_FALSE(f.armed());
    EXPECT_NE(f.fail_cause().find("lineage"), std::string::npos);
}

// ════════════════════════════════════════════════════════════════════════
// KAT 1 — FLAG OFF ⇒ byte-identical exclude-all template.
// ════════════════════════════════════════════════════════════════════════

TEST(DashCreditPoolIdx, Kat1_FlagOffTemplateByteIdentical) {
    GbtFixture gbt;

    // A fully healthy, proven-complete, FRESH follower…
    CreditPoolIdxFollower f(test_schedule(H - 6));
    auto fold = fold_synthetic_chain(f, H - 6, H - 1, gbt.prev_hash);
    ASSERT_TRUE(f.proven_complete());
    ASSERT_EQ(f.height(), H - 1);

    // …with the flag OFF refuses admission (conjunct a):
    AssetUnlockAdmission adm;
    EXPECT_FALSE(f.accrual_permitted(/*flag_on=*/false, H, gbt.prev_hash));
    EXPECT_FALSE(f.try_admit_unlocks(false, H, gbt.prev_hash, {}, {},
                                     kLlmq100_67, adm));
    EXPECT_TRUE(adm.empty());

    // and the template path is BYTE-IDENTICAL to today's exclude-all across
    // all three shapes the call site can take: seam absent (defaulted),
    // explicit nullptr, and an empty admission object.
    auto absent = build_embedded_workdata(
        H - 1, gbt.prev_hash, gbt.mnstates, gbt.mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER,
        1'700'000'123u, 0x20000000u, nullptr, &gbt.sml, &gbt.qmgr,
        0, dash::coin::k_zero_cl_sig, fold.balance);
    auto null_seam  = gbt.build(fold.balance, nullptr);
    AssetUnlockAdmission empty_adm;
    auto empty_seam = gbt.build(fold.balance, &empty_adm);
    expect_workdata_identical(absent, null_seam);
    expect_workdata_identical(null_seam, empty_seam);
    for (const auto& tx : null_seam.m_txs)
        EXPECT_NE(tx.type, CAssetUnlockPayload::SPECIALTX_TYPE);
}

// ════════════════════════════════════════════════════════════════════════
// KAT 3 — duplicate index candidate ⇒ EXCLUDED (fold clean, set authoritative).
// ════════════════════════════════════════════════════════════════════════
// Needs no BLS: the dedup check runs BEFORE the signature check, so the
// exclusion must hold in every build (fail-closed ordering pinned here).

TEST(DashCreditPoolIdx, Kat3_DuplicateIndexCandidateExcluded) {
    GbtFixture gbt;
    CreditPoolIdxFollower f(test_schedule(H - 6));
    fold_synthetic_chain(f, H - 6, H - 1, gbt.prev_hash);   // mines index 5
    ASSERT_TRUE(f.indexes().Contains(5));
    ASSERT_TRUE(f.proven_complete());

    // Candidate re-using mined index 5 (any signature — dedup fires first).
    auto dup = make_unlock_tx(5, 200, 1 * COIN_SAT, H - 2, raw256(0x77));
    QuorumCandidate q;
    q.quorum_hash = raw256(0x77);
    q.base_height = H - 24;
    AssetUnlockAdmission adm;
    const bool usable = f.try_admit_unlocks(true, H, gbt.prev_hash, {dup}, {q},
                                            kLlmq100_67, adm);
#ifdef C2POOL_DASH_BLS
    // Backend present: the predicate holds, the admission is usable, and the
    // duplicated index is excluded BEFORE any signature check runs.
    EXPECT_TRUE(usable);
#else
    // Stub build: conjunct (b) refuses the whole admission — structurally OFF.
    EXPECT_FALSE(usable);
#endif
    EXPECT_TRUE(adm.empty()) << "duplicated index must be EXCLUDED";
}

// ════════════════════════════════════════════════════════════════════════
// KAT 5 (stub half) — no BLS backend ⇒ structurally OFF, in EVERY build.
// ════════════════════════════════════════════════════════════════════════

#ifndef C2POOL_DASH_BLS
TEST(DashCreditPoolIdx, Kat5_NoBlsBackendMeansNoAccrualEver) {
    GbtFixture gbt;
    CreditPoolIdxFollower f(test_schedule(H - 6));
    fold_synthetic_chain(f, H - 6, H - 1, gbt.prev_hash);
    ASSERT_TRUE(f.proven_complete());
    // conjunct (b): flag ON, follower perfect — still refused.
    EXPECT_FALSE(f.accrual_permitted(true, H, gbt.prev_hash));
    AssetUnlockAdmission adm;
    EXPECT_FALSE(f.try_admit_unlocks(true, H, gbt.prev_hash, {}, {},
                                     kLlmq100_67, adm));
    EXPECT_TRUE(adm.empty());
}
#endif

// ════════════════════════════════════════════════════════════════════════
// KATs 4 + 5 (real BLS): verified sig ⇒ INCLUDED with exact committed
// balance; tampered sig ⇒ REJECTED.
// ════════════════════════════════════════════════════════════════════════

#ifdef C2POOL_DASH_BLS
namespace {
bool vendor_backend_sanity() {
    return dash::coin::vendor::bls_backend_available();
}

struct SignedUnlock {
    MutableTransaction tx;
    QuorumCandidate    quorum;
    int64_t            gross;   // vout + fee
    uint32_t           fee;
};

// Build a type-9 candidate whose quorumSig REALLY verifies: generate a
// quorum keypair, derive msgHash exactly as CheckAssetUnlockTx does (tx with
// zeroed sig), sign SignHash(llmqType, quorumHash, requestId(plwdtx‖index),
// msgHash) under the BASIC scheme, then splice the signature back in.
SignedUnlock make_signed_unlock(uint64_t index, uint32_t fee, int64_t vout,
                                uint32_t requested_height) {
    bls::BasicSchemeMPL scheme;
    std::vector<uint8_t> seed(32, 0x5A);
    bls::PrivateKey sk = scheme.KeyGen(seed);
    bls::G1Element pk = sk.GetG1Element();

    SignedUnlock out;
    out.fee = fee;
    out.gross = vout + fee;
    out.quorum.quorum_hash = raw256(0x77);
    out.quorum.base_height = requested_height - 20;
    auto pkraw = pk.Serialize(false);
    std::memcpy(out.quorum.quorum_public_key.data(), pkraw.data(), 48);

    // tx with ZEROED sig → msgHash
    out.tx = make_unlock_tx(index, fee, vout, requested_height,
                            out.quorum.quorum_hash);
    CAssetUnlockPayload pl;
    EXPECT_TRUE(dash::coin::vendor::parse_assetunlock_payload(
        out.tx.extra_payload, pl));
    const uint256 msg_hash = unlockverify::unlock_msg_hash(out.tx, pl);

    const uint256 request_id = unlockverify::unlock_request_id(index);
    const uint256 sign_hash = dash::coin::chainlock::build_sign_hash(
        kLlmq100_67.type, out.quorum.quorum_hash, request_id, msg_hash);

    bls::G2Element sig = scheme.Sign(sk, bls::Bytes(sign_hash.data(), 32));
    auto sigraw = sig.Serialize(false);
    std::array<uint8_t, 96> sigarr{};
    std::memcpy(sigarr.data(), sigraw.data(), 96);

    // splice the REAL signature into the payload
    out.tx = make_unlock_tx(index, fee, vout, requested_height,
                            out.quorum.quorum_hash, sigarr);
    return out;
}
}  // namespace

TEST(DashCreditPoolIdx, Kat4_VerifiedUnlockIncludedAndBalanceCommitsExactly) {
    GbtFixture gbt;
    CreditPoolIdxFollower f(test_schedule(H - 6));
    auto fold = fold_synthetic_chain(f, H - 6, H - 1, gbt.prev_hash);
    ASSERT_TRUE(f.proven_complete());
    ASSERT_TRUE(vendor_backend_sanity());

    auto su = make_signed_unlock(/*index=*/7, /*fee=*/200,
                                 /*vout=*/2 * COIN_SAT,
                                 /*requested_height=*/H - 2);

    AssetUnlockAdmission adm;
    ASSERT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {su.tx},
                                    {su.quorum}, kLlmq100_67, adm));
    ASSERT_EQ(adm.txs.size(), 1u) << "verified non-duplicate unlock must be INCLUDED";
    EXPECT_EQ(adm.gross_unlocked, su.gross);
    EXPECT_EQ(adm.total_payload_fees, static_cast<int64_t>(su.fee));

    // Build the template through the single call-site seam.
    auto w = gbt.build(fold.balance, &adm);

    // The unlock tx rides the body, byte-exact, with its payload fee recorded.
    bool found = false;
    for (size_t i = 0; i < w.m_txs.size(); ++i) {
        if (w.m_txs[i].type == CAssetUnlockPayload::SPECIALTX_TYPE) {
            found = true;
            EXPECT_EQ(pack_bytes(MutableTransaction(w.m_txs[i])), pack_bytes(su.tx));
            EXPECT_EQ(w.m_tx_fees[i], static_cast<uint64_t>(su.fee));
        }
    }
    EXPECT_TRUE(found);

    // The committed creditPoolBalance is EXACTLY what dashd's validator will
    // re-derive from this block's own txs: prev + platformReward − gross.
    CCbTx committed;
    ASSERT_TRUE(parse_cbtx(w.m_coinbase_payload, committed));
    const int64_t platform_reward =
        dash::coin::compute_dash_platform_reward_post_v20_mn_rr(H);
    EXPECT_EQ(committed.creditPoolBalance,
              fold.balance + platform_reward - su.gross);

    // And the follower's own scalar machine agrees when it folds the block
    // we just built (the cbTx-committed value IS the computed value).
    dash::coin::CreditPool xcheck;
    xcheck.seed(fold.balance, H - 1);
    BlockType built;
    built.m_previous_block = gbt.prev_hash;
    MutableTransaction cb;   // stand-in coinbase (index 0 skipped by the walk)
    cb.version = 3; cb.type = 5;
    built.m_txs.push_back(cb);
    for (const auto& t : w.m_txs) built.m_txs.push_back(MutableTransaction(t));
    xcheck.apply_block(built, H, platform_reward);
    EXPECT_EQ(xcheck.balance(), committed.creditPoolBalance);

    // The unlock's fee flows through the EXISTING value formulas.
    const int64_t reward = dash::coin::compute_dash_block_reward_post_v20(H);
    EXPECT_EQ(w.m_coinbase_value,
              static_cast<uint64_t>(reward + static_cast<int64_t>(su.fee)));
}

TEST(DashCreditPoolIdx, Kat5_TamperedQuorumSigRejected) {
    GbtFixture gbt;
    CreditPoolIdxFollower f(test_schedule(H - 6));
    fold_synthetic_chain(f, H - 6, H - 1, gbt.prev_hash);
    ASSERT_TRUE(f.proven_complete());

    auto su = make_signed_unlock(7, 200, 2 * COIN_SAT, H - 2);

    // Flip ONE byte of the signature inside the payload.
    CAssetUnlockPayload pl;
    ASSERT_TRUE(dash::coin::vendor::parse_assetunlock_payload(
        su.tx.extra_payload, pl));
    auto bad_sig = pl.quorumSig;
    bad_sig[13] ^= 0x01;
    auto bad_tx = make_unlock_tx(7, 200, 2 * COIN_SAT, H - 2,
                                 su.quorum.quorum_hash, bad_sig);

    AssetUnlockAdmission adm;
    EXPECT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {bad_tx},
                                    {su.quorum}, kLlmq100_67, adm));
    EXPECT_TRUE(adm.empty()) << "a bad quorumSig must be REJECTED (fail-closed BLS)";

    // Control (the test is not vacuous): the untampered tx IS admitted.
    AssetUnlockAdmission good;
    EXPECT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {su.tx},
                                    {su.quorum}, kLlmq100_67, good));
    EXPECT_EQ(good.txs.size(), 1u);

    // Expiry window refusals (assetlocktx.cpp:134-139) with a VALID sig:
    // requestedHeight in the future…
    auto future = make_signed_unlock(8, 200, 2 * COIN_SAT, H + 10);
    AssetUnlockAdmission f1;
    EXPECT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {future.tx},
                                    {future.quorum}, kLlmq100_67, f1));
    EXPECT_TRUE(f1.empty());
    // …and one expired past requested + 48.
    auto expired = make_signed_unlock(9, 200, 2 * COIN_SAT, H - 1 - 48);
    AssetUnlockAdmission f2;
    EXPECT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {expired.tx},
                                    {expired.quorum}, kLlmq100_67, f2));
    EXPECT_TRUE(f2.empty());

    // Quorum not in the active scan set (bad-assetunlock-too-old-quorum):
    // valid sig, but the candidate list names a DIFFERENT quorum hash.
    QuorumCandidate other = su.quorum;
    other.quorum_hash = raw256(0x99);
    AssetUnlockAdmission f3;
    EXPECT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {su.tx},
                                    {other}, kLlmq100_67, f3));
    EXPECT_TRUE(f3.empty());
}

// Withdrawal-limit conjunct with a REAL signature: an unlock beyond the
// era-correct LimitAmount is excluded even though its sig verifies.
TEST(DashCreditPoolIdx, Kat4b_LimitBindsEvenWithValidSig) {
    GbtFixture gbt;
    CreditPoolIdxFollower f(test_schedule(H - 6));
    auto fold = fold_synthetic_chain(f, H - 6, H - 1, gbt.prev_hash);
    // Pool holds ~990 DASH (era V22 limit = min(pool, 2000) = pool). An
    // unlock of MORE than the pool must be refused.
    auto too_big = make_signed_unlock(11, 300, fold.balance + COIN_SAT, H - 2);
    AssetUnlockAdmission adm;
    EXPECT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {too_big.tx},
                                    {too_big.quorum}, kLlmq100_67, adm));
    EXPECT_TRUE(adm.empty());
}
#endif  // C2POOL_DASH_BLS

// ════════════════════════════════════════════════════════════════════════
// CreditPoolIdxDb — schema round-trip, atomic apply, restore, wipe.
// ════════════════════════════════════════════════════════════════════════

namespace {
std::string temp_db_path(const char* tag) {
    auto p = std::filesystem::temp_directory_path() /
             (std::string("c2pool-cpidx-") + tag + "-" +
              std::to_string(::getpid()));
    std::filesystem::remove_all(p);
    return p.string();
}
}  // namespace

TEST(DashCreditPoolIdxDb, SchemaCodecsRoundTripAndRejectMalformed) {
    // ranges 'R'
    std::vector<std::pair<uint64_t, uint64_t>> r{{4, 9}, {100, 101}};
    auto enc = CreditPoolIdxDb::encode_ranges(r);
    EXPECT_EQ(enc[0], CreditPoolIdxDb::kSchemaVer);
    std::vector<std::pair<uint64_t, uint64_t>> back;
    ASSERT_TRUE(CreditPoolIdxDb::decode_ranges(enc, back));
    EXPECT_EQ(back, r);
    // malformed: overlap / adjacency / empty / trailing garbage all refused
    EXPECT_FALSE(CreditPoolIdxDb::decode_ranges(
        CreditPoolIdxDb::encode_ranges({{4, 9}, {8, 12}}), back));
    EXPECT_FALSE(CreditPoolIdxDb::decode_ranges(
        CreditPoolIdxDb::encode_ranges({{4, 9}, {9, 12}}), back));
    EXPECT_FALSE(CreditPoolIdxDb::decode_ranges(
        CreditPoolIdxDb::encode_ranges({{4, 4}}), back));
    auto trailing = enc;
    trailing.push_back(0x00);
    EXPECT_FALSE(CreditPoolIdxDb::decode_ranges(trailing, back));

    // cursor 'C' — 47 bytes exactly
    CpIdxCursor c;
    c.height = 2'400'000;
    c.block_hash = raw256(0x42);
    c.computed_balance = -12345678901LL;
    c.proven_complete = true;
    c.era = 1;
    auto cenc = CreditPoolIdxDb::encode_cursor(c);
    EXPECT_EQ(cenc.size(), 47u);
    CpIdxCursor cback;
    ASSERT_TRUE(CreditPoolIdxDb::decode_cursor(cenc, cback));
    EXPECT_EQ(cback.height, c.height);
    EXPECT_EQ(cback.block_hash, c.block_hash);
    EXPECT_EQ(cback.computed_balance, c.computed_balance);
    EXPECT_EQ(cback.proven_complete, true);
    EXPECT_EQ(cback.era, 1);
    auto cshort = cenc; cshort.pop_back();
    EXPECT_FALSE(CreditPoolIdxDb::decode_cursor(cshort, cback));
    auto cbad_era = cenc; cbad_era[46] = 7;
    EXPECT_FALSE(CreditPoolIdxDb::decode_cursor(cbad_era, cback));

    // seed 'S' — 44 bytes
    CpIdxSeedProvenance sp;
    sp.v20_floor_height = 1'987'776;
    sp.v20_block_hash = raw256(0x24);
    sp.seed_wallclock = 1'750'000'000LL;
    auto senc = CreditPoolIdxDb::encode_seed(sp);
    EXPECT_EQ(senc.size(), 44u);
    CpIdxSeedProvenance sback;
    ASSERT_TRUE(CreditPoolIdxDb::decode_seed(senc, sback));
    EXPECT_EQ(sback.v20_floor_height, sp.v20_floor_height);
    EXPECT_EQ(sback.v20_block_hash, sp.v20_block_hash);
    EXPECT_EQ(sback.seed_wallclock, sp.seed_wallclock);

    // window key: BIG-endian height so prefix scans ascend
    EXPECT_LT(CreditPoolIdxDb::key_window(255),
              CreditPoolIdxDb::key_window(256));
}

TEST(DashCreditPoolIdxDb, PersistRestoreAndWipe) {
    const std::string path = temp_db_path("persist");
    {
        CreditPoolIdxDb db(path);
        ASSERT_TRUE(db.open());
        CreditPoolIdxFollower f(test_schedule(1000));
        f.set_reward_fn([](uint32_t) { return 0; });
        f.attach_db(&db);
        f.arm(chain_hash(1000), 0);
        ASSERT_TRUE(f.apply_block(1001, chain_hash(1001),
            make_block(chain_hash(1000),
                       {make_cbtx_coinbase(1001, 1000 * COIN_SAT),
                        make_lock_tx(1000 * COIN_SAT)})));
        const int64_t gross = 10 * COIN_SAT + 190;
        ASSERT_TRUE(f.apply_block(1002, chain_hash(1002),
            make_block(chain_hash(1001),
                       {make_cbtx_coinbase(1002, 1000 * COIN_SAT - gross),
                        make_unlock_tx(5, 190, 10 * COIN_SAT, 1001,
                                       raw256(0x77))})));
        f.mark_proven_complete();
        db.close();
    }
    {
        // A fresh follower restores the cursor/set/window from disk…
        CreditPoolIdxDb db(path);
        ASSERT_TRUE(db.open());
        CreditPoolIdxFollower f(test_schedule(1000));
        f.set_reward_fn([](uint32_t) { return 0; });
        f.attach_db(&db);
        ASSERT_TRUE(f.try_restore());
        EXPECT_EQ(f.height(), 1002u);
        EXPECT_EQ(f.block_hash(), chain_hash(1002));
        EXPECT_EQ(f.balance(), 1000 * COIN_SAT - (10 * COIN_SAT + 190));
        EXPECT_TRUE(f.indexes().Contains(5));
        EXPECT_EQ(f.lately_unlocked(), 10 * COIN_SAT + 190);
        // …but NOT proven_complete: a restart must re-bridge to the tip first
        // (the predicate is one-way sticky across restarts too).
        EXPECT_FALSE(f.proven_complete());
        // resumed fold continues seamlessly
        EXPECT_TRUE(f.apply_block(1003, chain_hash(1003),
            make_block(chain_hash(1002),
                       {make_cbtx_coinbase(1003,
                                           1000 * COIN_SAT - (10 * COIN_SAT + 190))})));
        db.close();
    }
    {
        // A schedule whose floor disagrees adjudicates ABSENT + wipes.
        CreditPoolIdxDb db(path);
        ASSERT_TRUE(db.open());
        CreditPoolIdxFollower g(test_schedule(2000));
        g.attach_db(&db);
        EXPECT_FALSE(g.try_restore());
        // …and after the wipe the original schedule finds nothing either.
        CreditPoolIdxFollower f(test_schedule(1000));
        f.attach_db(&db);
        EXPECT_FALSE(f.try_restore());
        db.close();
    }
    std::filesystem::remove_all(path);
}

TEST(DashCreditPoolIdxDb, TornNamespaceAdjudicatesAbsent) {
    const std::string path = temp_db_path("torn");
    {
        CreditPoolIdxDb db(path);
        ASSERT_TRUE(db.open());
        // Write ONLY a cursor — no 'R', no 'S' (a torn/partial namespace).
        CpIdxCursor c;
        c.height = 1002;
        c.block_hash = chain_hash(1002);
        ASSERT_TRUE(db.write_cursor(c));
        std::vector<std::pair<uint64_t, uint64_t>> ranges;
        std::map<uint32_t, CpIdxWindowRowRec> rows;
        CpIdxCursor cur;
        CpIdxSeedProvenance seed;
        bool corrupt = false;
        EXPECT_FALSE(db.load(ranges, rows, cur, seed, corrupt));
        EXPECT_TRUE(corrupt) << "a torn namespace must be flagged for wipe";
        db.close();
    }
    std::filesystem::remove_all(path);
}

// Follower fail-closed also wipes the PERSISTED namespace (design: a balance
// divergence is total loss of provenance, on disk too).
TEST(DashCreditPoolIdxDb, FailClosedWipesTheNamespace) {
    const std::string path = temp_db_path("wipe");
    {
        CreditPoolIdxDb db(path);
        ASSERT_TRUE(db.open());
        CreditPoolIdxFollower f(test_schedule(1000));
        f.set_reward_fn([](uint32_t) { return 0; });
        f.attach_db(&db);
        f.arm(chain_hash(1000), 0);
        ASSERT_TRUE(f.apply_block(1001, chain_hash(1001),
            make_block(chain_hash(1000), {make_cbtx_coinbase(1001, 0)})));
        // gap ⇒ fail closed ⇒ namespace gone
        EXPECT_FALSE(f.apply_block(1003, chain_hash(1003),
            make_block(chain_hash(1002), {make_cbtx_coinbase(1003, 0)})));
        CreditPoolIdxFollower g(test_schedule(1000));
        g.attach_db(&db);
        EXPECT_FALSE(g.try_restore()) << "wiped namespace must not restore";
        db.close();
    }
    std::filesystem::remove_all(path);
}
