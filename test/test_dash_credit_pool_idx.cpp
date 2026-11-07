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
#include <impl/dash/coin/credit_pool_lane.hpp>
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
#include <map>
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
using dash::coin::cp_unlock_limit_v24;
using dash::coin::cp_idx_v24_active_at;
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
    const std::array<uint8_t, 96>& sig = {}, uint8_t payload_version = 1) {
    CAssetUnlockPayload p;
    p.nVersion = payload_version;
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
    // V24 (Dash Core v24.0.0 UnlockLimitV24): the net rule on the balance at
    // the window start; latelyUnlocked plays no part.
    EXPECT_EQ(*cp_idx_current_limit(10'000 * COIN_SAT, 500 * COIN_SAT, CpIdxEra::V24,
                                    10'000 * COIN_SAT),
              2000 * COIN_SAT);                              // floor of 2000 DASH
    EXPECT_EQ(*cp_idx_current_limit(12'000 * COIN_SAT, 5000 * COIN_SAT, CpIdxEra::V24,
                                    15'000 * COIN_SAT),
              0);                                            // drop taken: clamped, not negative
    EXPECT_EQ(*cp_idx_current_limit(100 * COIN_SAT, 0, CpIdxEra::V24, 100 * COIN_SAT),
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

// Dash Core v24.0.0 src/test/evo_assetlocks_tests.cpp credit_pool_unlock_limit_v24.
TEST(DashCreditPoolIdx, UnlockLimitV24MatchesDashCoreVectors) {
    constexpr int64_t COIN = COIN_SAT;
    constexpr int64_t MAX_MONEY = 21'000'000 * COIN;
    const auto limit = [](int64_t b, int64_t s) { return cp_unlock_limit_v24(b, s); };
    EXPECT_EQ(limit(15000 * COIN, 15000 * COIN), 3000 * COIN);
    EXPECT_EQ(limit(5000 * COIN, 5000 * COIN), 2000 * COIN);
    EXPECT_EQ(limit(40000 * COIN, 40000 * COIN), 8000 * COIN);
    // The drop already taken inside the window comes out of the allowance
    EXPECT_EQ(limit(14000 * COIN, 15000 * COIN), 2000 * COIN);
    EXPECT_EQ(limit(12000 * COIN + 1, 15000 * COIN), 1);
    EXPECT_EQ(limit(12000 * COIN, 15000 * COIN), 0);
    EXPECT_EQ(limit(11000 * COIN, 15000 * COIN), 0);
    // The floor covers small pools entirely
    EXPECT_EQ(limit(100 * COIN, 100 * COIN), 100 * COIN);
    // Growth inside the window is withdrawable on top of the allowed drop
    EXPECT_EQ(limit(16000 * COIN, 15000 * COIN), 4000 * COIN);
    EXPECT_EQ(limit(45000 * COIN, 40000 * COIN), 13000 * COIN);
    // Never more than the pool holds
    EXPECT_EQ(limit(500 * COIN, 500 * COIN), 500 * COIN);
    EXPECT_EQ(limit(0, 5000 * COIN), 0);
    // No balance at the window start
    EXPECT_EQ(limit(123 * COIN, 0), 123 * COIN);
    EXPECT_EQ(limit(0, 0), 0);
    // Integer truncation only ever rounds the allowance down
    EXPECT_EQ(limit(10000 * COIN + 4, 10000 * COIN + 4), 2000 * COIN);
    EXPECT_EQ(limit(10000 * COIN + 5, 10000 * COIN + 5), 2000 * COIN + 1);
    EXPECT_EQ(limit(MAX_MONEY, MAX_MONEY), MAX_MONEY * 20 / 100);
    // The era ladder passes the window-start balance through unchanged.
    EXPECT_EQ(*cp_idx_current_limit(45000 * COIN, 7 * COIN, CpIdxEra::V24, 40000 * COIN),
              13000 * COIN);
    // ...and the v24 rule can be STRICTER than the v22 cap: treating an
    // active era as v22 would admit what Dash Core v24 rejects.
    EXPECT_LT(*cp_idx_current_limit(12000 * COIN, 0, CpIdxEra::V24, 15000 * COIN),
              *cp_idx_current_limit(12000 * COIN, 0, CpIdxEra::V22));
}

// With no explicit height the era comes from the deployment status for the
// schedule's network; without one installed, mainnet is v24-INACTIVE only
// below the earliest possible activation (2,580,480) and UNKNOWN from it on,
// and an unknown era refuses every unlock (exclude-all).
TEST(DashCreditPoolIdx, V24EraUnknownFailsClosed) {
    CpIdxDeploySchedule s{100, 0, kCpIdxNeverActive, 576};
    EXPECT_EQ(cp_idx_era_at(s, 2'580'479), CpIdxEra::V22);
    EXPECT_FALSE(cp_idx_era_at(s, 2'580'480).has_value());
    EXPECT_EQ(cp_idx_v24_active_at(s, 2'580'479), std::optional<bool>(false));
    EXPECT_FALSE(cp_idx_v24_active_at(s, 2'580'480).has_value());
    // Testnet: the buried height decides.
    CpIdxDeploySchedule t{100, 0, kCpIdxNeverActive, 576, dash::coin::DashNetwork::TESTNET};
    EXPECT_EQ(cp_idx_era_at(t, 1'577'999), CpIdxEra::V22);
    EXPECT_EQ(cp_idx_era_at(t, 1'578'000), CpIdxEra::V24);

    // A follower past the earliest activation with no status: exclude-all.
    const uint32_t HH = 2'600'000;
    const uint256 tip_hash = raw256(0x5C);
    CreditPoolIdxFollower f(CpIdxDeploySchedule{HH - 6, 0u, kCpIdxNeverActive, 576u});
    fold_synthetic_chain(f, HH - 6, HH - 1, tip_hash);
    ASSERT_TRUE(f.proven_complete());
    AssetUnlockAdmission adm;
    EXPECT_FALSE(f.try_admit_unlocks(true, HH, tip_hash, {}, {}, kLlmq100_67, adm));
    EXPECT_TRUE(adm.empty());
    // An explicit activation height decides it.
    f.set_v24_height(HH - 1000);
    EXPECT_TRUE(f.try_admit_unlocks(true, HH, tip_hash, {}, {}, kLlmq100_67, adm));
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

// Dash Core v24 bad-assetunlocktx-version-2: a version-2 unlock (stable txid)
// rides only when DEPLOYMENT_V24 is active for the block being built.
TEST(DashCreditPoolIdx, V2UnlockNeedsV24ForTheBlock) {
    GbtFixture gbt;
    CreditPoolIdxFollower f(test_schedule(H - 6));
    fold_synthetic_chain(f, H - 6, H - 1, gbt.prev_hash);
    ASSERT_TRUE(f.proven_complete());
    ASSERT_TRUE(vendor_backend_sanity());

    // A really signed version-2 unlock: same construction, payload version 2
    // (msgHash = the full serialization with the signature zeroed).
    auto su = make_signed_unlock(21, 200, 2 * COIN_SAT, H - 2);
    {
        bls::BasicSchemeMPL scheme;
        std::vector<uint8_t> seed(32, 0x5A);
        bls::PrivateKey sk = scheme.KeyGen(seed);
        auto tx2 = make_unlock_tx(21, 200, 2 * COIN_SAT, H - 2, su.quorum.quorum_hash, {}, 2);
        CAssetUnlockPayload pl;
        ASSERT_TRUE(dash::coin::vendor::parse_assetunlock_payload(tx2.extra_payload, pl));
        const uint256 sign_hash = dash::coin::chainlock::build_sign_hash(
            kLlmq100_67.type, su.quorum.quorum_hash, unlockverify::unlock_request_id(21),
            unlockverify::unlock_msg_hash(tx2, pl));
        bls::G2Element sig = scheme.Sign(sk, bls::Bytes(sign_hash.data(), 32));
        auto sigraw = sig.Serialize(false);
        std::array<uint8_t, 96> sigarr{};
        std::memcpy(sigarr.data(), sigraw.data(), 96);
        su.tx = make_unlock_tx(21, 200, 2 * COIN_SAT, H - 2, su.quorum.quorum_hash, sigarr, 2);
    }
    // v24 not active for H (mainnet, no status, below 2,580,480): refused.
    AssetUnlockAdmission before;
    EXPECT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {su.tx}, {su.quorum}, kLlmq100_67, before));
    EXPECT_TRUE(before.empty()) << "bad-assetunlocktx-version-2";
    // v24 active from H: admitted (the pool at H-1 is still on the v22 rule).
    f.set_v24_height(H);
    AssetUnlockAdmission after;
    EXPECT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {su.tx}, {su.quorum}, kLlmq100_67, after));
    ASSERT_EQ(after.txs.size(), 1u);
    EXPECT_EQ(after.gross_unlocked, su.gross);
    // Version 3 is never valid.
    auto v3 = su.tx;
    v3.extra_payload[0] = 3;
    AssetUnlockAdmission bad;
    EXPECT_TRUE(f.try_admit_unlocks(true, H, gbt.prev_hash, {v3}, {su.quorum}, kLlmq100_67, bad));
    EXPECT_TRUE(bad.empty());
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

// The window rows carry the pool balance (schema 2), so the balance at the
// window start survives a restart.
TEST(DashCreditPoolIdxDb, WindowRowsCarryTheBalanceAcrossRestore) {
    CpIdxWindowRowRec r;
    r.gross_unlocked = 7;
    r.n_type9 = 1;
    r.balance = 0x0102030405060708LL;
    const auto enc = CreditPoolIdxDb::encode_row(r);
    ASSERT_EQ(enc.size(), 20u);
    EXPECT_EQ(enc[12], 0x08);
    EXPECT_EQ(enc[19], 0x01);

    const std::string path = temp_db_path("balance");
    CpIdxDeploySchedule s{1000, 0, kCpIdxNeverActive, 3};
    {
        CreditPoolIdxDb db(path);
        ASSERT_TRUE(db.open());
        CreditPoolIdxFollower f(s);
        f.set_reward_fn([](uint32_t) { return 0; });
        f.attach_db(&db);
        f.arm(chain_hash(1000), 0);
        int64_t bal = 1000 * COIN_SAT;
        ASSERT_TRUE(f.apply_block(1001, chain_hash(1001),
            make_block(chain_hash(1000), {make_cbtx_coinbase(1001, bal), make_lock_tx(bal)})));
        for (uint32_t h = 1002; h <= 1004; ++h)
            ASSERT_TRUE(f.apply_block(h, chain_hash(h),
                make_block(chain_hash(h - 1), {make_cbtx_coinbase(h, bal)})));
        EXPECT_EQ(f.balance_at_window_start(), std::optional<int64_t>(bal)) << "row 1001";
        db.close();
    }
    {
        CreditPoolIdxDb db(path);
        ASSERT_TRUE(db.open());
        CreditPoolIdxFollower f(s);
        f.set_reward_fn([](uint32_t) { return 0; });
        f.attach_db(&db);
        ASSERT_TRUE(f.try_restore());
        EXPECT_EQ(f.height(), 1004u);
        EXPECT_EQ(f.balance_at_window_start(), std::optional<int64_t>(1000 * COIN_SAT))
            << "the window-start row is restored with its balance";
        db.close();
    }
    std::filesystem::remove_all(path);
}

// ════════════════════════════════════════════════════════════════════════
// The follower on REAL testnet data, and the lane that runs it in the node.
// ════════════════════════════════════════════════════════════════════════

#include "dash_v24_testnet_credit_pool.inc"

namespace {
std::vector<unsigned char> cp_unhex(const std::string& h) {
    std::vector<unsigned char> out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(static_cast<unsigned char>(std::stoul(h.substr(i, 2), nullptr, 16)));
    return out;
}
std::vector<MutableTransaction> cp_special_txs(const char* list) {
    std::vector<MutableTransaction> out;
    std::string s(list), tok;
    for (size_t i = 0; i <= s.size(); ++i) {
        if (i == s.size() || s[i] == ' ') {
            if (!tok.empty()) {
                const auto raw = cp_unhex(tok);
                MutableTransaction tx;
                ::PackStream ps(raw);
                ps >> tx;
                EXPECT_TRUE(ps.empty());
                out.push_back(tx);
                tok.clear();
            }
        } else {
            tok.push_back(s[i]);
        }
    }
    return out;
}
uint256 cp_hash(const char* hex) { uint256 h; h.SetHex(hex); return h; }
}  // namespace

// The real testnet chain 1,581,800..1,582,439 (Dash Core v24 active since
// 1,578,000): the follower recomputes every block's pool balance (platform
// reward + locks - unlocks) and must land on the CbTx creditPoolBalance the
// chain committed, 639 blocks in a row with 38 unlocks and 8 locks. After 576
// blocks the window-start balance is the committed balance 576 blocks back,
// latelyUnlocked is the window's gross unlocks, and the limit is Dash Core
// v24's UnlockLimitV24 of the two.
TEST(DashCreditPoolIdx, RealTestnetBalancesFollowTheCbTx) {
    const size_t N = sizeof(kTnCreditPool) / sizeof(kTnCreditPool[0]);
    ASSERT_GE(N, 600u);
    CpIdxDeploySchedule s{kTnCreditPool[0].height, 1'148'500u, 1'578'000u, 576u,
                          dash::coin::DashNetwork::TESTNET};
    CreditPoolIdxFollower f(s);
    f.set_reward_fn([](uint32_t h) {
        return dash::coin::compute_dash_platform_reward_post_v20_mn_rr(
            h, dash::coin::DASH_MN_RR_HEIGHT_TESTNET);
    });
    f.arm(cp_hash(kTnCreditPool[0].hash), kTnCreditPool[0].balance);
    int locks = 0, unlocks = 0;
    std::vector<int64_t> gross(N, 0);
    for (size_t i = 1; i < N; ++i) {
        const auto& r = kTnCreditPool[i];
        std::vector<MutableTransaction> txs{make_cbtx_coinbase(r.height, r.balance)};
        for (auto& t : cp_special_txs(r.special_txs)) {
            if (t.type == 8) ++locks;
            if (t.type == 9) {
                ++unlocks;
                CAssetUnlockPayload pl;
                ASSERT_TRUE(dash::coin::vendor::parse_assetunlock_payload(t.extra_payload, pl));
                gross[i] += static_cast<int64_t>(pl.fee);
                for (const auto& o : t.vout) gross[i] += o.value;
            }
            txs.push_back(std::move(t));
        }
        ASSERT_TRUE(f.apply_block(r.height, cp_hash(r.hash),
                                  make_block(cp_hash(kTnCreditPool[i - 1].hash), std::move(txs))))
            << "h=" << r.height << ": " << f.fail_cause();
        ASSERT_EQ(f.balance(), r.balance) << "h=" << r.height;
    }
    EXPECT_EQ(unlocks, 38);
    EXPECT_EQ(locks, 8);
    const size_t L = N - 1;
    EXPECT_EQ(f.balance_at_window_start(), std::optional<int64_t>(kTnCreditPool[L - 576].balance));
    int64_t lately = 0;
    for (size_t i = L - 575; i <= L; ++i) lately += gross[i];
    EXPECT_EQ(f.lately_unlocked(), lately);
    EXPECT_GT(lately, 0);
    EXPECT_EQ(f.current_limit(),
              std::optional<int64_t>(cp_unlock_limit_v24(kTnCreditPool[L].balance,
                                                         kTnCreditPool[L - 576].balance)));
}

namespace {
// A synthetic chain for the lane: height -> hash, with a switchable branch.
struct LaneChain {
    std::map<uint32_t, uint256> hash;
    uint32_t tip{0};
    BlockType body(uint32_t h) const {
        return make_block(hash.at(h - 1), {make_cbtx_coinbase(h, 0)});
    }
};
dash::coin::CreditPoolLane make_lane(LaneChain& c, uint32_t live_floor,
                                     std::vector<uint256>& asked,
                                     dash::coin::CreditPoolLane::BodyCheckFn check) {
    dash::coin::CreditPoolLane::Seams s;
    s.hash_at = [&c](uint32_t h) -> std::optional<uint256> {
        auto it = c.hash.find(h);
        if (it == c.hash.end() || h > c.tip) return std::nullopt;
        return it->second;
    };
    s.tip = [&c]() -> std::optional<uint32_t> { return c.tip; };
    s.live_floor = [live_floor]() -> std::optional<uint32_t> { return live_floor; };
    s.request = [&asked](const std::vector<uint256>& hs) {
        asked.insert(asked.end(), hs.begin(), hs.end());
        return true;
    };
    s.check = std::move(check);
    return dash::coin::CreditPoolLane(CpIdxDeploySchedule{1000, 0u, kCpIdxNeverActive, 576u},
                                      dash::coin::DASH_MN_RR_HEIGHT_MAINNET, std::move(s),
                                      dash::coin::CreditPoolLane::SeedMode::FULL);
}
}  // namespace

// Seed below the live floor, follow the tip, complete at the header tip,
// rewind a tip reorg, re-arm on a reorg below the journal.
TEST(DashCreditPoolLane, SeedsFollowsCompletesAndRewinds) {
    LaneChain c;
    for (uint32_t h = 999; h <= 1100; ++h) c.hash[h] = chain_hash(h);
    c.tip = 1060;
    std::vector<uint256> asked;
    auto accept = [](const uint256&, const BlockType&) { return true; };
    auto lane = make_lane(c, /*live_floor=*/1050, asked, accept);
    lane.start(nullptr);
    EXPECT_EQ(lane.tick(0), 49u) << "arms at the floor and asks 1001..1049";
    ASSERT_TRUE(lane.status().armed);
    EXPECT_EQ(asked.front(), c.hash[1001]);
    // Seed bodies arrive out of order; they apply contiguously.
    for (uint32_t h = 1049; h >= 1001; --h) EXPECT_TRUE(lane.on_body(c.hash[h], c.body(h)));
    EXPECT_EQ(lane.status().height, 1049u);
    EXPECT_FALSE(lane.status().proven_complete) << "below the header tip";
    EXPECT_FALSE(lane.on_body(c.hash[1055], c.body(1055))) << "never asked for";
    // The tip lane continues contiguously.
    for (uint32_t h = 1050; h <= 1060; ++h) lane.on_ordered_block(h, c.hash[h], c.body(h));
    EXPECT_EQ(lane.status().height, 1060u);
    EXPECT_TRUE(lane.status().proven_complete) << "cursor met the header tip";
    lane.tick(1000);
    EXPECT_TRUE(lane.status().proven_complete);
    // A tip reorg of two blocks: rewind to 1058 and apply the new branch.
    c.hash[1059] = raw256(0x59);
    c.hash[1060] = raw256(0x60);
    lane.on_ordered_block(1059, c.hash[1059], c.body(1059));
    lane.on_ordered_block(1060, c.hash[1060], c.body(1060));
    auto st = lane.status();
    EXPECT_EQ(st.height, 1060u);
    EXPECT_EQ(st.rewinds, 1u);
    EXPECT_EQ(st.failures, 0u);
    EXPECT_TRUE(st.proven_complete);
    EXPECT_EQ(lane.with_follower([](const CreditPoolIdxFollower& f) { return f.block_hash(); }),
              c.hash[1060]);
    // A replayed body of the active chain is ignored, at the cursor and
    // well below the journal (the payee replay re-delivers old bodies).
    lane.on_ordered_block(1060, c.hash[1060], c.body(1060));
    lane.on_ordered_block(1005, c.hash[1005], c.body(1005));
    EXPECT_EQ(lane.status().applied, 49u + 11u + 2u);
    EXPECT_EQ(lane.status().height, 1060u) << "not re-armed by an old active-chain body";
    EXPECT_TRUE(lane.status().proven_complete);
    // A reorg below the journal: re-armed at the floor.
    for (uint32_t h = 1001; h <= 1100; ++h) c.hash[h] = raw256(static_cast<uint8_t>(h)) ;
    c.hash[1010] = chain_hash(5010);
    c.hash[1009] = chain_hash(5009);
    lane.on_ordered_block(1010, c.hash[1010], make_block(c.hash[1009], {make_cbtx_coinbase(1010, 0)}));
    st = lane.status();
    EXPECT_TRUE(st.armed);
    EXPECT_EQ(st.height, 1000u) << "re-armed at the v20 floor";
    EXPECT_FALSE(st.proven_complete);
}

// Seed bodies that do not bind are dropped and re-asked at once; a follower
// that fails closed is re-armed only after the back-off.
TEST(DashCreditPoolLane, UnboundBodiesAndFailClosed) {
    LaneChain c;
    for (uint32_t h = 999; h <= 1100; ++h) c.hash[h] = chain_hash(h);
    c.tip = 1100;
    std::vector<uint256> asked;
    const uint256 bad = chain_hash(1003);
    auto check = [bad](const uint256& want, const BlockType&) { return want != bad; };
    auto lane = make_lane(c, 1010, asked, check);
    lane.start(nullptr);
    lane.tick(0);
    EXPECT_TRUE(lane.on_body(c.hash[1003], c.body(1003)));
    EXPECT_EQ(lane.status().rejected_bodies, 1u);
    for (uint32_t h = 1001; h <= 1009; ++h) lane.on_body(c.hash[h], c.body(h));
    EXPECT_EQ(lane.status().height, 1002u) << "stops below the refused body";
    // A body whose committed balance is wrong: the follower fails closed.
    auto lane2 = make_lane(c, 1010, asked, [](const uint256&, const BlockType&) { return true; });
    lane2.start(nullptr);
    lane2.tick(0);
    EXPECT_TRUE(lane2.on_body(c.hash[1001],
                              make_block(c.hash[1000], {make_cbtx_coinbase(1001, 777)})));
    auto st = lane2.status();
    EXPECT_FALSE(st.armed);
    EXPECT_EQ(st.failures, 1u);
    EXPECT_NE(st.fail_cause.find("cross-check"), std::string::npos) << st.fail_cause;
    EXPECT_EQ(lane2.tick(1000), 0u) << "back-off: not re-armed yet";
    EXPECT_FALSE(lane2.status().armed);
    lane2.tick(1000 + dash::coin::CreditPoolLane::kRearmBackoffMs);
    EXPECT_TRUE(lane2.status().armed) << "re-armed after the back-off";
}

#ifdef C2POOL_DASH_BLS
// Admission runs only through a complete, fresh follower.
TEST(DashCreditPoolLane, AdmitNeedsACompleteFreshFollower) {
    LaneChain c;
    for (uint32_t h = 999; h <= 1100; ++h) c.hash[h] = chain_hash(h);
    c.tip = 1020;
    std::vector<uint256> asked;
    auto lane = make_lane(c, 1021, asked, [](const uint256&, const BlockType&) { return true; });
    lane.start(nullptr);
    lane.tick(0);
    EXPECT_FALSE(lane.admit(true, 1011, c.hash[1010], {}, {}, kLlmq100_67).has_value())
        << "not seeded";
    for (uint32_t h = 1001; h <= 1020; ++h) lane.on_body(c.hash[h], c.body(h));
    lane.tick(1);
    ASSERT_TRUE(lane.status().proven_complete);
    EXPECT_TRUE(lane.admit(true, 1021, c.hash[1020], {}, {}, kLlmq100_67).has_value());
    EXPECT_FALSE(lane.admit(true, 1022, c.hash[1020], {}, {}, kLlmq100_67).has_value())
        << "not fresh at the template's parent";
    EXPECT_FALSE(lane.admit(false, 1021, c.hash[1020], {}, {}, kLlmq100_67).has_value())
        << "flag off";
}
#endif  // C2POOL_DASH_BLS

// The default WINDOW seed: armed from a recent block's own CbTx balance, it
// tracks the balance, latelyUnlocked and the window-start balance exactly
// (Dash Core v24 UnlockLimitV24), but never admits an unlock: Dash Core
// refuses a duplicate unlock index against every unlock since v20, which only
// a full seed from the v20 floor knows.
TEST(DashCreditPoolLane, WindowSeedTracksTheLimitButNeverAdmits) {
    LaneChain c;
    for (uint32_t h = 999; h <= 2100; ++h) c.hash[h] = chain_hash(h);
    c.tip = 2000;
    const int64_t B = 9'000 * COIN_SAT;
    const int64_t G = 10 * COIN_SAT + 190;            // the unlock at 1500, gross
    auto balance_at = [&](uint32_t h) { return h >= 1500 ? B - G : B; };
    auto body = [&](uint32_t h) {
        std::vector<MutableTransaction> txs{make_cbtx_coinbase(h, balance_at(h))};
        if (h == 1500) txs.push_back(make_unlock_tx(5, 190, 10 * COIN_SAT, 1499, raw256(0x77)));
        return make_block(c.hash.at(h - 1), std::move(txs));
    };
    std::vector<uint256> asked;
    dash::coin::CreditPoolLane::Seams s;
    s.hash_at = [&c](uint32_t h) -> std::optional<uint256> {
        if (h > c.tip || !c.hash.count(h)) return std::nullopt;
        return c.hash.at(h);
    };
    s.tip = [&c]() -> std::optional<uint32_t> { return c.tip; };
    s.live_floor = []() -> std::optional<uint32_t> { return 1990u; };
    s.request = [&asked](const std::vector<uint256>& hs) {
        asked.insert(asked.end(), hs.begin(), hs.end());
        return true;
    };
    s.check = [](const uint256&, const BlockType&) { return true; };
    dash::coin::CreditPoolLane lane(CpIdxDeploySchedule{1000, 0u, /*v24=*/1100u, 576u},
                                    dash::coin::DASH_MN_RR_HEIGHT_MAINNET, std::move(s),
                                    dash::coin::CreditPoolLane::SeedMode::WINDOW);
    lane.start(nullptr);
    EXPECT_EQ(lane.tick(0), 0u);
    ASSERT_EQ(asked.size(), 1u) << "asks for the window floor block only";
    const uint32_t floor = 1990 - 576 - 8;
    EXPECT_EQ(asked[0], c.hash[floor]);
    EXPECT_FALSE(lane.status().armed);
    // The floor body arms it with its own committed balance.
    EXPECT_TRUE(lane.on_body(c.hash[floor], body(floor)));
    auto st = lane.status();
    ASSERT_TRUE(st.armed);
    EXPECT_FALSE(st.full_history);
    EXPECT_EQ(st.height, floor);
    EXPECT_EQ(st.balance, B);
    // Seed up to the live floor, then the tip lane.
    for (int round = 0; round < 40 && lane.status().height < 1989; ++round) {
        const uint32_t from = lane.status().height + 1;
        for (uint32_t h = from; h < from + 64 && h < 1990; ++h) lane.on_body(c.hash[h], body(h));
        lane.tick(1000 + round);
    }
    ASSERT_EQ(lane.status().height, 1989u);
    for (uint32_t h = 1990; h <= 2000; ++h) lane.on_ordered_block(h, c.hash[h], body(h));
    st = lane.status();
    EXPECT_EQ(st.height, 2000u);
    EXPECT_TRUE(st.proven_complete);
    EXPECT_EQ(st.balance, B - G);
    EXPECT_EQ(st.lately_unlocked, G) << "1500 is inside (1424, 2000]";
    EXPECT_EQ(st.window_start_balance, std::optional<int64_t>(B)) << "the balance at 1424";
    EXPECT_EQ(st.limit, std::optional<int64_t>(cp_unlock_limit_v24(B - G, B)));
    // Complete and fresh, but a window seed never admits.
    EXPECT_FALSE(lane.admit(true, 2001, c.hash[2000], {}, {}, kLlmq100_67).has_value());
}

// The coordinator's opt-in conditions, pinned:
//  (a) an unseeded (or window-seeded) follower admits nothing, so a template
//      excludes every type-9 unlock in the pool: only their fees are lost;
//  (b) the CbTx v4 creditPoolBalance and merkleRootAssetUnlocks do not depend
//      on the follower at all: with no admission the template is
//      byte-identical to one built with no follower, and the balance is the
//      tip balance + this block's platform reward (+ selected locks).
TEST(DashCreditPoolLane, UnseededFollowerLeavesTheTemplateUnchanged) {
    GbtFixture gbt;
    // A version-2 and a version-1 unlock wait in the pool.
    auto u2 = make_unlock_tx(31, 400, 3 * COIN_SAT, H - 2, raw256(0x77), {}, 2);
    auto u1 = make_unlock_tx(32, 300, 2 * COIN_SAT, H - 2, raw256(0x77));
    ASSERT_TRUE(gbt.mp.add_tx(u2));
    ASSERT_TRUE(gbt.mp.add_tx(u1));
    ASSERT_EQ(gbt.mp.asset_unlock_candidates().size(), 2u);
    const int64_t POOL = 5'000 * COIN_SAT;
    auto build = [&](const AssetUnlockAdmission* adm) {
        return build_embedded_workdata(
            H - 1, gbt.prev_hash, gbt.mnstates, gbt.mp, 0x1b104be3u, 1'700'000'000u,
            DASH_PUBKEY_VER, DASH_P2SH_VER, 1'700'000'123u, 0x20000000u, nullptr,
            &gbt.sml, &gbt.qmgr, 0, dash::coin::k_zero_cl_sig, POOL, nullptr, nullptr,
            dash::coin::DASH_MN_RR_HEIGHT_MAINNET, nullptr,
            dash::coin::DASH_MN_MIN_CONFIRMATIONS_MAINNET, false, "utxo-immature-serving",
            nullptr, /*accrue_pending_asset_locks=*/false, adm,
            /*include_mn_special_txs=*/false, nullptr, nullptr, nullptr, /*v24_active=*/true);
    };
    const auto none = build(nullptr);
    // Unseeded lanes, window and full: admission refuses (fail closed).
    for (auto mode : {dash::coin::CreditPoolLane::SeedMode::WINDOW,
                      dash::coin::CreditPoolLane::SeedMode::FULL}) {
        dash::coin::CreditPoolLane lane(test_schedule(H - 6), dash::coin::DASH_MN_RR_HEIGHT_MAINNET,
                                        dash::coin::CreditPoolLane::Seams{}, mode);
        lane.start(nullptr);
        const auto adm = lane.admit(true, H, gbt.prev_hash, gbt.mp.asset_unlock_candidates(), {},
                                    kLlmq100_67);
        EXPECT_FALSE(adm.has_value());
        const auto w = build(adm ? &*adm : nullptr);
        expect_workdata_identical(none, w);
    }
    for (const auto& t : none.m_txs) EXPECT_NE(t.type, 9) << "no unlock rides";
    CCbTx cb;
    ASSERT_TRUE(parse_cbtx(none.m_coinbase_payload, cb));
    EXPECT_EQ(cb.nVersion, 4);
    EXPECT_EQ(cb.merkleRootAssetUnlocks, uint256::ZERO);
    EXPECT_EQ(cb.creditPoolBalance,
              POOL + dash::coin::compute_dash_platform_reward_post_v20_mn_rr(H));
}
