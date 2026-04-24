/// Phase C-TEMPLATE step 13 — DIP-0027 CreditPool unit tests
///
/// Validates the per-block balance accounting math against the
/// dashcore evo/creditpool.cpp::DiffFromBlock semantics:
///   For each tx in the block (excluding coinbase):
///     - Type 8 (TRANSACTION_ASSET_LOCK):
///         pool += sum(payload.creditOutputs.value)
///     - Type 9 (TRANSACTION_ASSET_UNLOCK):
///         pool -= sum(tx.vout.value)
///
/// Tests cover:
///   1. Uninitialized pool refuses apply_block (nullopt return)
///   2. seed() initializes balance + height
///   3. apply_block on a no-activity block yields delta=0
///   4. apply_block with a single asset-lock adds correct amount
///   5. apply_block with a single asset-unlock subtracts gross vout sum
///   6. apply_block with multiple locks AND unlocks nets correctly
///   7. Coinbase (tx[0]) is skipped — its type may be 5 (CCbTx) but we
///      do NOT count it toward asset-lock accounting
///   8. clear() resets to uninitialized

#include <gtest/gtest.h>

#include <impl/dash/coin/credit_pool.hpp>
#include <impl/dash/coin/vendor/assetlock.hpp>
#include <impl/dash/coin/transaction.hpp>
#include <impl/dash/coin/block.hpp>
#include <core/pack.hpp>

using namespace dash::coin;

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Build a minimal coinbase tx with type=5 (CCbTx). Required as tx[0]
/// in every Dash block; CreditPool must skip it.
static MutableTransaction make_coinbase()
{
    MutableTransaction cb;
    cb.version = 3;
    cb.type    = 5;            // CCbTx
    // Single null-prevout input (coinbase convention).
    TxIn vin;
    vin.prevout.hash = uint256{};
    vin.prevout.index = 0xFFFFFFFF;
    vin.sequence     = 0xFFFFFFFF;
    cb.vin.push_back(vin);
    // Single trivial output (block reward placeholder).
    TxOut vout;
    vout.value = 5'00000000;     // 5 DASH
    cb.vout.push_back(vout);
    cb.locktime = 0;
    cb.extra_payload.clear();
    return cb;
}

/// Build an asset-lock tx (special tx type 8) with the given credit
/// amounts. The credit outputs go in extra_payload; tx.vout is OP_RETURN
/// markers (we use empty for simplicity — the math only looks at the
/// payload's creditOutputs).
static MutableTransaction make_asset_lock(std::vector<int64_t> credit_amounts)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type    = vendor::CAssetLockPayload::SPECIALTX_TYPE;
    tx.locktime = 0;

    vendor::CAssetLockPayload payload;
    payload.nVersion = vendor::CAssetLockPayload::CURRENT_VERSION;
    for (auto amt : credit_amounts) {
        TxOut o;
        o.value = amt;
        payload.creditOutputs.push_back(o);
    }
    auto stream = ::pack(payload);
    auto sp = stream.get_span();
    tx.extra_payload.assign(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

/// Build an asset-unlock tx (special tx type 9). The unlock amount is
/// the sum of tx.vout values. The payload BLS sig is left zeroed (we
/// don't verify here, only count).
static MutableTransaction make_asset_unlock(std::vector<int64_t> vout_amounts)
{
    MutableTransaction tx;
    tx.version = 3;
    tx.type    = vendor::CAssetUnlockPayload::SPECIALTX_TYPE;
    tx.locktime = 0;

    for (auto amt : vout_amounts) {
        TxOut o;
        o.value = amt;
        tx.vout.push_back(o);
    }

    vendor::CAssetUnlockPayload payload;
    payload.nVersion        = vendor::CAssetUnlockPayload::CURRENT_VERSION;
    payload.index           = 42;
    payload.fee             = 1000;
    payload.requestedHeight = 100;
    payload.quorumHash      = uint256{};
    payload.quorumSig       = {};
    auto stream = ::pack(payload);
    auto sp = stream.get_span();
    tx.extra_payload.assign(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    return tx;
}

/// Build a block with the given non-coinbase txs prepended by a CCbTx.
static BlockType make_block(std::vector<MutableTransaction> non_cb)
{
    BlockType b;
    // Header fields left default — CreditPool doesn't read them.
    b.m_txs.push_back(make_coinbase());
    for (auto& tx : non_cb) b.m_txs.push_back(std::move(tx));
    return b;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

TEST(DashCreditPool, UninitializedRefusesApplyBlock)
{
    CreditPool pool;
    ASSERT_FALSE(pool.initialized());
    auto b = make_block({});
    auto delta = pool.apply_block(b, 100);
    EXPECT_FALSE(delta.has_value());
    EXPECT_EQ(pool.balance(), 0);
}

TEST(DashCreditPool, SeedInitializes)
{
    CreditPool pool;
    pool.seed(1'000'00000000LL, 2'000'000);   // 1000 DASH at h=2M
    EXPECT_TRUE(pool.initialized());
    EXPECT_EQ(pool.balance(), 1'000'00000000LL);
    EXPECT_EQ(pool.height(), 2'000'000u);
}

TEST(DashCreditPool, NoActivityYieldsZeroDelta)
{
    CreditPool pool;
    pool.seed(500'00000000LL, 100);
    auto b = make_block({});                 // coinbase only, no activity
    auto delta = pool.apply_block(b, 101);
    ASSERT_TRUE(delta.has_value());
    EXPECT_EQ(*delta, 0);
    EXPECT_EQ(pool.balance(), 500'00000000LL);
    EXPECT_EQ(pool.height(), 101u);
}

TEST(DashCreditPool, AssetLockAddsToPool)
{
    CreditPool pool;
    pool.seed(1'000'00000000LL, 100);
    // Lock 10 DASH + 5 DASH = 15 DASH = 15e8 sat
    auto lock_tx = make_asset_lock({10'00000000LL, 5'00000000LL});
    auto b = make_block({lock_tx});
    auto delta = pool.apply_block(b, 101);
    ASSERT_TRUE(delta.has_value());
    EXPECT_EQ(*delta, 15'00000000LL);
    EXPECT_EQ(pool.balance(), 1'015'00000000LL);
}

TEST(DashCreditPool, AssetUnlockSubtractsGrossVoutSum)
{
    CreditPool pool;
    pool.seed(1'000'00000000LL, 100);
    // Unlock 7 DASH + 3 DASH = 10 DASH gross
    auto unlock_tx = make_asset_unlock({7'00000000LL, 3'00000000LL});
    auto b = make_block({unlock_tx});
    auto delta = pool.apply_block(b, 101);
    ASSERT_TRUE(delta.has_value());
    EXPECT_EQ(*delta, -10'00000000LL);
    EXPECT_EQ(pool.balance(), 990'00000000LL);
}

TEST(DashCreditPool, MultipleLockAndUnlockNetsCorrectly)
{
    CreditPool pool;
    pool.seed(1'000'00000000LL, 100);
    auto lock_a   = make_asset_lock({20'00000000LL});         // +20
    auto unlock_x = make_asset_unlock({5'00000000LL});        // -5
    auto lock_b   = make_asset_lock({1'00000000LL, 2'00000000LL});   // +3
    auto unlock_y = make_asset_unlock({4'00000000LL, 4'00000000LL}); // -8
    auto b = make_block({lock_a, unlock_x, lock_b, unlock_y});
    // Net: +20 -5 +3 -8 = +10
    auto delta = pool.apply_block(b, 101);
    ASSERT_TRUE(delta.has_value());
    EXPECT_EQ(*delta, 10'00000000LL);
    EXPECT_EQ(pool.balance(), 1'010'00000000LL);
}

TEST(DashCreditPool, CoinbaseSkipped)
{
    // Test that the cb tx (which has type=5 / CCbTx, not type 8 or 9)
    // is correctly skipped. We don't currently produce a coinbase that
    // looks like an asset-lock, but if a future change accidentally
    // mis-classifies the cb, this test will catch it.
    CreditPool pool;
    pool.seed(0, 100);
    auto b = make_block({});                 // just the coinbase
    auto delta = pool.apply_block(b, 101);
    ASSERT_TRUE(delta.has_value());
    EXPECT_EQ(*delta, 0)
        << "cb is type=5 not type=8/9, must not contribute to credit pool";
}

TEST(DashCreditPool, ClearResetsToUninitialized)
{
    CreditPool pool;
    pool.seed(123, 456);
    EXPECT_TRUE(pool.initialized());
    pool.clear();
    EXPECT_FALSE(pool.initialized());
    EXPECT_EQ(pool.balance(), 0);
    EXPECT_EQ(pool.height(), 0u);
}

TEST(DashCreditPool, RoundTripPayloadSerialization)
{
    // Sanity: pack(CAssetLockPayload).unpack() round-trips. This is what
    // parse_assetlock_payload does on the wire.
    vendor::CAssetLockPayload original;
    original.nVersion = 1;
    TxOut o1; o1.value = 12345;
    TxOut o2; o2.value = 67890;
    original.creditOutputs = {o1, o2};
    auto stream = ::pack(original);
    auto sp = stream.get_span();
    std::vector<unsigned char> bytes(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());

    vendor::CAssetLockPayload decoded;
    ASSERT_TRUE(vendor::parse_assetlock_payload(bytes, decoded));
    EXPECT_EQ(decoded.nVersion, original.nVersion);
    ASSERT_EQ(decoded.creditOutputs.size(), original.creditOutputs.size());
    EXPECT_EQ(decoded.creditOutputs[0].value, 12345);
    EXPECT_EQ(decoded.creditOutputs[1].value, 67890);
    EXPECT_EQ(decoded.total_credit(), 12345 + 67890);
}

TEST(DashCreditPool, RejectsTrailingGarbage)
{
    // Strict-tail policy: anything past the payload is rejected.
    vendor::CAssetLockPayload original;
    original.nVersion = 1;
    TxOut o1; o1.value = 100;
    original.creditOutputs = {o1};
    auto stream = ::pack(original);
    auto sp = stream.get_span();
    std::vector<unsigned char> bytes(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());
    bytes.push_back(0xFF);   // trailing garbage byte
    bytes.push_back(0xFE);

    vendor::CAssetLockPayload decoded;
    EXPECT_FALSE(vendor::parse_assetlock_payload(bytes, decoded))
        << "strict-tail policy must reject extra bytes";
}
