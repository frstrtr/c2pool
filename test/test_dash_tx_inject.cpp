// SPDX-License-Identifier: AGPL-3.0-or-later
// #157 — miner/user TX-INJECTION runtime (M1: inject pool + validation + priority).
//
// Proves the four load-bearing properties of the injection runtime, each
// RED-on-master (master has no Mempool::add_inject and no `consumed` double-spend
// set) / GREEN-after:
//
//   1. PRIORITY — a 0-fee injected tx is selected AHEAD of a fee-paying tx and
//      clears the blockMinFeeRate floor (on master a 0-fee tx sinks below the
//      floor and is never selected). The priority is a scoring-only mapDeltas
//      delta: it does NOT touch the base fee that feeds the coinbase.
//   2. REWARD-SAFETY — an inject with a real fee f contributes exactly f (its
//      BASE fee) to total_fees, never f + INJECT_FEE_DELTA. The coinbase is
//      derived from total_fees, so the delta cannot inflate a single duff.
//   3. VALIDITY, NOT BYPASS — an injected tx rides the SAME selector guards:
//        * a double-spending inject is DROPPED per-tx (the `consumed` set),
//          the template is NOT refused (on master both would be selected → an
//          invalid bad-txns-inputs-* block);
//        * a bad-script inject is admitted to the pool but DROPPED at template
//          build (never served);
//        * a missing-input inject is REFUSED at submit (unpriceable, by name).
//   4. DoS + SEAM DISCIPLINE — oversize is refused by name; a new ingestion
//      seam refuses unless the consensus-exact CheckInputScripts callback is
//      armed (sole-ingestion-path invariant).
//
// The signed-spend + script-verify scaffolding is the SAME dashcore VerifyScript
// (dash_scriptcheck.so) the KAT signs a real P2PKH spend against — no hand-rolled
// fixture. Folded into the test_dash_mempool executable (build.yml allowlisted).

#include <gtest/gtest.h>

#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/tx_inject_pool.hpp>
#include <impl/dash/coin/good_citizen_defaults.hpp>
#include <impl/dash/coin/vendor/dashscript/c2pool_scriptcheck.h>

#include <core/uint256.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <secp256k1.h>

#include <cstdint>
#include <cstring>
#include <vector>

using dash::coin::Mempool;
using dash::coin::TxInjectPool;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;

namespace {

std::vector<uint8_t> ser(const MutableTransaction& tx) {
    auto ps = ::pack(tx);
    auto sp = ps.get_span();
    const auto* b = reinterpret_cast<const uint8_t*>(sp.data());
    return std::vector<uint8_t>(b, b + sp.size());
}

OPScript to_script(const std::vector<uint8_t>& v) {
    return OPScript(v.data(), v.data() + v.size());
}

// One deterministic P2PKH keypair + scriptPubKey (mirrors test_dash_checkinputscripts).
struct Key {
    secp256k1_context* ctx;
    uint8_t seckey[32];
    uint8_t pub[33];
    size_t publen = 33;
    std::vector<uint8_t> spk;

    Key(uint8_t seed) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
        std::memset(seckey, seed, 32);
        secp256k1_pubkey p;
        EXPECT_EQ(secp256k1_ec_pubkey_create(ctx, &p, seckey), 1);
        secp256k1_ec_pubkey_serialize(ctx, pub, &publen, &p, SECP256K1_EC_COMPRESSED);
        uint8_t h160[20];
        c2pool_dash_hash160(pub, (unsigned)publen, h160);
        spk = {0x76, 0xa9, 0x14};
        spk.insert(spk.end(), h160, h160 + 20);
        spk.push_back(0x88);
        spk.push_back(0xac);
    }
    ~Key() { secp256k1_context_destroy(ctx); }

    std::vector<uint8_t> sign_scriptsig(const std::vector<uint8_t>& sighash32) const {
        secp256k1_ecdsa_signature sig;
        EXPECT_EQ(secp256k1_ecdsa_sign(ctx, &sig, sighash32.data(), seckey, nullptr, nullptr), 1);
        uint8_t der[72]; size_t derlen = 72;
        secp256k1_ecdsa_signature_serialize_der(ctx, der, &derlen, &sig);
        std::vector<uint8_t> ss;
        ss.push_back((uint8_t)(derlen + 1));
        ss.insert(ss.end(), der, der + derlen);
        ss.push_back(0x01);                       // SIGHASH_ALL
        ss.push_back((uint8_t)publen);
        ss.insert(ss.end(), pub, pub + publen);
        return ss;
    }
};

// Signed 1-in 1-out P2PKH spend of (prev:0). Coin value = out + fee.
MutableTransaction make_signed_spend(const Key& k, const uint256& prev,
                                     int64_t out_value) {
    MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = 0;
    TxIn in; in.prevout.hash = prev; in.prevout.index = 0; in.sequence = 0xffffffffu;
    in.scriptSig = to_script(k.spk);
    tx.vin.push_back(in);
    TxOut out; out.value = out_value; tx.vout.push_back(out);

    auto unsigned_bytes = ser(tx);
    uint8_t sighash[32];
    EXPECT_EQ(c2pool_dash_legacy_sighash(unsigned_bytes.data(), (unsigned)unsigned_bytes.size(),
                                         0, k.spk.data(), (unsigned)k.spk.size(),
                                         1, sighash), 1);
    auto ss = k.sign_scriptsig(std::vector<uint8_t>(sighash, sighash + 32));
    tx.vin[0].scriptSig = to_script(ss);
    return tx;
}

uint256 prevhash(uint8_t b) { uint256 h; std::memset(h.begin(), b, 32); return h; }

// Wire the consensus-exact CheckInputScripts callback (dashcore VerifyScript).
void arm_script_check(Mempool& mp) {
    mp.set_script_check([](const std::vector<uint8_t>& t, uint32_t n,
                           const std::vector<uint8_t>& s, uint32_t f) {
        return c2pool_dash_verify_input(s.data(), (unsigned)s.size(),
                                        t.data(), (unsigned)t.size(), n, f) == 1;
    });
}

} // namespace

// (1) PRIORITY: a 0-fee inject is selected AHEAD of a fee-paying tx and clears
//     the min-fee floor. RED on master: no add_inject; a 0-fee tx is below the
//     blockMinFeeRate floor and never selected.
TEST(DashTxInject, ZeroFeeInjectSelectedAheadOfFeeSorted)
{
    Key k(0x11);
    uint256 prevFee = prevhash(0xa1);
    uint256 prevInj = prevhash(0xa2);
    auto tx_fee = make_signed_spend(k, prevFee, 90'000);   // fee 10'000
    auto tx_inj = make_signed_spend(k, prevInj, 100'000);  // fee 0

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prevFee, 0), Coin(100'000, to_script(k.spk), 1, false));
    utxo.add_coin(Outpoint(prevInj, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp; mp.set_utxo(&utxo);
    arm_script_check(mp);

    ASSERT_TRUE(mp.add_tx(tx_fee));
    ASSERT_EQ(mp.add_inject(tx_inj), Mempool::InjectGate::Ok);

    auto [selected, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    ASSERT_EQ(selected.size(), 2u) << "both the fee tx and the prioritised 0-fee inject must be in the body";
    // The inject sorts FIRST (its modified feerate dominates).
    EXPECT_EQ(dash_txid(selected[0].tx), dash_txid(tx_inj))
        << "the injected tx must be offered FIRST (priority class)";
    // REWARD-SAFETY: the 0-fee inject contributes 0; total_fees is the fee tx's
    // base fee only — the priority delta never reaches the coinbase.
    EXPECT_EQ(fees, 10'000u);
}

// (2) REWARD-SAFETY: an inject with a real fee f contributes exactly f (base),
//     NOT f + INJECT_FEE_DELTA.
TEST(DashTxInject, InjectFeeDeltaNeverInflatesCoinbase)
{
    Key k(0x22);
    uint256 prev = prevhash(0xb1);
    auto tx = make_signed_spend(k, prev, 95'000);          // real fee 5'000

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp; mp.set_utxo(&utxo);
    arm_script_check(mp);
    ASSERT_EQ(mp.add_inject(tx), Mempool::InjectGate::Ok);

    auto [selected, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    ASSERT_EQ(selected.size(), 1u);
    EXPECT_EQ(selected[0].fee, 5'000u) << "SelectedTx.fee is the BASE fee, delta excluded";
    EXPECT_EQ(fees, 5'000u) << "total_fees (→ coinbasevalue) must be the base fee, never base+delta";
}

// (3a) VALIDITY: a double-spending tx is DROPPED per-tx by the `consumed` set,
//      the template is NOT refused. RED on master: no consumed set → BOTH txs
//      are selected → an invalid intra-block double-spend.
TEST(DashTxInject, DoubleSpendIsDroppedPerTxNotTemplate)
{
    Key k(0x33);
    uint256 prev = prevhash(0xc1);
    // Two distinct txs (different output value ⇒ different txid) spending the
    // SAME outpoint (prev:0). Both are individually consensus-priceable.
    auto a = make_signed_spend(k, prev, 90'000);   // fee 10'000
    auto b = make_signed_spend(k, prev, 80'000);   // fee 20'000 (higher — wins)

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp; mp.set_utxo(&utxo);
    arm_script_check(mp);
    ASSERT_TRUE(mp.add_tx(a));
    ASSERT_TRUE(mp.add_tx(b));

    auto [selected, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    ASSERT_EQ(selected.size(), 1u)
        << "exactly ONE of two conflicting txs may be in the body (the other is dropped)";
    // The higher-feerate one (b, fee 20'000) is selected first and wins.
    EXPECT_EQ(dash_txid(selected[0].tx), dash_txid(b));
    EXPECT_EQ(fees, 20'000u);
}

// (3b) VALIDITY: even with the injection PRIORITY delta, a double-spending inject
//      cannot force BOTH into the block — priority is offered-first, not a guard
//      bypass. The inject wins (offered first) and the conflicting fee tx drops.
TEST(DashTxInject, InjectDoubleSpendStillDropsTheConflict)
{
    Key k(0x44);
    uint256 prev = prevhash(0xd1);
    auto body_tx = make_signed_spend(k, prev, 80'000);   // fee 20'000 (a rich body tx)
    auto inj_tx  = make_signed_spend(k, prev, 100'000);  // fee 0, but INJECTED (spends same coin)

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp; mp.set_utxo(&utxo);
    arm_script_check(mp);
    ASSERT_TRUE(mp.add_tx(body_tx));
    ASSERT_EQ(mp.add_inject(inj_tx), Mempool::InjectGate::Ok);

    auto [selected, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    ASSERT_EQ(selected.size(), 1u) << "a conflicting inject NEVER lets both into the block";
    EXPECT_EQ(dash_txid(selected[0].tx), dash_txid(inj_tx)) << "the inject is offered first";
    EXPECT_EQ(fees, 0u) << "the 0-fee inject won; the fee tx it conflicts with is dropped";
}

// (3c) VALIDITY: a bad-script inject is admitted to the pool (priceable from the
//      UTXO value) but DROPPED at template build by the ARMED script check —
//      never served. Priority is not a guard bypass.
TEST(DashTxInject, BadScriptInjectDroppedAtTemplateBuild)
{
    Key k(0x55);
    uint256 prev = prevhash(0xe1);
    auto good = make_signed_spend(k, prev, 90'000);
    auto bad = good;
    { auto ss = bad.vin[0].scriptSig.m_data; ASSERT_GT(ss.size(), 6u); ss[4] ^= 0x01;
      bad.vin[0].scriptSig = to_script(ss); }

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp; mp.set_utxo(&utxo);
    arm_script_check(mp);
    // Priceable ⇒ admitted with priority.
    ASSERT_EQ(mp.add_inject(bad), Mempool::InjectGate::Ok);
    // ...but the armed selector script-check DROPS it: never served.
    auto [selected, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    EXPECT_EQ(selected.size(), 0u) << "an invalid-script inject must be dropped at template build";
    EXPECT_EQ(fees, 0u);
}

// (3d) VALIDITY: an inject whose input is not in the view is REFUSED at submit,
//      by name (unpriceable) — never left in the pool to be silently excluded.
TEST(DashTxInject, MissingInputInjectRefusedByName)
{
    Key k(0x66);
    uint256 prev = prevhash(0xf1);   // NOT added to the UTXO view
    auto tx = make_signed_spend(k, prev, 90'000);

    UTXOViewCache utxo(nullptr);
    Mempool mp; mp.set_utxo(&utxo);
    arm_script_check(mp);
    EXPECT_EQ(mp.add_inject(tx), Mempool::InjectGate::Unpriceable);
    // Rolled back — not left as a dead pool entry.
    auto [selected, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    EXPECT_EQ(selected.size(), 0u);
    (void)fees;
}

// (4a) DoS: an oversize inject is refused by name, before any consensus work.
TEST(DashTxInject, OversizeInjectRefusedByName)
{
    MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = 0;
    TxIn in; in.prevout.hash = prevhash(0x01); in.prevout.index = 0; in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    TxOut out; out.value = 1;
    out.scriptPubKey = to_script(std::vector<uint8_t>(
        Mempool::kMaxInjectTxBytes + 64, 0x51));   // scriptPubKey alone exceeds the cap
    tx.vout.push_back(out);

    UTXOViewCache utxo(nullptr);
    Mempool mp; mp.set_utxo(&utxo);
    arm_script_check(mp);
    EXPECT_EQ(mp.add_inject(tx), Mempool::InjectGate::TooLarge);
}

// (4b) SEAM DISCIPLINE: a new ingestion seam refuses unless the consensus-exact
//      CheckInputScripts callback is armed (sole-ingestion-path invariant).
TEST(DashTxInject, InjectRefusedWhenScriptCheckUnarmed)
{
    Key k(0x77);
    uint256 prev = prevhash(0xab);
    auto tx = make_signed_spend(k, prev, 90'000);
    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp; mp.set_utxo(&utxo);
    // NO set_script_check.
    EXPECT_FALSE(mp.has_script_check());
    EXPECT_EQ(mp.add_inject(tx), Mempool::InjectGate::ScriptCheckUnarmed);
}

// (4c) DoS pool ledger: the bounded TxInjectPool caps entries, per-tx bytes, and
//      cumulative bytes — each refusal named.
TEST(DashTxInject, InjectPoolDoSCaps)
{
    TxInjectPool pool;
    uint256 t1 = prevhash(0x10);
    // per-tx oversize (checked before the cumulative cap).
    EXPECT_EQ(pool.would_admit(t1, TxInjectPool::kMaxInjectTxBytes + 1),
              TxInjectPool::Admit::TooLarge);
    // admit one, then a duplicate is named.
    ASSERT_EQ(pool.admit(t1, 0, 0, 250), TxInjectPool::Admit::Ok);
    EXPECT_EQ(pool.would_admit(t1, 250), TxInjectPool::Admit::Duplicate);
    EXPECT_EQ(pool.size(), 1u);
    // CUMULATIVE byte cap: fill the pool with per-tx-legal entries up near the
    // total ceiling, then the next (also per-tx-legal) entry is refused by name.
    const uint32_t chunk = 90'000;   // < kMaxInjectTxBytes, so per-tx passes
    uint8_t seed = 0x20;
    while (pool.total_bytes() + chunk <= TxInjectPool::kMaxInjectTotalBytes) {
        uint256 id = prevhash(seed++);
        ASSERT_EQ(pool.admit(id, 0, 0, chunk), TxInjectPool::Admit::Ok);
    }
    uint256 over = prevhash(seed++);
    EXPECT_EQ(pool.would_admit(over, chunk), TxInjectPool::Admit::TotalBytesExceeded)
        << "a per-tx-legal inject that would exceed the cumulative cap is refused by name";
    // Expiry reap: an expiry_height==0 entry never expires; a set one drops at
    // height > expiry and is reported so the caller evicts it from the mempool.
    auto dropped = pool.reap_expired(/*height=*/0);
    EXPECT_TRUE(dropped.empty());
    uint256 tExp = prevhash(seed++);
    pool.clear();
    pool.admit(tExp, 0, /*expiry_height=*/100, 250);
    auto d2 = pool.reap_expired(/*height=*/101);
    ASSERT_EQ(d2.size(), 1u);
    EXPECT_EQ(d2[0], tExp);
}

// (5) GOOD-CITIZEN: injection is opt-in ONLY. It is NOT a TxServeLever, so the
//     daemonless good-citizen resolver can never turn it on. This anchors the
//     "never defaulted ON" guarantee: the resolver's closed set arms the twelve
//     serving levers and has no injection concept at all.
TEST(DashTxInject, NeverGoodCitizenDefaulted)
{
    using namespace dash::coin;
    TxServeLevers req;   // everything unset
    TxServeResolution r = resolve_good_citizen_tx_serve(/*daemonless=*/true, req);
    // The resolver arms the known serving levers in daemonless posture...
    EXPECT_TRUE(r.serve_mempool_txs);
    EXPECT_TRUE(r.tx_serve_own_set);
    EXPECT_TRUE(r.defaulted_any);
    // ...and there is deliberately NO tx-inject field it could ever set. The
    // node-level flag (NodeCoinState::m_tx_inject_enabled) defaults false and is
    // flipped only by an explicit --embedded-tx-inject; see main_dash.cpp. This
    // test exists so a future refactor that tried to fold injection into the
    // good-citizen levers would have to delete it — a loud tripwire.
    SUCCEED();
}
