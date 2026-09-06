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
//      armed (sole-ingestion-path invariant). The seam ALSO closes the two
//      admission rows the invariant used to argue N-A on relay-only ingestion:
//        * FAIL-CLOSED BIP68 (bad-txns-nonfinal) — a v2 inject that opts into a
//          relative sequence-lock is refused (inject-bip68-unsupported), since
//          SequenceLocks is not yet ported (M2);
//        * REWARD-SAFE value range (bad-txns-vout-*) — an inject with a vout
//          outside MoneyRange is refused (inject-bad-txns-vout-range), and the
//          shared compute_fee pricing path MoneyRange-guards out_sum so a
//          relay/BIP35 tx cannot wrap the sum into a fabricated coinbase fee.
//
// The signed-spend + script-verify scaffolding is the SAME dashcore VerifyScript
// (dash_scriptcheck.so) the KAT signs a real P2PKH spend against — no hand-rolled
// fixture. Folded into the test_dash_mempool executable (build.yml allowlisted).

#include <gtest/gtest.h>

#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/tx_inject_pool.hpp>
#include <impl/dash/coin/node_coin_state.hpp>   // #157 M2: submit_inject gate (relay routes through it)
#include <impl/dash/tx_inject_relay.hpp>        // #157 M2: ingest_peer_inject relay policy
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

// (4d) GAP-1 FAIL-CLOSED — BIP68 relative-locktime. This is a NEW ingestion
//      seam, so the sole-ingestion-path invariant's "relay-admitted txs are
//      final at admission" premise no longer holds: a directly-injected tx
//      never passed a relaying dashd's SequenceLocks. We port absolute-locktime
//      finality (is_final_tx) but NOT relative BIP68 (that is M2), so an inject
//      that OPTS IN to a relative lock — nVersion>=2 with an input whose
//      nSequence leaves SEQUENCE_LOCKTIME_DISABLE_FLAG clear — is FAIL-CLOSED
//      refused by name rather than risked into a bad-txns-nonfinal template.
//      RED on 9e859686: InjectGate::Bip68Unsupported does not exist and the tx
//      is admitted (Ok) → selectable → an invalid block. GREEN after: refused.
TEST(DashTxInject, Bip68RelativeLockInjectRefusedFailClosed)
{
    Key k(0x88);
    uint256 prev = prevhash(0xba);

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp; mp.set_utxo(&utxo);
    arm_script_check(mp);

    // NEGATIVE: nVersion==2 with a BIP68 relative-lock input (bit 31 clear).
    auto rel = make_signed_spend(k, prev, 90'000);
    rel.version = 2;
    rel.vin[0].sequence = 0x0000000au;   // disable-flag clear ⇒ relative lock ON
    EXPECT_EQ(mp.add_inject(rel), Mempool::InjectGate::Bip68Unsupported)
        << "a v2 inject that opts into a BIP68 relative lock must be fail-closed refused";

    // POSITIVE TWIN 1: nVersion==2 but every input disables the relative lock
    // (SEQUENCE_FINAL has bit 31 set) ⇒ no BIP68 opt-in ⇒ admitted.
    auto v2_final = make_signed_spend(k, prev, 90'000);
    v2_final.version = 2;                 // vin sequence stays 0xffffffff
    EXPECT_EQ(mp.add_inject(v2_final), Mempool::InjectGate::Ok)
        << "a v2 inject with no relative-lock input rides the normal path";

    // POSITIVE TWIN 2: nVersion==1 never activates BIP68, even with the same
    // relative-lock sequence bits — version-gated, exactly as consensus does it.
    uint256 prev2 = prevhash(0xbb);
    utxo.add_coin(Outpoint(prev2, 0), Coin(100'000, to_script(k.spk), 1, false));
    auto v1_rel = make_signed_spend(k, prev2, 90'000);
    v1_rel.version = 1;
    v1_rel.vin[0].sequence = 0x0000000au;
    EXPECT_EQ(mp.add_inject(v1_rel), Mempool::InjectGate::Ok)
        << "BIP68 is nVersion>=2 only; a v1 inject is unaffected";
}

// (4e) GAP-2 REWARD-SAFETY — CheckTransaction output value-range (MoneyRange).
//      compute_fee casts vout.value to uint64 for out_sum, so an out-of-range
//      value (INT64_MIN) wraps the sum and fabricates a positive fee → inflated
//      total_fees → the coinbase value MOVES → an invalid, reward-unsafe block.
//      Two guards close it: add_inject refuses by name BEFORE pricing, and
//      compute_fee_locked (the shared pricing path every ingestion seam uses)
//      MoneyRange-guards out_sum so a relay/BIP35 tx is template-EXCLUDED.
//      RED on 9e859686: InjectGate::BadVoutRange does not exist, the inject is
//      admitted, and a 2×INT64_MIN relay tx prices to a fabricated fee and is
//      SELECTED. GREEN after: refused / excluded, coinbase untouched.
TEST(DashTxInject, VoutValueRangeInjectRefusedAndPricingFailClosed)
{
    Key k(0x99);
    uint256 prev = prevhash(0xca);

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp; mp.set_utxo(&utxo);
    arm_script_check(mp);

    // NEGATIVE (add_inject gate): a vout outside MoneyRange (INT64_MIN — the
    // exact wrap value) is refused by name, ahead of admission/pricing.
    auto badneg = make_signed_spend(k, prev, 90'000);
    badneg.vout[0].value = INT64_MIN;
    EXPECT_EQ(mp.add_inject(badneg), Mempool::InjectGate::BadVoutRange)
        << "an inject with a vout below MoneyRange must be refused by name";

    // NEGATIVE (upper bound): a vout above MAX_MONEY is equally refused.
    auto badhi = make_signed_spend(k, prev, 90'000);
    badhi.vout[0].value = Mempool::DASH_MAX_MONEY + 1;
    EXPECT_EQ(mp.add_inject(badhi), Mempool::InjectGate::BadVoutRange)
        << "an inject with a vout above MoneyRange must be refused by name";

    // POSITIVE TWIN: an in-range inject prices normally and is served at its
    // true base fee — the guard is a no-op for any valid tx.
    auto good = make_signed_spend(k, prev, 90'000);   // fee 10'000
    EXPECT_EQ(mp.add_inject(good), Mempool::InjectGate::Ok);
    {
        auto [selected, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
        ASSERT_EQ(selected.size(), 1u);
        EXPECT_EQ(dash_txid(selected[0].tx), dash_txid(good));
        EXPECT_EQ(fees, 10'000u) << "a valid inject prices to its true base fee (guard is a no-op)";
    }

    // compute_fee_locked GUARD via the RELAY seam (add_tx), which has NO inject
    // gate: two INT64_MIN vouts wrap out_sum to 0, so on 9e859686 the tx prices
    // to a fabricated fee (in_sum) and is SELECTED — a value-creating block.
    // Script-check is left UNARMED so the selector's fee_fold_proven gate is the
    // sole discriminator (no signature confound). GREEN after: MoneyRange makes
    // the tx unpriceable ⇒ fee_fold_proven false ⇒ template-excluded.
    uint256 prevW = prevhash(0xcb);
    UTXOViewCache utxo2(nullptr);
    utxo2.add_coin(Outpoint(prevW, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp2; mp2.set_utxo(&utxo2);
    // NO arm_script_check — isolate the pricing guard.
    MutableTransaction wrap;
    wrap.version = 1; wrap.type = 0; wrap.locktime = 0;
    TxIn win; win.prevout.hash = prevW; win.prevout.index = 0; win.sequence = 0xffffffffu;
    win.scriptSig = to_script(k.spk);
    wrap.vin.push_back(win);
    TxOut wo1; wo1.value = INT64_MIN; wo1.scriptPubKey = to_script(k.spk); wrap.vout.push_back(wo1);
    TxOut wo2; wo2.value = INT64_MIN; wo2.scriptPubKey = to_script(k.spk); wrap.vout.push_back(wo2);
    ASSERT_TRUE(mp2.add_tx(wrap));   // admitted (unpriceable txs are admitted, then excluded)
    auto [sel2, fees2] = mp2.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    EXPECT_EQ(sel2.size(), 0u)
        << "a relay tx whose vouts wrap out_sum must be template-excluded, not priced to a fake fee";
    EXPECT_EQ(fees2, 0u) << "the fabricated fee must never reach total_fees / the coinbase";
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

// ═══════════════════════════════════════════════════════════════════════════
// #157 M2 — PEER TX-INJECTION RELAY (src/impl/dash/tx_inject_relay.hpp).
//
// These KATs drive dash::ingest_peer_inject — the transport-side policy that
// sits IN FRONT of submit_inject. They are RED on master by construction:
// tx_inject_relay.hpp does not exist there, so this TU fails to compile. GREEN
// after: the relay routes a peer's tx through the SAME M1 submit_inject gate,
// deduplicates, rate-limits, and first-see fans out.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

using dash::coin::NodeCoinState;

// Arm the consensus-exact CheckInputScripts callback on a NodeCoinState's mempool
// (same VerifyScript the local hex loader uses), then enable injection.
void arm_ncs(NodeCoinState& st, UTXOViewCache& utxo) {
    st.mempool().set_utxo(&utxo);
    st.set_script_check([](const std::vector<uint8_t>& t, uint32_t n,
                           const std::vector<uint8_t>& s, uint32_t f) {
        return c2pool_dash_verify_input(s.data(), (unsigned)s.size(),
                                        t.data(), (unsigned)t.size(), n, f) == 1;
    });
    st.set_tx_inject_enabled(true);
}

// The submit_fn the handler builds: route the peer tx through submit_inject and
// collapse the rich result into the relay's InjectSubmitOutcome.
auto make_sink(NodeCoinState& st, const MutableTransaction& tx,
               uint32_t flags = 0, int32_t expiry = 0) {
    return [&st, tx, flags, expiry]() -> dash::InjectSubmitOutcome {
        auto r = st.submit_inject(tx, flags, expiry);
        return dash::InjectSubmitOutcome{ r.ok, r.cause };
    };
}

} // namespace

// (M2-1) A valid signed spend from a peer is ACCEPTED through submit_inject and
//        flagged for first-see fan-out; the inject lands in the pool + mempool.
TEST(DashTxInject, PeerInjectAcceptedAndForwardedOnFirstSee)
{
    Key k(0xa1);
    uint256 prev = prevhash(0x71);
    auto tx = make_signed_spend(k, prev, 100'000);   // fee 0 (injected)

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    NodeCoinState st; arm_ncs(st, utxo);

    dash::NodeInjectSeen node_seen;
    dash::PeerInjectGuard peer;
    const uint256 txid = dash_txid(tx);

    auto v = dash::ingest_peer_inject(/*enabled=*/true, node_seen, peer, txid,
                                      /*byte_size=*/225, /*now=*/1000,
                                      make_sink(st, tx));
    EXPECT_EQ(v.kind, dash::InjectRelayVerdict::Kind::Accepted);
    EXPECT_TRUE(v.forward) << "a first-see ACCEPT must fan out";
    EXPECT_EQ(v.txid, txid);
    EXPECT_EQ(st.inject_pool_size(), 1u);
    EXPECT_TRUE(node_seen.contains(txid));
}

// (M2-2) A missing-input tx is REJECTED by name (submit_inject → unpriceable)
//        and NOT forwarded.
TEST(DashTxInject, PeerInjectRejectedByNameNotForwarded)
{
    Key k(0xa2);
    uint256 prev = prevhash(0x72);   // NOT in the UTXO view
    auto tx = make_signed_spend(k, prev, 90'000);

    UTXOViewCache utxo(nullptr);     // empty
    NodeCoinState st; arm_ncs(st, utxo);

    dash::NodeInjectSeen node_seen;
    dash::PeerInjectGuard peer;
    const uint256 txid = dash_txid(tx);

    auto v = dash::ingest_peer_inject(true, node_seen, peer, txid, 225, 1000,
                                      make_sink(st, tx));
    EXPECT_EQ(v.kind, dash::InjectRelayVerdict::Kind::Rejected);
    EXPECT_EQ(v.cause, "inject-unpriceable");
    EXPECT_FALSE(v.forward);
    EXPECT_EQ(st.inject_pool_size(), 0u);
    // A rejected txid is still REMEMBERED (as rejected) so a re-send is not
    // re-validated.
    EXPECT_TRUE(node_seen.contains(txid));
}

// (M2-3) The same tx re-sent by the same peer, and by a DIFFERENT peer, is a
//        Duplicate — submit_inject is called EXACTLY ONCE (no re-validation).
TEST(DashTxInject, PeerInjectDuplicateNotReforwarded)
{
    Key k(0xa3);
    uint256 prev = prevhash(0x73);
    auto tx = make_signed_spend(k, prev, 100'000);

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    NodeCoinState st; arm_ncs(st, utxo);

    dash::NodeInjectSeen node_seen;
    dash::PeerInjectGuard peerA, peerB;
    const uint256 txid = dash_txid(tx);

    int submit_calls = 0;
    auto counting_sink = [&]() -> dash::InjectSubmitOutcome {
        ++submit_calls;
        auto r = st.submit_inject(tx, 0, 0);
        return dash::InjectSubmitOutcome{ r.ok, r.cause };
    };

    // First-see from peer A: accepted + forwarded, one submit.
    auto v1 = dash::ingest_peer_inject(true, node_seen, peerA, txid, 225, 1000, counting_sink);
    EXPECT_EQ(v1.kind, dash::InjectRelayVerdict::Kind::Accepted);
    EXPECT_TRUE(v1.forward);

    // Same tx again from peer A: per-peer duplicate, no submit, no forward.
    auto v2 = dash::ingest_peer_inject(true, node_seen, peerA, txid, 225, 1001, counting_sink);
    EXPECT_EQ(v2.kind, dash::InjectRelayVerdict::Kind::Duplicate);
    EXPECT_FALSE(v2.forward);

    // Same tx from peer B: node-wide duplicate, no submit, no forward.
    auto v3 = dash::ingest_peer_inject(true, node_seen, peerB, txid, 225, 1002, counting_sink);
    EXPECT_EQ(v3.kind, dash::InjectRelayVerdict::Kind::Duplicate);
    EXPECT_FALSE(v3.forward);

    EXPECT_EQ(submit_calls, 1) << "a duplicate must NEVER re-run the (script-checking) submit gate";
    EXPECT_EQ(st.inject_pool_size(), 1u);
}

// (M2-4) DoS: one peer sending many distinct injects inside a window is cut off
//        at the per-peer budget; the over-budget request never reaches submit.
TEST(DashTxInject, PeerInjectRateLimitedDoS)
{
    UTXOViewCache utxo(nullptr);
    NodeCoinState st; arm_ncs(st, utxo);   // view left empty on purpose

    dash::NodeInjectSeen node_seen;
    dash::PeerInjectGuard peer;

    int submit_calls = 0;
    const std::size_t cap = dash::PeerInjectGuard::kMaxInjectsPerPeerPerWindow;

    // Fire `cap` distinct txids inside one window (now fixed): each is allowed
    // through to submit (and rejected as unpriceable — irrelevant to the cap).
    for (std::size_t i = 0; i < cap; ++i) {
        uint256 id = prevhash(static_cast<uint8_t>(0x80 + i));
        auto v = dash::ingest_peer_inject(true, node_seen, peer, id, 225, /*now=*/5000,
            [&]() -> dash::InjectSubmitOutcome { ++submit_calls; return {false, "inject-unpriceable"}; });
        EXPECT_NE(v.kind, dash::InjectRelayVerdict::Kind::RateLimited)
            << "request " << i << " is within budget";
    }
    EXPECT_EQ(submit_calls, static_cast<int>(cap));

    // The next distinct txid in the SAME window is refused BEFORE submit.
    uint256 over = prevhash(static_cast<uint8_t>(0x80 + cap));
    auto vr = dash::ingest_peer_inject(true, node_seen, peer, over, 225, /*now=*/5000,
        [&]() -> dash::InjectSubmitOutcome { ++submit_calls; return {false, "x"}; });
    EXPECT_EQ(vr.kind, dash::InjectRelayVerdict::Kind::RateLimited);
    EXPECT_FALSE(vr.forward);
    EXPECT_EQ(submit_calls, static_cast<int>(cap)) << "the rate-limited request must not reach submit";

    // The window slides: the same txid a full window later is admitted through.
    auto vlater = dash::ingest_peer_inject(true, node_seen, peer, over, 225,
        /*now=*/5000 + dash::PeerInjectGuard::kWindowSeconds,
        [&]() -> dash::InjectSubmitOutcome { ++submit_calls; return {false, "x"}; });
    EXPECT_NE(vlater.kind, dash::InjectRelayVerdict::Kind::RateLimited)
        << "after the window slides the peer recovers its budget";
}

// (M2-5) FLAG OFF: a disabled node ignores every tx_inject — no submit, no state
//        mutation (node seen-set + peer guard untouched), no forward.
TEST(DashTxInject, PeerInjectIgnoredWhenFlagOff)
{
    Key k(0xa5);
    uint256 prev = prevhash(0x75);
    auto tx = make_signed_spend(k, prev, 100'000);

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    NodeCoinState st; st.mempool().set_utxo(&utxo);
    st.set_tx_inject_enabled(false);   // DISABLED

    dash::NodeInjectSeen node_seen;
    dash::PeerInjectGuard peer;
    const uint256 txid = dash_txid(tx);

    int submit_calls = 0;
    auto v = dash::ingest_peer_inject(/*enabled=*/false, node_seen, peer, txid, 225, 1000,
        [&]() -> dash::InjectSubmitOutcome { ++submit_calls; return {true, "ok"}; });

    EXPECT_EQ(v.kind, dash::InjectRelayVerdict::Kind::Disabled);
    EXPECT_FALSE(v.forward);
    EXPECT_EQ(submit_calls, 0) << "a disabled node must not call submit_inject";
    EXPECT_EQ(node_seen.size(), 0u) << "no node-level state may be mutated when the flag is OFF";
    EXPECT_FALSE(peer.peer_has_seen(txid)) << "no per-peer state may be mutated when the flag is OFF";
    EXPECT_TRUE(peer.window.empty());
    EXPECT_EQ(st.inject_pool_size(), 0u);
}

// (M2-6) An accepted inject is an ordinary mempool body tx: it is SELECTED into
//        the template body (the same hashes register_template_txs would receive),
//        so it rides that path with zero extra code. Structural proof, no NodeImpl.
TEST(DashTxInject, InjectedTxRidesRegisterTemplateTxs)
{
    Key k(0xa6);
    uint256 prev = prevhash(0x76);
    auto tx = make_signed_spend(k, prev, 100'000);

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    NodeCoinState st; arm_ncs(st, utxo);

    dash::NodeInjectSeen node_seen;
    dash::PeerInjectGuard peer;
    const uint256 txid = dash_txid(tx);

    auto v = dash::ingest_peer_inject(true, node_seen, peer, txid, 225, 1000, make_sink(st, tx));
    ASSERT_EQ(v.kind, dash::InjectRelayVerdict::Kind::Accepted);

    // The body the template builder selects — the same {tx, fee} vector whose
    // hashes register_template_txs(m_txs, m_tx_hashes) would carry into m_known_txs.
    auto [selected, fees] = st.mempool().get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    ASSERT_EQ(selected.size(), 1u);
    EXPECT_EQ(dash_txid(selected[0].tx), txid)
        << "the accepted inject must be in the served body (rides register_template_txs)";
    EXPECT_EQ(fees, 0u) << "a 0-fee inject contributes 0 to total_fees — reward path unchanged";
}
