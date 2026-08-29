// SPDX-License-Identifier: AGPL-3.0-or-later
// PR-C4 — consensus-exact CheckInputScripts over the C1 fold view.
//
// Proves the reward-safety belt the dashd-cut tx-serving path needs: a served
// mempool tx whose scriptSig does NOT satisfy the referenced coin's
// scriptPubKey is EXCLUDED from the template (fail-closed), while a valid one is
// selected, and with the check OFF selection is byte-identical to master.
//
// The verifier under test is dashcore's OWN VerifyScript (dash_scriptcheck.so,
// the interpreter vendored byte-for-byte under coin/vendor/dashscript/), driven
// through the pure-C c2pool_dash_* API. The KAT signs a real P2PKH spend with
// the linked secp256k1 so the full EvalScript + legacy SignatureHash + ECDSA
// path is exercised end to end -- no hand-rolled fixture that could pass a
// broken interpreter.
//
// Folded into the test_dash_mempool executable (build.yml allowlisted) so it is
// always built and run -- never a NOT_BUILT sentinel.

#include <gtest/gtest.h>

#include <impl/dash/coin/mempool.hpp>
#include <impl/dash/coin/vendor/dashscript/c2pool_scriptcheck.h>

#include <core/uint256.hpp>
#include <core/coin/utxo_view_cache.hpp>

#include <secp256k1.h>

#include <cstdint>
#include <cstring>
#include <vector>

using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::dash_txid;
using ::core::coin::UTXOViewCache;
using ::core::coin::Outpoint;
using ::core::coin::Coin;
using ::bitcoin_family::coin::TxIn;
using ::bitcoin_family::coin::TxOut;
// OPScript lives in the global namespace (src/core/opscript.hpp).

namespace {

constexpr uint32_t kDashScriptFlagsAll =
    C2POOL_DASH_SCRIPT_VERIFY_P2SH | C2POOL_DASH_SCRIPT_VERIFY_DERSIG |
    C2POOL_DASH_SCRIPT_VERIFY_NULLDUMMY | C2POOL_DASH_SCRIPT_VERIFY_CLTV |
    C2POOL_DASH_SCRIPT_VERIFY_CSV;

std::vector<uint8_t> ser(const MutableTransaction& tx) {
    auto ps = ::pack(tx);
    auto sp = ps.get_span();
    const auto* b = reinterpret_cast<const uint8_t*>(sp.data());
    return std::vector<uint8_t>(b, b + sp.size());
}

OPScript to_script(const std::vector<uint8_t>& v) {
    return OPScript(v.data(), v.data() + v.size());
}

// One deterministic P2PKH keypair + scriptPubKey.
struct Key {
    secp256k1_context* ctx;
    uint8_t seckey[32];
    uint8_t pub[33];
    size_t publen = 33;
    std::vector<uint8_t> spk;   // OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG

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

    // scriptSig = <DER sig || SIGHASH_ALL> <pubkey>
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

// Build a signed 1-in 1-out P2PKH spend of (prev:0). Coin value = out+fee.
MutableTransaction make_signed_spend(const Key& k, const uint256& prev,
                                     int64_t out_value) {
    MutableTransaction tx;
    tx.version = 1; tx.type = 0; tx.locktime = 0;
    TxIn in; in.prevout.hash = prev; in.prevout.index = 0; in.sequence = 0xffffffffu;
    in.scriptSig = to_script(k.spk);   // scriptCode for the legacy sighash
    tx.vin.push_back(in);
    TxOut out; out.value = out_value; tx.vout.push_back(out);

    auto unsigned_bytes = ser(tx);
    uint8_t sighash[32];
    EXPECT_EQ(c2pool_dash_legacy_sighash(unsigned_bytes.data(), (unsigned)unsigned_bytes.size(),
                                         0, k.spk.data(), (unsigned)k.spk.size(),
                                         1 /*SIGHASH_ALL*/, sighash), 1);
    auto ss = k.sign_scriptsig(std::vector<uint8_t>(sighash, sighash + 32));
    tx.vin[0].scriptSig = to_script(ss);
    return tx;
}

uint256 prevhash(uint8_t b) { uint256 h; std::memset(h.begin(), b, 32); return h; }

} // namespace

// KAT (a): a valid scriptSig over a fold coin is script-verified => selectable.
TEST(DashCheckInputScripts, ValidScriptSigVerifiesAndIsSelectable)
{
    Key k(0x11);
    uint256 prev = prevhash(0xa1);
    auto tx = make_signed_spend(k, prev, 90'000);

    // Direct consensus-exact verify (dashcore VerifyScript).
    auto txb = ser(tx);
    EXPECT_EQ(c2pool_dash_verify_input(k.spk.data(), (unsigned)k.spk.size(),
                                       txb.data(), (unsigned)txb.size(), 0,
                                       kDashScriptFlagsAll), 1);

    // Selectable through the real mempool selector with the check ARMED.
    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), /*height=*/1, /*cb=*/false));
    Mempool mp; mp.set_utxo(&utxo);
    ASSERT_TRUE(mp.add_tx(tx));
    mp.set_script_check([](const std::vector<uint8_t>& t, uint32_t n,
                           const std::vector<uint8_t>& s, uint32_t f) {
        return c2pool_dash_verify_input(s.data(), (unsigned)s.size(),
                                        t.data(), (unsigned)t.size(), n, f) == 1;
    });
    auto [selected, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    ASSERT_EQ(selected.size(), 1u) << "valid signed tx must be selected with the check ON";
    EXPECT_EQ(fees, 10'000u);
}

// KAT (b): a mutated/invalid scriptSig is script-REJECTED => excluded.
TEST(DashCheckInputScripts, MutatedScriptSigIsRejectedAndExcluded)
{
    Key k(0x22);
    uint256 prev = prevhash(0xb2);
    auto good = make_signed_spend(k, prev, 90'000);

    // Flip one byte inside the DER signature (offset lands in the sig body).
    auto bad = good;
    {
        auto ss = bad.vin[0].scriptSig.m_data;   // <len><der..><01><pklen><pk>
        ASSERT_GT(ss.size(), 6u);
        ss[4] ^= 0x01;                            // corrupt the signature
        bad.vin[0].scriptSig = to_script(ss);
    }

    auto badb = ser(bad);
    EXPECT_EQ(c2pool_dash_verify_input(k.spk.data(), (unsigned)k.spk.size(),
                                       badb.data(), (unsigned)badb.size(), 0,
                                       kDashScriptFlagsAll), 0)
        << "a corrupted scriptSig must fail dashcore VerifyScript";

    // Through the mempool: the invalid tx is priceable (fee computed from the
    // UTXO value, independent of script validity) and WOULD be emitted on
    // master, but the ARMED check EXCLUDES it (fail-closed).
    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prev, 0), Coin(100'000, to_script(k.spk), 1, false));
    Mempool mp; mp.set_utxo(&utxo);
    ASSERT_TRUE(mp.add_tx(bad));

    // OFF (master baseline): the script-invalid tx IS selected -- the exact gap
    // C4 closes (a template that would be rejected bad-txns-inputs-* on submit).
    {
        auto [sel_off, f_off] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
        EXPECT_EQ(sel_off.size(), 1u)
            << "OFF: master selects the tx purely on fee -- the invalid-script gap";
    }
    // ON: excluded.
    mp.set_script_check([](const std::vector<uint8_t>& t, uint32_t n,
                           const std::vector<uint8_t>& s, uint32_t f) {
        return c2pool_dash_verify_input(s.data(), (unsigned)s.size(),
                                        t.data(), (unsigned)t.size(), n, f) == 1;
    });
    {
        auto [sel_on, f_on] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
        EXPECT_EQ(sel_on.size(), 0u)
            << "ON: the script-invalid tx must be excluded from the template";
        EXPECT_EQ(f_on, 0u);
    }
}

// KAT (c): OFF (no callback wired) => selection byte-identical to master. The
// same valid AND invalid txs both flow through untouched when the check is not
// armed, and the selected set equals the pre-C4 (fee_fold_proven-only) set.
TEST(DashCheckInputScripts, OffIsByteIdenticalToMaster)
{
    Key k(0x33);
    uint256 prevGood = prevhash(0xc3);
    uint256 prevBad  = prevhash(0xc4);
    auto good = make_signed_spend(k, prevGood, 90'000);
    auto bad  = make_signed_spend(k, prevBad, 80'000);
    { // corrupt bad's scriptSig
        auto ss = bad.vin[0].scriptSig.m_data;
        ss[5] ^= 0x02;
        bad.vin[0].scriptSig = to_script(ss);
    }

    UTXOViewCache utxo(nullptr);
    utxo.add_coin(Outpoint(prevGood, 0), Coin(100'000, to_script(k.spk), 1, false));
    utxo.add_coin(Outpoint(prevBad, 0),  Coin(100'000, to_script(k.spk), 1, false));

    Mempool mp; mp.set_utxo(&utxo);
    ASSERT_TRUE(mp.add_tx(good));
    ASSERT_TRUE(mp.add_tx(bad));

    // No script check wired: has_script_check() false and BOTH txs (valid +
    // invalid) are selected exactly as master's fee_fold_proven-only selector
    // would -- proving the flag-off path is untouched.
    EXPECT_FALSE(mp.has_script_check());
    auto [selected, fees] = mp.get_sorted_txs_with_fees(1u << 20, false, 2'000'000u, 0);
    EXPECT_EQ(selected.size(), 2u)
        << "OFF: selection is byte-identical to master (both priced txs kept)";
    EXPECT_EQ(fees, 30'000u);   // 10000 + 20000
}
