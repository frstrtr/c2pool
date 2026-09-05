// COMPILE-CHECK + LOGIC-TEST DRIVER (not a deliverable).
// Links against xmr_coinbase.cpp with STUBBED coin-layer crypto (the allocation
// logic under test uses no crypto). Verifies the exact-sum invariant, K_fair
// ordering, the residual sink, the CARROT fence, and the ACCEPT re-derivation
// check. Build: g++ -std=c++20 -I shim xmr_coinbase.cpp driver.cpp -o check
#include "impl/xmr/settle/xmr_coinbase.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>

// ---- stub coin-layer crypto (declarations in xmr_derivation.hpp + fwd decl) ----
namespace xmr { namespace coin {
void hash_to_scalar(const void* d, std::size_t n, EcScalar& s) {
    unsigned char acc = 0x5a;
    const auto* p = static_cast<const unsigned char*>(d);
    for (std::size_t i = 0; i < n; ++i) acc = static_cast<unsigned char>(acc ^ p[i]);
    for (int i = 0; i < 32; ++i) s.data()[i] = static_cast<unsigned char>(acc + i);
}
bool generate_key_derivation(const PublicKey& A, const SecretKey&, KeyDerivation& D) {
    for (int i = 0; i < 32; ++i) D.data()[i] = static_cast<unsigned char>(A.data()[i] ^ 0x11);
    return true;
}
void derivation_to_scalar(const KeyDerivation& D, std::size_t i, EcScalar& s) {
    for (int k = 0; k < 32; ++k) s.data()[k] = static_cast<unsigned char>(D.data()[k] + i);
}
bool derive_public_key(const KeyDerivation& D, std::size_t i, const PublicKey& B, PublicKey& P) {
    for (int k = 0; k < 32; ++k) P.data()[k] = static_cast<unsigned char>(B.data()[k] ^ D.data()[k]);
    P.data()[0] = static_cast<unsigned char>(i);   // make each vout key distinct
    return true;
}
void derive_view_tag(const KeyDerivation& D, std::size_t i, ViewTag& vt) {
    vt.tag = static_cast<unsigned char>(D.data()[0] ^ static_cast<unsigned char>(i));
}
bool secret_key_to_public_key(const SecretKey& s, PublicKey& p) {
    for (int i = 0; i < 32; ++i) p.data()[i] = static_cast<unsigned char>(s.data()[i] ^ 0x42);
    return true;
}
}} // namespace xmr::coin

using namespace v37::xmr::settle;

static v37::ScriptRef xmr_ref(unsigned char seed) {
    v37::ScriptRef r;
    r.kind = v37::xmr::XMR_STD;
    r.payload.resize(64);
    for (int i = 0; i < 64; ++i) r.payload[i] = static_cast<unsigned char>(seed + i);
    return r;
}
static v37::bytes32 id_of(unsigned char seed) {
    v37::bytes32 b; for (int i = 0; i < 32; ++i) b.b[i] = static_cast<unsigned char>(seed + i); return b;
}
static std::uint64_t sum_amounts(const std::vector<CoinbaseOutput>& v) {
    std::uint64_t s = 0; for (auto& o : v) s += o.amount; return s;
}

static int fails = 0;
#define CHECK(c, msg) do { if (!(c)) { std::printf("FAIL: %s\n", msg); ++fails; } } while (0)

static CoinbaseInputs base_inputs() {
    CoinbaseInputs in;
    in.monero_major_version = 16;
    in.height = 3000000;
    in.base_reward = 600000000000ull;   // 0.6 XMR tail (piconero)
    in.fees = 0;
    in.chain_id = 0xABCD;
    in.residual_sink = xmr_ref(0x99);
    in.residual_sink_identity = id_of(0x99);
    in.h_min = 0;
    in.output_cap = 2700;
    in.extra_nonce = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0}; // 14-B p2pool-style padded nonce
    return in;
}

int main() {
    // ---- Case A: budget > Sum(owed) -> owed paid in full + sink absorbs surplus.
    {
        CoinbaseInputs in = base_inputs(); in.base_reward = 1000; in.fees = 0;
        in.owed = { {xmr_ref(1),200,1,id_of(1)}, {xmr_ref(2),300,2,id_of(2)}, {xmr_ref(3),100,3,id_of(3)} };
        auto o = allocate_exact_sum(in);
        CHECK(!o.empty(), "A: nonempty");
        CHECK(sum_amounts(o) == 1000, "A: exact-sum");
        CHECK(o.size() == 4, "A: 3 owed + sink");
        CHECK(o[0].amount == 200 && o[1].amount == 300 && o[2].amount == 100, "A: oldest-first amounts");
        CHECK(o.back().role == CoinbaseOutput::Role::Sink && o.back().amount == 400, "A: sink=400");
        CHECK(o[0].role == CoinbaseOutput::Role::Owed, "A: role owed");
    }
    // ---- Case B: budget < Sum(owed) -> partial last owed, no sink.
    {
        CoinbaseInputs in = base_inputs(); in.base_reward = 1000; in.fees = 0;
        in.owed = { {xmr_ref(1),600,1,id_of(1)}, {xmr_ref(2),700,2,id_of(2)} };
        auto o = allocate_exact_sum(in);
        CHECK(sum_amounts(o) == 1000, "B: exact-sum");
        CHECK(o.size() == 2, "B: 2 outputs, no sink");
        CHECK(o[0].amount == 600 && o[1].amount == 400, "B: partial last");
        for (auto& x : o) CHECK(x.role == CoinbaseOutput::Role::Owed, "B: all owed");
    }
    // ---- Case C: below-h_min owed carried (no output).
    {
        CoinbaseInputs in = base_inputs(); in.base_reward = 1000; in.fees = 0; in.h_min = 10;
        in.owed = { {xmr_ref(1),5,1,id_of(1)}, {xmr_ref(2),600,2,id_of(2)} };
        auto o = allocate_exact_sum(in);
        CHECK(sum_amounts(o) == 1000, "C: exact-sum");
        CHECK(o.size() == 2, "C: fe2 owed + sink (fe1 carried)");
        CHECK(o[0].amount == 600 && o[1].role == CoinbaseOutput::Role::Sink && o[1].amount == 400, "C: carry+sink");
    }
    // ---- Case D: cap reached -> remainder to sink.
    {
        CoinbaseInputs in = base_inputs(); in.base_reward = 1000; in.fees = 0; in.output_cap = 3;
        in.owed = { {xmr_ref(1),100,1,id_of(1)},{xmr_ref(2),100,2,id_of(2)},
                    {xmr_ref(3),100,3,id_of(3)},{xmr_ref(4),100,4,id_of(4)},{xmr_ref(5),100,5,id_of(5)} };
        auto o = allocate_exact_sum(in);
        CHECK(sum_amounts(o) == 1000, "D: exact-sum");
        CHECK(o.size() == 3, "D: cap_owed(2) + sink");
        CHECK(o[2].role == CoinbaseOutput::Role::Sink && o[2].amount == 800, "D: sink=800");
    }
    // ---- Case E: fixed output deducted first, order owed|fixed|sink.
    {
        CoinbaseInputs in = base_inputs(); in.base_reward = 1000; in.fees = 0;
        in.fixed = { {xmr_ref(0x50), 50, id_of(0x50)} };
        in.owed  = { {xmr_ref(1),200,1,id_of(1)} };
        auto o = allocate_exact_sum(in);
        CHECK(sum_amounts(o) == 1000, "E: exact-sum");
        CHECK(o.size() == 3, "E: owed+fixed+sink");
        CHECK(o[0].role == CoinbaseOutput::Role::Owed && o[0].amount == 200, "E: owed first");
        CHECK(o[1].role == CoinbaseOutput::Role::Fixed && o[1].amount == 50, "E: fixed mid");
        CHECK(o[2].role == CoinbaseOutput::Role::Sink && o[2].amount == 750, "E: sink last");
    }
    // ---- Case F: no owed, no fixed -> whole budget to sink.
    {
        CoinbaseInputs in = base_inputs(); in.base_reward = 1000; in.fees = 0;
        auto o = allocate_exact_sum(in);
        CHECK(o.size() == 1 && o[0].role == CoinbaseOutput::Role::Sink && o[0].amount == 1000, "F: all to sink");
    }
    // ---- Case G: fixed == budget -> no owed, no sink.
    {
        CoinbaseInputs in = base_inputs(); in.base_reward = 1000; in.fees = 0;
        in.fixed = { {xmr_ref(0x50), 1000, id_of(0x50)} };
        in.owed  = { {xmr_ref(1),200,1,id_of(1)} };
        auto o = allocate_exact_sum(in);
        CHECK(sum_amounts(o) == 1000 && o.size() == 1 && o[0].role == CoinbaseOutput::Role::Fixed, "G: fixed==budget");
    }
    // ---- Error cases.
    {
        BuildError e = BuildError::None;
        CoinbaseInputs in = base_inputs(); in.base_reward = 1000; in.fees = 0;
        in.fixed = { {xmr_ref(0x50), 1001, id_of(0x50)} };
        auto o = allocate_exact_sum(in, &e);
        CHECK(o.empty() && e == BuildError::FixedExceedsBudget, "H: FixedExceedsBudget");
    }
    {
        BuildError e = BuildError::None;
        CoinbaseInputs in = base_inputs(); in.base_reward = 1000; in.fees = 0; in.output_cap = 0;
        auto o = allocate_exact_sum(in, &e);
        CHECK(o.empty() && e == BuildError::CapTooSmall, "I: CapTooSmall");
    }
    {
        BuildError e = BuildError::None;
        CoinbaseInputs in = base_inputs(); in.base_reward = 0; in.fees = 0;
        auto o = allocate_exact_sum(in, &e);
        CHECK(o.empty() && e == BuildError::ZeroBudget, "J: ZeroBudget");
    }

    // ---- CARROT fence.
    {
        CoinbaseInputs in = base_inputs();
        in.owed = { {xmr_ref(1),200000000000ull,1,id_of(1)} };
        auto b16 = build_coinbase(in);
        CHECK(b16.ok, "fence: v16 builds");
        in.monero_major_version = 17;
        auto b17 = build_coinbase(in);
        CHECK(!b17.ok && b17.error == BuildError::CarrotFence, "fence: v17 refused");
    }

    // ---- build_coinbase exact-sum + ACCEPT re-derivation.
    {
        CoinbaseInputs in = base_inputs();
        in.owed = { {xmr_ref(1),200000000000ull,1,id_of(1)},
                    {xmr_ref(2),150000000000ull,2,id_of(2)} };
        auto b = build_coinbase(in);
        CHECK(b.ok, "build: ok");
        std::uint64_t s = 0; for (auto& o : b.outputs) s += o.amount;
        CHECK(s == in.budget(), "build: exact-sum == base_reward+fees");

        // feed the built coinbase back as a received one -> must match.
        ReceivedCoinbase got;
        got.R = b.R;
        for (auto& o : b.outputs) { got.amounts.push_back(o.amount);
                                    got.keys.push_back(o.one_time_key);
                                    got.view_tags.push_back(o.view_tag); }
        got.tx_extra = b.tx_extra;
        auto m = canonical_coinbase_matches(in, got);
        CHECK(m.matches && m.first_bad_index == -1, "accept: identical matches");

        // perturb an output amount -> first_bad_index points at it.
        auto got2 = got; got2.amounts[1] += 1;
        auto m2 = canonical_coinbase_matches(in, got2);
        CHECK(!m2.matches && m2.first_bad_index == 1, "accept: amount tamper -> index 1");

        // perturb the key -> "wrong wallet at index i".
        auto got3 = got; got3.keys[0].data()[5] ^= 0xff;
        auto m3 = canonical_coinbase_matches(in, got3);
        CHECK(!m3.matches && m3.first_bad_index == 0, "accept: key tamper -> index 0");

        // perturb R -> IDX_R.
        auto got4 = got; got4.R.data()[0] ^= 0xff;
        auto m4 = canonical_coinbase_matches(in, got4);
        CHECK(!m4.matches && m4.first_bad_index == IDX_R, "accept: R tamper -> IDX_R");

        // wrong count -> IDX_COUNT.
        auto got5 = got; got5.amounts.pop_back();
        auto m5 = canonical_coinbase_matches(in, got5);
        CHECK(!m5.matches && m5.first_bad_index == IDX_COUNT, "accept: count -> IDX_COUNT");

        // perturb tx_extra (commitment) -> IDX_EXTRA.
        auto got6 = got; got6.tx_extra.back() ^= 0xff;
        auto m6 = canonical_coinbase_matches(in, got6);
        CHECK(!m6.matches && m6.first_bad_index == IDX_EXTRA, "accept: extra -> IDX_EXTRA");
    }

    // ---- weight-aware cap.
    {
        // wire cap binds below the penalty headroom.
        CHECK(weight_aware_output_cap(300000, 0, 2700) == 2700, "cap: wire binds");
        // tiny wire cap.
        CHECK(weight_aware_output_cap(300000, 0, 10) == 10, "cap: small wire");
        // never zero.
        CHECK(weight_aware_output_cap(0, 1000000, 2700) == 1, "cap: floor 1");
    }

    if (fails == 0) std::printf("ALL W5-COINBASE CHECKS PASSED\n");
    else            std::printf("%d CHECK(S) FAILED\n", fails);
    return fails == 0 ? 0 : 1;
}
