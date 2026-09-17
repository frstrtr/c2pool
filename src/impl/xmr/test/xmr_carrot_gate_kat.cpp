// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/test/xmr_carrot_gate_kat.cpp
//     X6b KAT: the CARROT / FCMP++ VERSION GATE on the W5-XMR coinbase builder.
//
// This KAT exists to defend TWO properties, and it is worth being blunt about
// which is which, because they pull in opposite directions:
//
//   (A) ADDING THE GATE MOVED NO BYTE OF THE PRE-CARROT COINBASE.
//       Case 1 pins a complete v16 coinbase -- r, R, every one-time key P_i,
//       every view tag, the merge-mining root, tx_extra, the whole serialized
//       prefix, the prefix hash and the coinbase tx hash -- against goldens
//       CAPTURED FROM THE PRE-GATE TREE (origin/master 854336be) by compiling
//       the identical input vector against the unmodified build_coinbase() and
//       recording its output. Any drift in the pre-CARROT recipe, however
//       small, reds this test. That is the whole claim of the version gate: the
//       v16 arm is the old code, unchanged.
//
//       Mainnet Monero is at hard-fork major_version 16 today (hardforks.cpp
//       mainnet table ends at { 16, 2689608 }; re-verified 2026-09-17), so this
//       vector is a TODAY-MAINNET coinbase, not a hypothetical one.
//
//   (B) THE CARROT ARM STILL FAILS CLOSED.
//       The gate is a dispatcher, NOT a lift. Every major_version from 17 to
//       255 is refused with BuildError::CarrotFence and produces no outputs, no
//       keys, no prefix -- exactly the behaviour the flat fence had. The CARROT
//       derivation is a SCAFFOLD (see ../settle/xmr_carrot.hpp): upstream
//       monero-project/monero has not merged CARROT, has not tagged the fork,
//       and publishes no coinbase-enote reference vectors, so there is nothing
//       to conform to and nothing to pin. A KAT that let v17 build would be
//       certifying an invented derivation; this one certifies the refusal.
//
// Cases (each reported PASS/FAIL, nonzero exit on any failure):
//   1. v16 byte-identity goldens      -- the pre-CARROT coinbase, field by field.
//   2. regime classification          -- total over all 256 major_versions, one
//                                        boundary, PreCarrot iff <= 16.
//   3. v17..255 fail closed           -- build_coinbase refuses, emits nothing.
//   4. arms called directly           -- the pre-CARROT arm refuses a CARROT
//                                        block; the CARROT arm refuses ANY block.
//   5. the CARROT seam refuses        -- both stubs return false, fill nothing,
//                                        and report NotImplemented.
//   6. fence constants pinned         -- 16 / 17, and the CANON descriptor fence
//                                        XMR_PRECARROT_MAX_MAJOR_VERSION is
//                                        still 16 (this wave touched no canon).
//   7. downstream refusals unchanged  -- derive_tx_secret_key and
//                                        canonical_coinbase_matches at v17.
//
// VECTOR PROVENANCE: the ed25519 points used as payout targets are the OFFICIAL
// monero-project tests/crypto/tests.txt consensus vectors (generate_key_
// derivation / derive_public_key / generate_keys inputs), so every derivation
// runs against real on-curve points. The coinbase goldens themselves are
// c2pool's own output, captured pre-gate as described above. No third-party code
// is copied into this file.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/settle/xmr_coinbase.hpp"
#include "impl/xmr/settle/xmr_carrot.hpp"
#include "impl/xmr/coin/xmr_derivation.hpp"

using namespace v37::xmr::settle;

namespace {

int g_fail = 0;
#define CHECK(cond, ...) do { \
    bool _ok = (cond); \
    std::printf("  [%s] ", _ok ? "PASS" : "FAIL"); \
    std::printf(__VA_ARGS__); std::printf("\n"); \
    if (!_ok) ++g_fail; \
} while (0)

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> o; o.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}
std::string hex(const unsigned char* b, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[b[i] >> 4]); s.push_back(d[b[i] & 0xf]); }
    return s;
}
template <class T> std::string hx(const T& t) { return hex(t.data(), 32); }
template <class T> T key_from_hex(const std::string& h) {
    T t{}; auto v = unhex(h);
    std::memcpy(t.data(), v.data(), v.size() < 32 ? v.size() : 32);
    return t;
}

// ---- OFFICIAL monero-project tests/crypto/tests.txt points ----------------
const char* kP_A   = "fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984";
const char* kP_B   = "6d9dd2068b9d6d643b407e360dfc5eb7a1f628fe2de8112a9e5731e8b3680c39";
const char* kP_PUB = "0cf20fe6862d94989e57543c21cd35c9d834364db7701b8d55f63137b1abac35";
const char* kP_P   = "d48008aff5f27d8fcdc2a3bf814ed3505530f598075f3bf7e868fea696b109f6";

::v37::ScriptRef ref_of(const char* b_hex, const char* a_hex) {
    ::v37::ScriptRef r;
    r.kind = ::v37::xmr::XMR_STD;
    r.payload.resize(64);
    auto B = unhex(b_hex), A = unhex(a_hex);
    std::memcpy(r.payload.data(),      B.data(), 32);
    std::memcpy(r.payload.data() + 32, A.data(), 32);
    return r;
}
::v37::bytes32 id_of(unsigned char seed) {
    ::v37::bytes32 b{};
    for (int i = 0; i < 32; ++i) b[i] = static_cast<unsigned char>(seed + 3 * i);
    return b;
}

// ---------------------------------------------------------------------------
// THE PINNED INPUT VECTOR. Every field is fixed; the builder is a pure function
// of it, so the goldens below are reproducible by anyone at any time. Shape is
// deliberately non-trivial: two paid owed entries in K_fair order, one owed
// entry BELOW h_min (carries, emits no output), one mandated fixed output, and
// a residual sink that absorbs the remainder exactly (HF13: no burn).
// ---------------------------------------------------------------------------
CoinbaseInputs golden_inputs_v16() {
    CoinbaseInputs in;
    in.monero_major_version = 16;          // today's mainnet fork
    in.height = 3400000;
    in.prev_id = key_from_hex<::xmr::coin::Hash256>(
        "4f2e1d0c9b8a79685746352413020ffeeddccbbaa99887766554433221100aabb");
    in.base_reward = 600000000000ull;      // 0.6 XMR tail emission (piconero)
    in.fees        = 30414082ull;
    in.chain_id    = 0x5837AC01u;
    in.lane_commitment = id_of(0x27);      // owed_digest stand-in
    in.h_min = 1000000000ull;              // 0.001 XMR payout floor
    in.output_cap = 2700;
    in.extra_nonce = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                      0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};

    OwedEntry e1; e1.pay = ref_of(kP_B, kP_A);
    e1.owed = 41000000000ull; e1.first_eligible = 100; e1.identity = id_of(0x01);
    OwedEntry e2; e2.pay = ref_of(kP_PUB, kP_P);
    e2.owed = 7250000000ull;  e2.first_eligible = 90;  e2.identity = id_of(0x02);
    OwedEntry e3 = e2; e3.identity = id_of(0x40);
    e3.owed = 500000000ull;                // below h_min -> carries, no output
    in.owed = {e1, e2, e3};

    FixedOutput f1; f1.pay = ref_of(kP_PUB, kP_A);
    f1.amount = 3000000000ull; f1.identity = id_of(0x77);
    in.fixed = {f1};

    in.residual_sink = ref_of(kP_B, kP_P);
    in.residual_sink_identity = id_of(0x99);
    return in;
}

// ---------------------------------------------------------------------------
// THE GOLDENS. Captured from origin/master 854336be -- the tree BEFORE the
// version gate existed -- by running the vector above through the then-current
// build_coinbase(). Regenerate ONLY with a deliberate, reviewed consensus
// change to the pre-CARROT recipe; a diff here otherwise means this wave (or a
// later one) moved a byte it promised not to move.
// ---------------------------------------------------------------------------
const std::uint64_t kG_budget = 600030414082ull;
const char* kG_r  = "ec641de0e4696af42a432c36e584557b06ac1ab1ee97e2e74617ef5a0e3ef600";
const char* kG_R  = "4ee5f6c2004eb10bbb9ca46fb1f33e17577a1f70bcd3f37629e918f6bb3a7713";
const char* kG_mm = "448434e63d1b441cd2831302829bdda55da8d2da82e8ca0604928044e21a3907";

struct GoldenOut {
    unsigned      role;
    std::uint64_t amount;
    const char*   P;
    unsigned char vt;
};
const GoldenOut kG_outs[] = {
    // K_fair oldest-owed-first: e2 (first_eligible 90) before e1 (100).
    {0u, 7250000000ull,   "f932749f44bdfd62c3fb2c8ddf75f5843166aebb8bde989d96285759e7cf3fd0", 0x98},
    {0u, 41000000000ull,  "871863287ca6ef05cdea83f894b23ac90e09cf224ebc3a3ab56d26163460866a", 0x82},
    {1u, 3000000000ull,   "e7c3f349bbf28f7c8c50e29a72920aa46dccc5d6d2075b0d0b5bd123b525b0c0", 0x46},
    {2u, 548780414082ull, "ae9a7dd47cf835768e7fcde5a00d3d7db03a22ed3bb721f389df98c21ac6a952", 0xf3},
};
const std::size_t kG_nout = sizeof(kG_outs) / sizeof(kG_outs[0]);

const char* kG_tx_extra =
    "014ee5f6c2004eb10bbb9ca46fb1f33e17577a1f70bcd3f37629e918f6bb3a7713"
    "0210000102030405060708090a0b0c0d0e0f"
    "032100448434e63d1b441cd2831302829bdda55da8d2da82e8ca0604928044e21a3907";

const char* kG_prefix =
    "02fcc2cf0101ffc0c2cf010480f188811b03"
    "f932749f44bdfd62c3fb2c8ddf75f5843166aebb8bde989d96285759e7cf3fd098"
    "80b4a9de980103"
    "871863287ca6ef05cdea83f894b23ac90e09cf224ebc3a3ab56d26163460866a82"
    "80bcc1960b03"
    "e7c3f349bbf28f7c8c50e29a72920aa46dccc5d6d2075b0d0b5bd123b525b0c046"
    "82a9f2aefc0f03"
    "ae9a7dd47cf835768e7fcde5a00d3d7db03a22ed3bb721f389df98c21ac6a952f3"
    "56"
    "014ee5f6c2004eb10bbb9ca46fb1f33e17577a1f70bcd3f37629e918f6bb3a7713"
    "0210000102030405060708090a0b0c0d0e0f"
    "032100448434e63d1b441cd2831302829bdda55da8d2da82e8ca0604928044e21a3907";

const char* kG_prefix_hash = "24cd8c5c1701f464a90118dde8a07b6704a18f7b84a5144331169d02a31d0b51";
const char* kG_tx_hash     = "a2a6224b95eb8f53f45ab12b5f33355c21ab9d671440a9da9226b049771253a9";

// A refusal must be TOTAL: no outputs, no keys, no serialized bytes. A builder
// that returns ok=false while leaving a half-filled transaction behind is a trap
// for any caller that checks the wrong field.
bool refusal_is_total(const BuiltCoinbase& b) {
    return !b.ok
        && b.error == BuildError::CarrotFence
        && b.outputs.empty()
        && b.tx_extra.empty()
        && b.prefix.empty();
}

// ---- compile-time half of the contract ------------------------------------
static_assert(W5_PRECARROT_MAX_MAJOR_VERSION == 16,
              "pre-CARROT fence must stay at mainnet v16");
static_assert(W5_CARROT_MIN_MAJOR_VERSION == 17,
              "CARROT regime must begin at v17");
static_assert(W5_CARROT_MIN_MAJOR_VERSION == W5_PRECARROT_MAX_MAJOR_VERSION + 1,
              "there must be exactly one regime boundary");
static_assert(!carrot::DERIVATION_IMPLEMENTED,
              "no conformant CARROT derivation exists; the fence must not lift");
static_assert(!carrot::conformant(), "carrot::conformant() must track the scaffold");
static_assert(!carrot::UPSTREAM_FORK_PINNED,
              "monero-project has not tagged a CARROT release");
static_assert(coinbase_regime(16) == CoinbaseRegime::PreCarrot, "v16 is pre-CARROT");
static_assert(coinbase_regime(17) == CoinbaseRegime::Carrot, "v17 is CARROT");
static_assert(coinbase_regime(255) == CoinbaseRegime::Carrot, "v255 is CARROT");

} // namespace

// ---------------------------------------------------------------------------
int main() {
    std::printf("=== X6b CARROT version-gate KAT ===\n");

    // -----------------------------------------------------------------------
    std::printf("\n== 1. v16 pre-CARROT coinbase is BYTE-IDENTICAL to the pre-gate tree ==\n");
    {
        CoinbaseInputs in = golden_inputs_v16();
        BuiltCoinbase b = build_coinbase(in);

        CHECK(b.ok, "v16 builds (error=%s detail=%s)", to_string(b.error), b.detail.c_str());
        if (!b.ok) { std::printf("\nX6b CARROT GATE KAT FAILED (%d)\n", g_fail + 1); return 1; }

        CHECK(b.budget == kG_budget, "budget == %llu", (unsigned long long)kG_budget);
        CHECK(hx(b.r) == kG_r, "deterministic tx secret key r == golden");
        CHECK(hx(b.R) == kG_R, "tx pubkey R = r*G == golden");
        CHECK(hx(b.mm_root) == kG_mm, "merge-mining root (tx_extra 0x03 leaf) == golden");
        CHECK(b.outputs.size() == kG_nout, "output count == %zu", kG_nout);

        if (b.outputs.size() == kG_nout) {
            for (std::size_t i = 0; i < kG_nout; ++i) {
                CHECK(static_cast<unsigned>(b.outputs[i].role) == kG_outs[i].role,
                      "vout %zu role == %u", i, kG_outs[i].role);
                CHECK(b.outputs[i].amount == kG_outs[i].amount,
                      "vout %zu amount == %llu", i, (unsigned long long)kG_outs[i].amount);
                CHECK(hx(b.outputs[i].one_time_key) == kG_outs[i].P,
                      "vout %zu one-time key P_i == golden", i);
                CHECK(b.outputs[i].view_tag.tag == kG_outs[i].vt,
                      "vout %zu view tag == %02x", i, (unsigned)kG_outs[i].vt);
            }
        }

        CHECK(hex(b.tx_extra.data(), b.tx_extra.size()) == kG_tx_extra,
              "tx_extra (0x01 R || 0x02 nonce || 0x03 MM) == golden (%zu B)", b.tx_extra.size());
        CHECK(hex(b.prefix.data(), b.prefix.size()) == kG_prefix,
              "serialized miner_tx prefix == golden (%zu B)", b.prefix.size());
        CHECK(hx(b.prefix_hash) == kG_prefix_hash, "prefix hash == golden");
        CHECK(hx(b.coinbase_tx_hash) == kG_tx_hash, "coinbase tx hash == golden");

        // Exact-sum is consensus on Monero since HF13; restate it here so a
        // golden refresh can never quietly accept a burning coinbase.
        std::uint64_t sum = 0;
        for (const auto& o : b.outputs) sum += o.amount;
        CHECK(sum == b.budget, "exact-sum: Sum(vout) == base_reward + fees (no burn)");

        // The gate must be transparent: the dispatcher and the arm agree byte
        // for byte on a v16 block.
        BuiltCoinbase direct = build_coinbase_precarrot(in);
        CHECK(direct.ok && direct.prefix == b.prefix && hx(direct.R) == hx(b.R),
              "build_coinbase(v16) == build_coinbase_precarrot(v16), byte for byte");
    }

    // -----------------------------------------------------------------------
    std::printf("\n== 2. regime classification is total, with ONE boundary ==\n");
    {
        int boundaries = 0;
        bool consistent = true;
        for (int v = 0; v <= 255; ++v) {
            const std::uint8_t mv = static_cast<std::uint8_t>(v);
            const CoinbaseRegime reg = coinbase_regime(mv);
            const bool pre = (reg == CoinbaseRegime::PreCarrot);
            if (pre != (mv <= W5_PRECARROT_MAX_MAJOR_VERSION)) consistent = false;
            if (v > 0 && reg != coinbase_regime(static_cast<std::uint8_t>(v - 1)))
                ++boundaries;
        }
        CHECK(consistent, "PreCarrot iff major_version <= %u, over all 256 values",
              (unsigned)W5_PRECARROT_MAX_MAJOR_VERSION);
        CHECK(boundaries == 1, "exactly one regime boundary in 0..255 (found %d)", boundaries);
        CHECK(coinbase_regime(16) == CoinbaseRegime::PreCarrot, "v16 -> PreCarrot");
        CHECK(coinbase_regime(17) == CoinbaseRegime::Carrot, "v17 -> Carrot");
    }

    // -----------------------------------------------------------------------
    std::printf("\n== 3. the CARROT regime STILL FAILS CLOSED (fence not lifted) ==\n");
    {
        CoinbaseInputs in = golden_inputs_v16();
        int refused = 0, total = 0;
        for (int v = W5_CARROT_MIN_MAJOR_VERSION; v <= 255; ++v) {
            CoinbaseInputs c = in;
            c.monero_major_version = static_cast<std::uint8_t>(v);
            BuiltCoinbase b = build_coinbase(c);
            ++total;
            if (refusal_is_total(b)) ++refused;
        }
        CHECK(refused == total, "every major_version 17..255 refused, nothing emitted (%d/%d)",
              refused, total);

        CoinbaseInputs v17 = in; v17.monero_major_version = 17;
        BuiltCoinbase b17 = build_coinbase(v17);
        CHECK(b17.error == BuildError::CarrotFence,
              "v17 error is CarrotFence (%s)", to_string(b17.error));
        CHECK(b17.detail.find("CARROT_FENCE") != std::string::npos,
              "v17 detail still greps as CARROT_FENCE");
        CHECK(b17.detail.find("SCAFFOLD") != std::string::npos,
              "v17 detail names the scaffold, so an operator sees WHY");
        CHECK(b17.detail.find("xmr_carrot.hpp") != std::string::npos,
              "v17 detail points at the seam file");
    }

    // -----------------------------------------------------------------------
    std::printf("\n== 4. each arm refuses on its own, not only via the dispatcher ==\n");
    {
        CoinbaseInputs in = golden_inputs_v16();

        CoinbaseInputs v17 = in; v17.monero_major_version = 17;
        BuiltCoinbase pre17 = build_coinbase_precarrot(v17);
        CHECK(refusal_is_total(pre17),
              "build_coinbase_precarrot(v17) refuses: the old recipe cannot reach a CARROT block");

        // The CARROT arm is a scaffold, so it refuses for ANY version -- calling
        // it on a v16 block must not accidentally produce a pre-CARROT coinbase.
        BuiltCoinbase car16 = build_coinbase_carrot(in);
        CHECK(refusal_is_total(car16),
              "build_coinbase_carrot(v16) refuses too: the scaffold never builds");
        CHECK(car16.budget == kG_budget, "the refusing arm still reports the budget it was asked for");
    }

    // -----------------------------------------------------------------------
    std::printf("\n== 5. the CARROT derivation seam refuses and fills nothing ==\n");
    {
        carrot::CarrotCoinbaseRequest req;
        req.pay = ref_of(kP_B, kP_A);
        req.amount = 41000000000ull;
        req.height = 3400000;
        for (std::size_t i = 0; i < carrot::ANCHOR_LEN; ++i)
            req.anchor_norm[i] = static_cast<unsigned char>(i + 1);

        carrot::CarrotCoinbaseEnote enote;
        // Pre-dirty the destination so "filled nothing" is a real assertion.
        std::memset(enote.onetime_address.data(), 0xAB, 32);
        enote.amount = 123456;
        carrot::CarrotError err = carrot::CarrotError::None;

        bool got = carrot::derive_coinbase_enote(req, enote, &err);
        CHECK(!got, "derive_coinbase_enote() refuses");
        CHECK(err == carrot::CarrotError::NotImplemented,
              "reported as NotImplemented (%s)", carrot::to_string(err));
        bool zeroed = (enote.amount == 0);
        for (int i = 0; i < 32; ++i) if (enote.onetime_address.data()[i] != 0) zeroed = false;
        for (std::size_t i = 0; i < carrot::VIEW_TAG_LEN; ++i) if (enote.view_tag[i] != 0) zeroed = false;
        for (std::size_t i = 0; i < carrot::D_E_LEN; ++i) if (enote.ephemeral_pubkey[i] != 0) zeroed = false;
        CHECK(zeroed, "the refused enote is wiped, not left half-built");

        unsigned char anchor[carrot::ANCHOR_LEN];
        std::memset(anchor, 0xCD, sizeof(anchor));
        carrot::CarrotError aerr = carrot::CarrotError::None;
        bool agot = carrot::derive_deterministic_anchor(req.pay, req.height, id_of(0x27),
                                                        anchor, &aerr);
        CHECK(!agot, "derive_deterministic_anchor() refuses (it is an operator ruling, not a transcription)");
        CHECK(aerr == carrot::CarrotError::NotImplemented, "reported as NotImplemented");
        bool azero = true;
        for (std::size_t i = 0; i < carrot::ANCHOR_LEN; ++i) if (anchor[i] != 0) azero = false;
        CHECK(azero, "the refused anchor is wiped");

        CHECK(!carrot::DERIVATION_IMPLEMENTED, "carrot::DERIVATION_IMPLEMENTED is false");
        CHECK(!carrot::conformant(), "carrot::conformant() is false");
        CHECK(!carrot::UPSTREAM_FORK_PINNED, "upstream has not pinned the CARROT fork");
        CHECK(std::strstr(carrot::seam_status(), "SCAFFOLD") != nullptr,
              "seam_status() says SCAFFOLD out loud");
    }

    // -----------------------------------------------------------------------
    std::printf("\n== 6. fence constants, including the CANON descriptor fence ==\n");
    {
        CHECK(W5_PRECARROT_MAX_MAJOR_VERSION == 16, "W5 pre-CARROT max == 16");
        CHECK(W5_CARROT_MIN_MAJOR_VERSION == 17, "W5 CARROT min == 17");
        // The consumer fence is DERIVED from canon; assert canon itself is
        // unmoved, because lifting it is an operator ruling this wave did not
        // make and must not have made by accident.
        CHECK(::v37::xmr::XMR_PRECARROT_MAX_MAJOR_VERSION == 16,
              "CANON descriptor fence XMR_PRECARROT_MAX_MAJOR_VERSION still 16");
        CHECK(W5_PRECARROT_MAX_MAJOR_VERSION == ::v37::xmr::XMR_PRECARROT_MAX_MAJOR_VERSION,
              "the consumer fence tracks canon exactly");
        CHECK(::v37::xmr::xmr_precarrot_ok(16), "canon: v16 ok");
        CHECK(!::v37::xmr::xmr_precarrot_ok(17), "canon: v17 fenced");
        CHECK(carrot::CARROT_EXPECTED_MAJOR_VERSION == W5_CARROT_MIN_MAJOR_VERSION,
              "the expected CARROT fork number and the regime boundary agree");
    }

    // -----------------------------------------------------------------------
    std::printf("\n== 7. downstream refusals are unchanged by the gate ==\n");
    {
        CoinbaseInputs v17 = golden_inputs_v16();
        v17.monero_major_version = 17;

        ::xmr::coin::SecretKey r{};
        std::memset(r.data(), 0x5A, 32);
        CHECK(!derive_tx_secret_key(v17, r), "derive_tx_secret_key(v17) still refuses");
        bool untouched = true;
        for (int i = 0; i < 32; ++i) if (r.data()[i] != 0x5A) untouched = false;
        CHECK(untouched, "the refused tx secret key was not written");

        ReceivedCoinbase got;   // contents irrelevant: the rebuild must fail first
        MatchResult m = canonical_coinbase_matches(v17, got);
        CHECK(!m.matches && m.first_bad_index == IDX_BUILD,
              "ACCEPT re-derivation at v17 fails at IDX_BUILD (%d)", m.first_bad_index);

        // ... and the v16 ACCEPT path still round-trips through the gate.
        CoinbaseInputs in = golden_inputs_v16();
        BuiltCoinbase b = build_coinbase(in);
        ReceivedCoinbase ok16;
        ok16.R = b.R;
        ok16.tx_extra = b.tx_extra;
        for (const auto& o : b.outputs) {
            ok16.amounts.push_back(o.amount);
            ok16.keys.push_back(o.one_time_key);
            ok16.view_tags.push_back(o.view_tag);
        }
        MatchResult m16 = canonical_coinbase_matches(in, ok16);
        CHECK(m16.matches, "v16 ACCEPT still matches its own canonical rebuild (%s)",
              m16.reason.c_str());
    }

    std::printf("\n%s (%d failures)\n",
                g_fail ? "X6b CARROT GATE KAT FAILED" : "X6b CARROT GATE KAT OK", g_fail);
    return g_fail ? 1 : 0;
}
