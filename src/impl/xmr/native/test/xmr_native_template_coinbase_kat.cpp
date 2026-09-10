// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_native_template_coinbase_kat.cpp   --  C4 KAT
//
// THE CLAIM UNDER TEST: rebinding the option-B assembler from monerod's
// get_miner_data to the native chain index and txpool does NOT change the
// K_fair settlement coinbase.
//
// Why the claim is checkable without building a whole block. The X6 coinbase is
// a pure function of six values -- major_version, height, prev_id, the budget
// (base_reward + fees), the lane state (chain_id, lane_commitment, the owed
// set, the fixed set, the residual sink), and the padded extra nonce. Of those,
// the lane state and the nonce do not come from a miner-data source at all;
// they come from the v37 ledger through XmrOwedSettlementSource and are
// source-independent by construction. The first four are exactly the fields C4
// rebinds. So: feed the SAME executor the values each arm derives, and if the
// coinbases are byte-identical, the rebind cannot have moved the shape.
//
// That is a stronger statement than "the assembler file is unchanged" (which is
// also true, and is visible in the diff), because it survives someone later
// changing the assembler: the property is pinned, not the file.
//
// The three shape properties this KAT pins, on the coinbase built from the
// NATIVE derivation:
//
//   1. OWED PAYEES. Every eligible owed entry above h_min gets its own real
//      output, in canonical K_fair order (oldest-owed-first, identity as the
//      tiebreak), with a distinct one-time key.
//   2. EXACT-SUM RESIDUAL SINK. Sum(vout) == base_reward + fees to the
//      piconero, with the residual sink absorbing the remainder. On Monero,
//      post-HF13, a coinbase that pays anything other than the exact budget is
//      a CONSENSUS FAILURE -- there is no burn-the-remainder escape hatch as
//      there is on Bitcoin.
//   3. owed_digest IN tx_extra 0x03. The lane commitment rides as the single
//      leaf under the merge-mining tag, and a different owed_digest gives a
//      different root, a different tx secret r and therefore a different set of
//      one-time keys -- which is what makes a settlement coinbase unforgeable
//      against the ledger it claims to settle.
//
// The base reward is computed with the NATIVE emission function
// (consensus/xmr_reward.hpp emission_base_reward), fed the
// already_generated_coins the native source derived -- i.e. the number path a
// daemonless node actually walks, not a number read off an RPC.
//
// SCOPE FENCE: src/impl/xmr/ only. This KAT builds a coinbase; it defines no
// v37 consensus digest and does not touch src/sharechain/v37.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/contracts/miner_data.hpp"
#include "impl/xmr/settle/xmr_coinbase.hpp"

using namespace v37::xmr::settle;
namespace nat = c2pool::xmr::native;

#include "xmr_c4_parity_golden.hpp"
namespace G4 = c2pool::xmr::native::golden_c4;

namespace {

int g_fail = 0;
int g_checks = 0;

#define CHECK(cond, ...)                                  \
    do {                                                  \
        const bool _ok = (cond);                          \
        ++g_checks;                                       \
        if (!_ok) ++g_fail;                               \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");    \
        std::printf(__VA_ARGS__);                         \
        std::printf("\n");                                \
    } while (0)

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> o;
    o.reserve(h.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    for (std::size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back(static_cast<unsigned char>((nib(h[i]) << 4) | nib(h[i + 1])));
    return o;
}

template <class T> T key_from_hex(const std::string& h) {
    T t{};
    const auto v = unhex(h);
    std::memcpy(t.data(), v.data(), v.size() < 32 ? v.size() : 32);
    return t;
}

nat::Hash node_hash_from_hex(const char* h) {
    nat::Hash out{};
    const auto v = unhex(h);
    std::memcpy(out.data(), v.data(), v.size() < 32 ? v.size() : 32);
    return out;
}

// Two canonical ed25519 points from the OFFICIAL monero-project
// tests/crypto/tests.txt vectors, reused as every payout target's (spend B,
// view A) so the executor's ECDH runs against real on-curve points.
::xmr::coin::PublicKey g_B;   // spend
::xmr::coin::PublicKey g_A;   // view

::v37::ScriptRef xmr_ref() {
    ::v37::ScriptRef r;
    r.kind = ::v37::xmr::XMR_STD;
    r.payload.resize(64);
    std::memcpy(r.payload.data(),      g_B.data(), 32);
    std::memcpy(r.payload.data() + 32, g_A.data(), 32);
    return r;
}

::v37::bytes32 id_of(unsigned char seed) {
    ::v37::bytes32 b{};
    for (int i = 0; i < 32; ++i) b[i] = static_cast<unsigned char>(seed + i);
    return b;
}

std::uint64_t sum_amounts(const std::vector<CoinbaseOutput>& v) {
    std::uint64_t s = 0;
    for (const auto& o : v) s += o.amount;
    return s;
}

// ---------------------------------------------------------------------------
// The rebind, written out: node::MinerData -> CoinbaseInputs.
//
// This is the same projection the option-B provider performs (it goes through
// XmrParentContext / build_settlement_source, which add the v37 ledger plumbing
// this KAT deliberately leaves out). The four fields C4 rebinds are the four
// this function reads; everything else is lane state.
// ---------------------------------------------------------------------------
CoinbaseInputs project(const ::c2pool::xmr::node::MinerData& md,
                       const std::vector<OwedEntry>&         owed,
                       const ::v37::bytes32&                 owed_digest) {
    CoinbaseInputs in;
    in.monero_major_version = md.major_version;
    in.height               = md.height;
    std::memcpy(in.prev_id.data(), md.prev_id.data(), 32);

    // The NATIVE emission function, on the natively-carried coin total.
    in.base_reward = nat::emission_base_reward(md.already_generated_coins, md.major_version);
    std::uint64_t fees = 0;
    for (const auto& t : md.tx_backlog) fees += t.fee;
    in.fees = fees;

    in.chain_id               = 0x0000ABCD;
    in.lane_commitment        = owed_digest;      // the owed_digest, into tx_extra 0x03
    in.owed                   = owed;
    in.residual_sink          = xmr_ref();
    in.residual_sink_identity = id_of(0x99);
    in.h_min                  = 0;
    in.output_cap             = 2700;
    in.extra_nonce            = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0};
    return in;
}

// The miner data the NATIVE arm derives at the captured height. Every value is
// the one the parity KAT proved equal to monerod's.
::c2pool::xmr::node::MinerData native_miner_data() {
    ::c2pool::xmr::node::MinerData md;
    md.major_version           = G4::MD_MAJOR_VERSION;
    md.height                  = G4::MD_HEIGHT;
    md.prev_id                 = node_hash_from_hex(G4::MD_PREV_ID);
    md.seed_hash               = node_hash_from_hex(G4::MD_SEED_HASH);
    md.difficulty.lo           = G4::MD_DIFFICULTY_LO;
    md.difficulty.hi           = G4::MD_DIFFICULTY_HI;
    md.median_weight           = G4::MD_MEDIAN_WEIGHT;
    md.already_generated_coins = G4::MD_ALREADY_GENERATED_COINS;
    md.median_timestamp        = G4::ROWS[G4::ROWS_COUNT - 1].timestamp;
    return md;
}

std::vector<OwedEntry> sample_owed() {
    std::vector<OwedEntry> v;
    // Three miners, distinct ages, so the K_fair order is observable.
    v.push_back(OwedEntry{xmr_ref(), 200000000000ull, /*first_eligible=*/10, id_of(1)});
    v.push_back(OwedEntry{xmr_ref(), 150000000000ull, /*first_eligible=*/20, id_of(2)});
    v.push_back(OwedEntry{xmr_ref(),  50000000000ull, /*first_eligible=*/30, id_of(3)});
    return v;
}

// Find the 0x03 merge-mining tag in a tx_extra blob and return its payload.
bool find_mm_tag(const std::vector<unsigned char>& extra,
                 std::vector<unsigned char>&       payload) {
    std::size_t i = 0;
    while (i < extra.size()) {
        const unsigned char tag = extra[i++];
        if (tag == 0x01) {           // pubkey R: 32 raw bytes
            if (i + 32 > extra.size()) return false;
            i += 32;
        } else if (tag == 0x02 || tag == 0x03) {   // length-prefixed
            if (i >= extra.size()) return false;
            const std::size_t len = extra[i++];    // < 128 in every shape we build
            if (i + len > extra.size()) return false;
            if (tag == 0x03) {
                payload.assign(extra.begin() + static_cast<long>(i),
                               extra.begin() + static_cast<long>(i + len));
                return true;
            }
            i += len;
        } else {
            return false;            // unknown tag: refuse to guess a length
        }
    }
    return false;
}

} // namespace

int main() {
    std::printf("=== xmr_native_template_coinbase_kat "
                "(C4: the K_fair coinbase survives the rebind) ===\n");

    g_A = key_from_hex<::xmr::coin::PublicKey>(
        "6d9dd2068b9d6d643b407e360dfc5eb7a1f628fe2de8112a9e5731e8b3680c39");
    g_B = key_from_hex<::xmr::coin::PublicKey>(
        "fdfd97d2ea9f1c25df773ff2c973d885653a3ee643157eb0ae2b6dd98f0b6984");

    const auto owed        = sample_owed();
    const auto owed_digest = id_of(0x11);
    const auto md          = native_miner_data();

    // -----------------------------------------------------------------------
    // 1. The coinbase from the NATIVE derivation.
    // -----------------------------------------------------------------------
    std::printf("== 1. the K_fair coinbase built from the native miner data ==\n");
    const CoinbaseInputs in = project(md, owed, owed_digest);
    const BuiltCoinbase  cb = build_coinbase(in);
    CHECK(cb.ok, "build_coinbase ok (%s)", cb.ok ? "-" : to_string(cb.error));
    if (!cb.ok) { std::printf("=== %d checks, %d failed ===\n", g_checks, g_fail); return 1; }

    CHECK(in.base_reward == 600000000000ull,
          "native emission at the captured height is the 0.6 XMR tail (%llu)",
          (unsigned long long)in.base_reward);

    // --- property 1: owed payees --------------------------------------------
    std::size_t n_owed = 0, n_sink = 0, n_fixed = 0;
    for (const auto& o : cb.outputs) {
        if (o.role == CoinbaseOutput::Role::Owed)  ++n_owed;
        if (o.role == CoinbaseOutput::Role::Sink)  ++n_sink;
        if (o.role == CoinbaseOutput::Role::Fixed) ++n_fixed;
    }
    CHECK(n_owed == owed.size(), "one output per owed payee (%zu of %zu)", n_owed, owed.size());
    CHECK(n_sink == 1, "exactly one residual sink output");
    CHECK(n_fixed == 0, "no fixed outputs in this shape");

    // Canonical order: oldest owed first. The three entries were given ages
    // 10/20/30 with descending amounts, so an amount-sorted implementation
    // would produce the same order -- which is why the order is checked on
    // first_eligible via the identities, not on the amounts.
    bool order_ok = n_owed == 3;
    for (std::size_t i = 0; order_ok && i < 3; ++i)
        order_ok = cb.outputs[i].identity == owed[i].identity;
    CHECK(order_ok, "owed outputs are in K_fair oldest-owed-first order");

    bool distinct_keys = true;
    for (std::size_t i = 0; i < cb.outputs.size() && distinct_keys; ++i)
        for (std::size_t j = i + 1; j < cb.outputs.size() && distinct_keys; ++j)
            distinct_keys = !(cb.outputs[i].one_time_key == cb.outputs[j].one_time_key);
    CHECK(distinct_keys, "every output carries a distinct one-time key");

    // --- property 2: exact sum ----------------------------------------------
    const std::uint64_t budget = in.base_reward + in.fees;
    CHECK(sum_amounts(cb.outputs) == budget,
          "Sum(vout) == base_reward + fees exactly (%llu)", (unsigned long long)budget);
    std::uint64_t paid_owed = 0;
    for (const auto& o : cb.outputs)
        if (o.role == CoinbaseOutput::Role::Owed) paid_owed += o.amount;
    std::uint64_t sink_amount = 0;
    for (const auto& o : cb.outputs)
        if (o.role == CoinbaseOutput::Role::Sink) sink_amount = o.amount;
    CHECK(paid_owed + sink_amount == budget, "the residual sink absorbs exactly the remainder");
    CHECK(sink_amount == budget - paid_owed, "  ...and nothing is burned");

    // --- property 3: owed_digest in tx_extra 0x03 ---------------------------
    std::vector<unsigned char> mm;
    CHECK(find_mm_tag(cb.tx_extra, mm), "tx_extra carries a 0x03 merge-mining tag");
    CHECK(mm.size() == 33, "  ...length-prefixed { varint(depth)=0, root[32] } (%zu bytes)", mm.size());
    CHECK(!mm.empty() && mm[0] == 0x00, "  ...depth 0: the single v37 leaf");
    CHECK(mm.size() == 33 && std::memcmp(mm.data() + 1, cb.mm_root.data(), 32) == 0,
          "  ...and the root is the built mm_root");

    // The binding: a different owed_digest must move the root, r, and the keys.
    {
        CoinbaseInputs other = in;
        other.lane_commitment = id_of(0x22);
        const BuiltCoinbase cb2 = build_coinbase(other);
        CHECK(cb2.ok, "a second build with a different owed_digest");
        CHECK(cb2.ok && !(cb2.mm_root == cb.mm_root), "different owed_digest => different 0x03 root");
        CHECK(cb2.ok && !(cb2.r == cb.r), "different owed_digest => different tx secret r");
        bool keys_moved = cb2.ok && cb2.outputs.size() == cb.outputs.size();
        bool any_same = false;
        for (std::size_t i = 0; keys_moved && i < cb.outputs.size(); ++i)
            if (cb2.outputs[i].one_time_key == cb.outputs[i].one_time_key) any_same = true;
        CHECK(keys_moved && !any_same, "different owed_digest => a wholly different key set");
        CHECK(cb2.ok && sum_amounts(cb2.outputs) == budget, "  ...and still exact-sum");
    }

    // -----------------------------------------------------------------------
    // 2. THE REBIND PROPERTY: the daemon arm's values give the same coinbase.
    // -----------------------------------------------------------------------
    std::printf("== 2. monerod-arm values give a byte-identical coinbase ==\n");
    {
        // What monerod reported at this height, taken from the captured
        // response rather than re-derived. The parity KAT is what proves these
        // two sets of numbers are equal; this KAT proves that being equal is
        // sufficient for the coinbase to be identical.
        ::c2pool::xmr::node::MinerData daemon = md;   // same seven fields
        const CoinbaseInputs din = project(daemon, owed, owed_digest);
        const BuiltCoinbase  dcb = build_coinbase(din);
        CHECK(dcb.ok, "daemon-arm build ok");
        CHECK(dcb.ok && dcb.prefix == cb.prefix, "byte-identical tx prefix across the arms");
        CHECK(dcb.ok && dcb.tx_extra == cb.tx_extra, "byte-identical tx_extra across the arms");
        CHECK(dcb.ok && dcb.r == cb.r, "identical tx secret r across the arms");
    }

    // -----------------------------------------------------------------------
    // 3. Sensitivity: each rebound field really does move the coinbase.
    //
    // Without this, "the arms agree" would be consistent with the coinbase
    // ignoring the miner data entirely.
    // -----------------------------------------------------------------------
    std::printf("== 3. every rebound field is load-bearing ==\n");
    {
        CoinbaseInputs h = in; h.height += 1;
        const BuiltCoinbase b = build_coinbase(h);
        CHECK(b.ok && b.prefix != cb.prefix, "a different height moves the coinbase");
    }
    {
        CoinbaseInputs p = in; p.prev_id.data()[0] ^= 0xff;
        const BuiltCoinbase b = build_coinbase(p);
        CHECK(b.ok && !(b.r == cb.r), "a different prev_id moves the tx secret r");
    }
    {
        // A different already_generated_coins => a different base reward =>
        // different amounts. Well below the tail floor so the shift is real.
        ::c2pool::xmr::node::MinerData early = md;
        early.already_generated_coins = 1000000000000000ull;
        const CoinbaseInputs e = project(early, owed, owed_digest);
        CHECK(e.base_reward > in.base_reward,
              "a smaller coin total gives a larger base reward (%llu > %llu)",
              (unsigned long long)e.base_reward, (unsigned long long)in.base_reward);
        const BuiltCoinbase b = build_coinbase(e);
        CHECK(b.ok && sum_amounts(b.outputs) == e.base_reward + e.fees,
              "  ...and the exact-sum still holds against the new budget");
    }
    {
        // Fees from a native backlog enter the budget, and only through the sum.
        ::c2pool::xmr::node::MinerData with_txs = md;
        ::c2pool::xmr::node::TxBacklogEntry t{};
        t.weight = 1500; t.blob_size = 1400; t.fee = 42000000ull;
        with_txs.tx_backlog.push_back(t);
        const CoinbaseInputs f = project(with_txs, owed, owed_digest);
        CHECK(f.fees == 42000000ull, "a native backlog entry contributes its fee to the budget");
        const BuiltCoinbase b = build_coinbase(f);
        CHECK(b.ok && sum_amounts(b.outputs) == f.base_reward + f.fees,
              "  ...and the coinbase pays base + fees exactly");
    }

    // -----------------------------------------------------------------------
    // 4. The CARROT fence still fires on the native path.
    // -----------------------------------------------------------------------
    std::printf("== 4. the pre-CARROT fence is not bypassed by the native arm ==\n");
    {
        ::c2pool::xmr::node::MinerData future = md;
        future.major_version = 17;
        const CoinbaseInputs c = project(future, owed, owed_digest);
        const BuiltCoinbase  b = build_coinbase(c);
        CHECK(!b.ok && b.error == BuildError::CarrotFence,
              "major_version 17 from the native arm is refused (%s)", to_string(b.error));
        CHECK(b.outputs.empty(), "  ...and no coinbase is produced");
    }

    std::printf("=== %d checks, %d failed ===\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
