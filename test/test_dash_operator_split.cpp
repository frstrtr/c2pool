// SPDX-License-Identifier: AGPL-3.0-or-later
//
// ═══════════════════════════════════════════════════════════════════════════
// DASH masternode operator-reward split — incident h=2516595 KATs
// ═══════════════════════════════════════════════════════════════════════════
//
// INCIDENT (2026-08-05, production, binary ca5c9469): the FIRST block ever
// mined on an embedded daemonless template (h=2516595, pow 0…0d08e71b…) was
// REJECTED by dashd with bad-cb-payee. The scheduled masternode
// (proRegTxHash 0037c2c5…) has an 8% operator-reward split registered via
// ProTx; dashd's canonical coinbase pays TWO MN outputs
//     0.76413304 → XoDo3w4ZUqn93uL3FeRNb9fgfXvgg7BvDC   (owner)
//     0.06644635 → Xnem6ejaXAfKDTh5PFGSa9ozMQNMY6bvs7   (operator)
// while the embedded builder paid the ENTIRE share to the owner script.
// CheckMasternodePayments validates the full payout set (scripts AND
// amounts) → deterministic rejection → a lost won block.
//
// The split data was IN the shipped daemonless state the whole time: the
// mainnet checkpoint anchor (2513000) carries mn 0037c2c5… with bps=800 and
// both scripts; the omission was in the consumer (the builder), not the
// data. These KATs pin, against dashd masternode/payments.cpp
// GetBlockTxOuts (verbatim, v20.1.1):
//
//     CAmount operatorReward = 0;
//     if (dmnPayee->nOperatorReward != 0
//         && dmnPayee->pdmnState->scriptOperatorPayout != CScript()) {
//         operatorReward = (masternodeReward * dmnPayee->nOperatorReward) / 10000;
//         masternodeReward -= operatorReward;
//     }
//     if (masternodeReward > 0) emplace_back(masternodeReward, scriptPayout);
//     if (operatorReward > 0)   emplace_back(operatorReward, scriptOperatorPayout);
//
// (a) the builder emits BOTH outputs with dashd-exact amounts (truncating
//     division, owner-first order) — KAT'd with the real h=2516595 values;
// (b) an UNPROVEN split refuses the embedded serve with its own named
//     cause (cause=mn-payout-split-unprovable value=protx=… threshold=
//     payout-set-known) at BOTH the viability gate and the pre-emit gate;
// (c) a proven zero split builds the single owner output exactly as before;
// (d) the state machine mirrors dashd ResetOperatorFields on operator-key
//     change (ProUpRegTx) and revocation (ProUpRevTx) — the stale operator
//     payout script must go with the key.
//
// All hermetic: no live node, amounts recomputed from the same closed-form
// integer arithmetic dashd uses.

#include <gtest/gtest.h>

#include <impl/dash/coin/embedded_gbt.hpp>
#include <impl/dash/coin/node_coin_state.hpp>
#include <impl/dash/coin/mn_checkpoint.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/mn_state_machine.hpp>
#include <impl/dash/coin/utxo_adapter.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/dash/coin/embedded_oracle_shadow.hpp>

#include <core/uint256.hpp>
#include <core/pack.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using dash::coin::MNState;
using dash::coin::MnStateMachine;
using dash::coin::Mempool;
using dash::coin::MutableTransaction;
using dash::coin::NodeCoinState;
using dash::coin::DashWorkData;
using dash::coin::PackedPayment;
using dash::coin::build_embedded_workdata;
using dash::coin::compute_dash_block_reward_post_v20;
using dash::coin::compute_dash_mn_payment_post_v20;
using dash::coin::compute_dash_platform_reward_post_v20_mn_rr;
using ::core::coin::UTXOViewCache;

// Dash mainnet base58 version bytes (chainparams.cpp PUBKEY_ADDRESS=76,
// SCRIPT_ADDRESS=16) — same constants the sibling embedded_gbt KATs use.
static constexpr uint8_t DASH_PUBKEY_VER = 76;
static constexpr uint8_t DASH_P2SH_VER   = 16;

// Past V20 + MN_RR, matching the mainnet steady state (and the incident).
static constexpr uint32_t H = 2'400'000;

// ─── incident h=2516595 ground truth (canonical, dashd-accepted) ──────────
// Canonical MN share = owner + operator output values of the accepted block.
static constexpr int64_t K_MN_SHARE   = 83'057'939;  // duffs
static constexpr int64_t K_OWNER_OUT  = 76'413'304;  // → XoDo3w4…
static constexpr int64_t K_OPER_OUT   =  6'644'635;  // → Xnem6ej…
static constexpr uint16_t K_BPS       = 800;         // 8.00% (ProRegTx)
// scriptPubKeys, base58check-decoded from the two canonical payout
// addresses (and byte-identical to checkpoint-anchor row 0037c2c5…).
static const std::vector<unsigned char> K_OWNER_SCRIPT = {
    0x76, 0xa9, 0x14, 0x89, 0x7c, 0x15, 0x1a, 0x6a, 0xa2, 0x35, 0xb7, 0x88,
    0x0f, 0xb7, 0xd3, 0x4d, 0xac, 0xac, 0xa1, 0x78, 0xca, 0x03, 0x95, 0x88,
    0xac};
static const std::vector<unsigned char> K_OPER_SCRIPT = {
    0x76, 0xa9, 0x14, 0x83, 0x3c, 0xb9, 0xad, 0x96, 0x45, 0x55, 0xc7, 0x80,
    0x50, 0xae, 0x92, 0xb6, 0x85, 0xde, 0x5c, 0x32, 0x20, 0x0f, 0xc9, 0x88,
    0xac};

static uint256 raw256(uint8_t base) {
    uint256 h;
    std::array<uint8_t, 32> p{};
    for (size_t i = 0; i < 32; ++i) p[i] = static_cast<uint8_t>(base + i);
    std::memcpy(h.data(), p.data(), 32);
    return h;
}

static MNState split_mn(uint16_t bps,
                        const std::vector<unsigned char>& owner,
                        const std::vector<unsigned char>& oper,
                        uint8_t provenance = MNState::SPLIT_KNOWN) {
    MNState s;
    s.isValid = true;
    s.nRegisteredHeight = 2'300'000;
    s.nLastPaidHeight = 0;
    s.scriptPayout.m_data = owner;
    s.nOperatorReward = bps;
    s.scriptOperatorPayout.m_data = oper;
    s.payoutSplitProvenance = provenance;
    return s;
}

static MnStateMachine machine_with(const MNState& s) {
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}});
    return m;
}

// The non-burn packed payments (the "!6a" OP_RETURN is the platform
// credit-pool burn, not an MN payment).
static std::vector<PackedPayment> mn_payments(const DashWorkData& w) {
    std::vector<PackedPayment> out;
    for (const auto& p : w.m_packed_payments)
        if (p.payee != "!6a") out.push_back(p);
    return out;
}

// Arm the SML posture the emit gate requires (it is a no-op while
// require_sml is off) — same minimal fixture the collateral-spend emit KAT
// uses: a fully-confirmed 1-entry SML current at the tip, so the ONLY
// defect the gate can find is the one under test.
static void arm_emit_gate(NodeCoinState& st, const uint256& prev_hash) {
    using dash::coin::vendor::CSimplifiedMNList;
    using dash::coin::vendor::CSimplifiedMNListEntry;
    std::vector<CSimplifiedMNListEntry> entries;
    CSimplifiedMNListEntry e;
    e.nVersion = CSimplifiedMNListEntry::VER_BASIC_BLS;
    e.proRegTxHash = raw256(0x01);
    e.confirmedHash = raw256(0x77);
    e.isValid = true;
    entries.push_back(e);
    st.set_require_sml(true);
    st.sml() = CSimplifiedMNList(std::move(entries));
    st.set_have_sml(true);
    st.set_sml_current_hash(prev_hash);
}

// ════════════════════════════════════════════════════════════════════════
// The split arithmetic itself — dashd GetBlockTxOuts, bit-exact
// ════════════════════════════════════════════════════════════════════════

TEST(DashOperatorSplit, SplitMathKatH2516595) {
    MNState s = split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    // floor(83'057'939 * 800 / 10000) = floor(6'644'635.12) = 6'644'635 —
    // the canonical operator output of the dashd-accepted block, truncating
    // division, NOT round-half-up (llround would give the same here; the
    // truncation edge is pinned separately below).
    EXPECT_EQ(s.operator_payment_of(K_MN_SHARE), K_OPER_OUT);
    EXPECT_EQ(K_MN_SHARE - s.operator_payment_of(K_MN_SHARE), K_OWNER_OUT);
}

TEST(DashOperatorSplit, SplitMathTruncatesLikeDashd) {
    MNState s = split_mn(1, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    // 9'999 * 1 / 10000 = 0.9999 → 0 (dashd's own comment: "might turn out
    // to result in 0"). No operator output may be emitted for it.
    EXPECT_EQ(s.operator_payment_of(9'999), 0);
    // One duff more crosses the boundary.
    EXPECT_EQ(s.operator_payment_of(10'000), 1);
}

TEST(DashOperatorSplit, SplitZeroWhenNoScriptOrNoBps) {
    // bps registered, operator script unset → dashd pays a single owner
    // output (the `scriptOperatorPayout != CScript()` guard).
    MNState no_script = split_mn(K_BPS, K_OWNER_SCRIPT, {});
    EXPECT_EQ(no_script.operator_payment_of(K_MN_SHARE), 0);
    // script set, bps == 0 → likewise single-output (the `nOperatorReward
    // != 0` guard; consensus additionally forbids this state on-chain).
    MNState no_bps = split_mn(0, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    EXPECT_EQ(no_bps.operator_payment_of(K_MN_SHARE), 0);
}

// ════════════════════════════════════════════════════════════════════════
// (a) the BUILDER emits both outputs, dashd-exact, owner first
// ════════════════════════════════════════════════════════════════════════

TEST(DashOperatorSplit, BuilderEmitsOwnerAndOperatorOutputs) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);   // empty template: subsidy-exact arithmetic

    auto mnstates = machine_with(split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT));

    auto w = build_embedded_workdata(
        /*prev_height=*/H - 1, raw256(0xAB), mnstates, mp,
        /*bits=*/0x1b104be3u, /*mtp=*/1'700'000'000u,
        DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Independent re-derivation of THIS height's MN share.
    const int64_t reward          = compute_dash_block_reward_post_v20(H);
    const int64_t platform_reward = compute_dash_platform_reward_post_v20_mn_rr(H);
    const int64_t mn_payment      = compute_dash_mn_payment_post_v20(reward)
                                    - platform_reward;
    ASSERT_GT(mn_payment, 0);
    const int64_t op_due  = (mn_payment * K_BPS) / 10000;   // dashd formula
    const int64_t own_due = mn_payment - op_due;
    ASSERT_GT(op_due, 0);

    const auto mn_outs = mn_payments(w);
    ASSERT_EQ(mn_outs.size(), 2u)
        << "h=2516595 defect: the builder must emit the operator output, "
           "not fold the whole share into the owner's";
    // dashd GetBlockTxOuts order: owner first, operator second.
    EXPECT_EQ(mn_outs[0].amount, static_cast<uint64_t>(own_due));
    EXPECT_EQ(mn_outs[1].amount, static_cast<uint64_t>(op_due));
    // Set-level conservation: split, not duplicated.
    EXPECT_EQ(mn_outs[0].amount + mn_outs[1].amount,
              static_cast<uint64_t>(mn_payment));
    EXPECT_EQ(w.m_payment_amount, static_cast<uint64_t>(mn_payment));
    // The canonical incident addresses, re-encoded from the scripts.
    EXPECT_EQ(mn_outs[0].payee, "XoDo3w4ZUqn93uL3FeRNb9fgfXvgg7BvDC");
    EXPECT_EQ(mn_outs[1].payee, "Xnem6ejaXAfKDTh5PFGSa9ozMQNMY6bvs7");
}

// (c) proven zero split → the single owner output, exactly as before.
TEST(DashOperatorSplit, BuilderSingleOutputWhenSplitKnownZero) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);

    auto mnstates = machine_with(split_mn(0, K_OWNER_SCRIPT, {}));
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    const auto mn_outs = mn_payments(w);
    ASSERT_EQ(mn_outs.size(), 1u);
    EXPECT_EQ(mn_outs[0].amount, w.m_payment_amount);
    EXPECT_EQ(mn_outs[0].payee, "XoDo3w4ZUqn93uL3FeRNb9fgfXvgg7BvDC");
}

// bps=10000 (a full-operator MN — one exists on mainnet at the checkpoint
// anchor): owner share is 0 → dashd's `if (masternodeReward > 0)` emits NO
// owner output; the single output is the operator's.
TEST(DashOperatorSplit, BuilderFullOperatorSplitOmitsZeroOwnerOutput) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);

    auto mnstates = machine_with(split_mn(10000, K_OWNER_SCRIPT, K_OPER_SCRIPT));
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    const auto mn_outs = mn_payments(w);
    ASSERT_EQ(mn_outs.size(), 1u);
    EXPECT_EQ(mn_outs[0].amount, w.m_payment_amount);
    EXPECT_EQ(mn_outs[0].payee, "Xnem6ejaXAfKDTh5PFGSa9ozMQNMY6bvs7");
}

// ════════════════════════════════════════════════════════════════════════
// (b) UNPROVEN split → REFUSED, with its own named cause
// ════════════════════════════════════════════════════════════════════════

TEST(DashOperatorSplit, UnprovableSplitRefusesServeWithNamedCause) {
    NodeCoinState st;
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
        {raw256(0x01),
         split_mn(0, K_OWNER_SCRIPT, {}, MNState::SPLIT_UNKNOWN)}});
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    ASSERT_TRUE(st.populated());

    // Guard ON (default posture): refuse, and say the cause's own name.
    auto e = st.make_embedded_work_inputs();
    ASSERT_FALSE(e.viable())
        << "an unproven payout split must refuse the embedded arm "
           "(h=2516595: serving it loses the won block to bad-cb-payee)";
    EXPECT_EQ(e.decline.cause, std::string("mn-payout-split-unprovable"));
    EXPECT_EQ(e.decline.value,
              "protx=" + raw256(0x01).GetHex().substr(0, 12));
    EXPECT_EQ(e.decline.threshold, std::string("payout-set-known"));
    // The greppable one-line marker discipline shared with the other gates.
    EXPECT_EQ(e.decline.one_line(),
              "cause=mn-payout-split-unprovable value=protx="
                  + raw256(0x01).GetHex().substr(0, 12)
                  + " threshold=payout-set-known");

    // NEGATIVE PASS — guard off reproduces the pre-fix fail-open.
    st.set_require_provable_payout_split(false);
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "guard-off must reproduce the incident posture (fail-open)";
    st.set_require_provable_payout_split(true);

    // CONTROL — same tip, same MN, split PROVEN → viable again.
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
        {raw256(0x01), split_mn(0, K_OWNER_SCRIPT, {})}});
    EXPECT_TRUE(st.make_embedded_work_inputs().viable())
        << "the gate must be provenance-specific, not a blanket refuse";
}

TEST(DashOperatorSplit, EmitGateMirrorsUnprovableSplit) {
    NodeCoinState st;
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
        {raw256(0x01),
         split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT,
                  MNState::SPLIT_UNKNOWN)}});
    arm_emit_gate(st, raw256(0xAB));
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), st.mnstates(), mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    dash::coin::DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(w, &why))
        << "a cached/bypassed template must be stopped at emit too";
    EXPECT_EQ(why.cause, std::string("emit-mn-payout-split-unprovable"));
    EXPECT_EQ(why.threshold, std::string("payout-set-known"));
}

// Defence in depth: a template whose MN payment IGNORES a proven split (the
// exact h=2516595 builder defect, resurrected via any future regression)
// must be rejected at emit by amount re-derivation.
TEST(DashOperatorSplit, EmitGateRejectsSplitDriftTemplate) {
    NodeCoinState st;
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
        {raw256(0x01), split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT)}});
    arm_emit_gate(st, raw256(0xAB));
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);

    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), st.mnstates(), mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    // Sanity: the fixed builder passes the emit re-derivation…
    dash::coin::DeclineReport why;
    // (viability preconditions like SML/qc are not armed in this bare
    // fixture; probe ONLY the split re-derivation by reproducing the
    // incident template: fold the operator output back into the owner's.)
    std::vector<PackedPayment> broken;
    uint64_t mn_total = 0;
    for (const auto& p : w.m_packed_payments) {
        if (p.payee == "!6a") { broken.push_back(p); continue; }
        mn_total += p.amount;
    }
    PackedPayment all_to_owner;
    all_to_owner.payee  = "XoDo3w4ZUqn93uL3FeRNb9fgfXvgg7BvDC";
    all_to_owner.amount = mn_total;                  // the h=2516595 coinbase
    broken.push_back(all_to_owner);
    DashWorkData incident = w;
    incident.m_packed_payments = broken;

    EXPECT_FALSE(st.embedded_template_emit_ok(incident, &why));
    EXPECT_EQ(why.cause, std::string("emit-mn-payout-split-drift"));
}

// ════════════════════════════════════════════════════════════════════════
// (d) ResetOperatorFields mirror — the stale operator script goes with the key
// ════════════════════════════════════════════════════════════════════════

static MutableTransaction protx_tx(uint16_t type,
                                   const std::vector<unsigned char>& payload) {
    MutableTransaction tx;
    tx.version = 3;
    tx.type = type;
    tx.extra_payload = payload;
    // A non-empty vin/vout so the tx is structurally a spend, not a
    // coinbase (pass 1 walks i>=1; the test block provides a coinbase).
    ::bitcoin_family::coin::TxIn in;
    in.prevout.hash = raw256(0x77);
    in.prevout.index = 0;
    in.sequence = 0xffffffffu;
    tx.vin.push_back(in);
    return tx;
}

static dash::coin::BlockType block_with(uint32_t /*height*/,
                                        std::vector<MutableTransaction> txs,
                                        const std::vector<unsigned char>& cb_payee,
                                        int64_t cb_value) {
    dash::coin::BlockType b;
    MutableTransaction cb;
    cb.version = 3;
    cb.type = 5;   // CbTx
    ::bitcoin_family::coin::TxOut o;
    o.value = cb_value;
    o.scriptPubKey.m_data = cb_payee;
    cb.vout.push_back(o);
    b.m_txs.push_back(cb);
    for (auto& t : txs) b.m_txs.push_back(std::move(t));
    return b;
}

TEST(DashOperatorSplit, ProUpRegTxOperatorKeyChangeClearsOperatorPayout) {
    // Seed one MN with a proven split, cursor at 999.
    MNState s = split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}},
           /*as_of_height=*/999);

    // ProUpRegTx changing the operator BLS key.
    dash::coin::vendor::CProUpRegTx up;
    up.proTxHash = raw256(0x01);
    for (size_t i = 0; i < up.pubKeyOperator.size(); ++i)
        up.pubKeyOperator[i] = static_cast<uint8_t>(0xC0 + i);   // != seeded
    up.scriptPayout.m_data = K_OWNER_SCRIPT;
    auto ps = ::pack(up);
    auto sp = ps.get_span();
    std::vector<unsigned char> payload(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());

    auto blk = block_with(1000, {protx_tx(3, payload)}, K_OWNER_SCRIPT,
                          /*cb_value=*/100'000'000);
    auto r = m.apply_block(blk, 1000);
    ASSERT_FALSE(r.skipped_out_of_order);

    const auto& st2 = m.entries().at(raw256(0x01));
    // dashcore dmnstate.h ResetOperatorFields: scriptOperatorPayout,
    // addr(netInfo), platformNodeID cleared; MN PoSe-banned until the new
    // operator revives it. bps itself is immutable → split stays PROVEN.
    EXPECT_TRUE(st2.scriptOperatorPayout.m_data.empty())
        << "the OLD operator's payout script must go with the old key — "
           "keeping it pays a script dashd no longer pays (bad-cb-payee)";
    EXPECT_FALSE(st2.isValid);
    EXPECT_EQ(st2.payoutSplitProvenance, MNState::SPLIT_KNOWN);
    EXPECT_EQ(st2.operator_payment_of(K_MN_SHARE), 0)
        << "post-reset the payout set is single-owner";
}

TEST(DashOperatorSplit, ProUpRevTxClearsOperatorPayout) {
    MNState s = split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}},
           /*as_of_height=*/999);

    dash::coin::vendor::CProUpRevTx rev;
    rev.proTxHash = raw256(0x01);
    rev.nReason = 1;   // termination of service
    auto ps = ::pack(rev);
    auto sp = ps.get_span();
    std::vector<unsigned char> payload(
        reinterpret_cast<const unsigned char*>(sp.data()),
        reinterpret_cast<const unsigned char*>(sp.data()) + sp.size());

    auto blk = block_with(1000, {protx_tx(4, payload)}, K_OWNER_SCRIPT,
                          100'000'000);
    auto r = m.apply_block(blk, 1000);
    ASSERT_FALSE(r.skipped_out_of_order);

    const auto& st2 = m.entries().at(raw256(0x01));
    EXPECT_TRUE(st2.scriptOperatorPayout.m_data.empty());
    EXPECT_FALSE(st2.isValid);
    EXPECT_EQ(st2.operator_payment_of(K_MN_SHARE), 0);
}

// ════════════════════════════════════════════════════════════════════════
// Pass-3 observation: the canonical coinbase proves / falsifies the split
// ════════════════════════════════════════════════════════════════════════

static dash::coin::BlockType coinbase_only_block(
    std::vector<std::pair<std::vector<unsigned char>, int64_t>> outs) {
    dash::coin::BlockType b;
    MutableTransaction cb;
    cb.version = 3;
    cb.type = 5;
    for (auto& [script, value] : outs) {
        ::bitcoin_family::coin::TxOut o;
        o.value = value;
        o.scriptPubKey.m_data = script;
        cb.vout.push_back(o);
    }
    b.m_txs.push_back(cb);
    return b;
}

TEST(DashOperatorSplit, Pass3AdoptsSplitFromObservedCanonicalPayout) {
    // Provenance UNKNOWN (filtered-seed shape: bps absent → 0).
    MNState s = split_mn(0, K_OWNER_SCRIPT, {}, MNState::SPLIT_UNKNOWN);
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}},
           /*as_of_height=*/999);

    // The canonical h=2516595 payout shape: owner + operator outputs.
    auto blk = coinbase_only_block({{K_OWNER_SCRIPT, K_OWNER_OUT},
                                    {K_OPER_SCRIPT, K_OPER_OUT}});
    auto r = m.apply_block(blk, 1000);
    ASSERT_EQ(r.paid, 1u);
    EXPECT_EQ(r.split_adopted, 1u);

    const auto& st2 = m.entries().at(raw256(0x01));
    EXPECT_EQ(st2.payoutSplitProvenance, MNState::SPLIT_KNOWN);
    // bps uniquely determined: ceil(6'644'635 * 10000 / 83'057'939) = 800,
    // floor-verified against dashd's truncating recomputation.
    EXPECT_EQ(st2.nOperatorReward, K_BPS);
    EXPECT_EQ(st2.scriptOperatorPayout.m_data, K_OPER_SCRIPT);
    EXPECT_EQ(st2.operator_payment_of(K_MN_SHARE), K_OPER_OUT);
}

TEST(DashOperatorSplit, Pass3DemotesContradictedSplit) {
    // Proven split... that the network no longer pays (stale knowledge —
    // e.g. a pre-anchor ProUpServTx we never saw). Single-owner coinbase.
    MNState s = split_mn(K_BPS, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{raw256(0x01), s}},
           /*as_of_height=*/999);

    auto blk = coinbase_only_block({{K_OWNER_SCRIPT, K_MN_SHARE}});
    auto r = m.apply_block(blk, 1000);
    ASSERT_EQ(r.paid, 1u);
    EXPECT_EQ(r.split_desync, 1u);
    EXPECT_EQ(m.entries().at(raw256(0x01)).payoutSplitProvenance,
              MNState::SPLIT_UNKNOWN)
        << "a contradicted split must fail closed (refused when scheduled) "
           "until re-proven";
}

// ════════════════════════════════════════════════════════════════════════
// nOperatorReward == 10000 — the 2026-10-28 mn-payout-split-unprovable
// incident. dashd masternode/payments.cpp:65-79 (v23.1.7):
//
//     operatorReward = 0;
//     if (nOperatorReward != 0 && scriptOperatorPayout != CScript()) {
//         operatorReward    = (masternodeReward * nOperatorReward) / 10000;
//         masternodeReward -= operatorReward;
//     }
//     if (masternodeReward > 0) emplace_back(masternodeReward, scriptPayout);
//     if (operatorReward  > 0) emplace_back(operatorReward,  scriptOperatorPayout);
//
// With bps == 10000 the owner remainder is exactly 0, so dashd pays ONE MN
// output — to scriptOperatorPayout, for the whole share — and NO owner
// output. The mainnet anchor (h=2549400) carries four such rows, all with the
// operator script equal to the owner script; pass 3 demanded a second
// (operator) output beside the owner one, demoted each of them to
// SPLIT_UNKNOWN on its first payment after the anchor, and the serve gate
// then refused every height one of them was scheduled for
// (cause=mn-payout-split-unprovable, ~3 consecutive heights per pass).
// ════════════════════════════════════════════════════════════════════════

// Ground truth: mainnet block 2549648
// (000000000000000f15fc1efb1f7b27980177c4d6eeaa324ca5429158b8429c93), coinbase
// txid 7006d78d9d4467bb1b716f3e89ee490305c37908937616592eca36c785da2259,
// outputs [miner, OP_RETURN credit-pool burn, MN] — the MN output pays
// proTx 47676550eca46ed6… (bps=10000, operator script == owner script).
static constexpr int64_t K_2549648_MINER = 41'095'669;
static constexpr int64_t K_2549648_BURN  = 46'231'323;
static constexpr int64_t K_2549648_MN    = 77'055'682;
static const char* const K_2549648_COINBASE_HEX =
    "03000500010000000000000000000000000000000000000000000000000000000000000000"
    "ffffffff300390e7261a2f5669614254432f4d696e65642062792077753030303531372f10"
    "a56265006f5fb17bb0f94066ce130000ffffffff03f5117302000000001976a914bc89d607"
    "1dabc5b4494d303af761a052a5c70d5788ac1b6fc10200000000016ac2c697040000000019"
    "76a914d16529b809097990baa10d3a0daa60efaede895f88ac00000000af030090e726007e"
    "31bbcfafb05e582f121424b6677a9b89299c1d1d9522d772de816cd11e84844b9c21bf9b2c"
    "56a5f367b3587259c91bb43018c5231312ad0d4b2ac397dcc67201874b48ffc429aab3bd53"
    "05e9b218465359a5b0543a43797fe07b260815b6092ca282e5c6e7e3e0d1cc0fd5f0195220"
    "7d02412f0f624f47c3fd5308a5388f0cec2eb93687197bded1c91385888660a2bc5217261d"
    "b23e3cc46c7721a37bf54b10996a017295030000";
static const char* const K_2549648_COINBASE_TXID =
    "7006d78d9d4467bb1b716f3e89ee490305c37908937616592eca36c785da2259";
static const char* const K_FULLOP_PROTX =
    "47676550eca46ed65b0565da7239c3439b1d6900a0c4562effd551a094bbbe5f";
static const char* const K_FULLOP_ADDR = "Xun2FGjJHPYBrcrG582D4yQq4ZW4Z42WVZ";

static std::vector<unsigned char> hex_bytes(const std::string& h) {
    std::vector<unsigned char> v;
    v.reserve(h.size() / 2);
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>(
            std::stoul(h.substr(i, 2), nullptr, 16)));
    return v;
}

// 76a914 d16529b8…895f 88ac — the single script of the full-operator MN paid
// at 2549648 (owner and operator alike).
static const std::vector<unsigned char> K_FULLOP_SCRIPT =
    hex_bytes("76a914d16529b809097990baa10d3a0daa60efaede895f88ac");
// 76a914 bc89d607…0d57 88ac — the 2549648 miner output.
static const std::vector<unsigned char> K_MINER_SCRIPT =
    hex_bytes("76a914bc89d6071dabc5b4494d303af761a052a5c70d5788ac");

// A mainnet-shaped coinbase: the MN outputs PLUS the platform credit-pool
// burn (OP_RETURN) and a miner output, rotated by `rot` so no check can lean
// on output order (2549648 = [miner, OP_RETURN, MN];
// 2562669 = [OP_RETURN, MN, miner]). coinbase_only_block() has no miner
// output, which is what let the adoption KAT above pass while adoption is
// dead on every real coinbase.
static dash::coin::BlockType mainnet_shaped_block(
    const std::vector<unsigned char>& miner_script, int64_t miner_value,
    std::vector<std::pair<std::vector<unsigned char>, int64_t>> mn_outs,
    size_t rot = 0) {
    std::vector<std::pair<std::vector<unsigned char>, int64_t>> outs;
    outs.emplace_back(miner_script, miner_value);
    outs.emplace_back(std::vector<unsigned char>{0x6a}, K_2549648_BURN);
    for (auto& o : mn_outs) outs.push_back(std::move(o));
    std::rotate(outs.begin(),
                outs.begin() + static_cast<std::ptrdiff_t>(rot % outs.size()),
                outs.end());
    return coinbase_only_block(std::move(outs));
}

// (a) THE INCIDENT: bps=10000, operator script == owner script. The block
// pays that script ONCE, for the whole share. That is dashd's exact output
// set — consistent, no demotion.
TEST(DashOperatorSplit, Pass3FullOperatorSplitSameScriptSingleOutputIsConsistent) {
    for (size_t rot = 0; rot < 3; ++rot) {
        MnStateMachine m;
        m.load(std::vector<std::pair<uint256, MNState>>{
                   {raw256(0x01),
                    split_mn(10000, K_FULLOP_SCRIPT, K_FULLOP_SCRIPT)}},
               /*as_of_height=*/999);
        auto blk = mainnet_shaped_block(K_MINER_SCRIPT, K_2549648_MINER,
                                        {{K_FULLOP_SCRIPT, K_2549648_MN}}, rot);
        auto r = m.apply_block(blk, 1000);
        EXPECT_EQ(r.paid, 1u) << "rot=" << rot;
        EXPECT_FALSE(r.payee_desync) << "rot=" << rot;
        EXPECT_EQ(r.split_desync, 0u)
            << "rot=" << rot << ": dashd pays a bps=10000 masternode ONE output"
               " (payments.cpp:74 skips the zero owner remainder); demanding a"
               " second one is the 2026-10-28 false demotion";
        const auto& st = m.entries().at(raw256(0x01));
        EXPECT_EQ(st.payoutSplitProvenance, MNState::SPLIT_KNOWN) << "rot=" << rot;
        EXPECT_EQ(st.nLastPaidHeight, 1000u) << "rot=" << rot;
        EXPECT_EQ(st.nOperatorReward, 10000);
        EXPECT_EQ(st.scriptOperatorPayout.m_data, K_FULLOP_SCRIPT);
    }
}

// (b) bps=10000 with a DISTINCT operator script: the coinbase pays ONLY the
// operator script. That must be read as "the projected masternode was paid"
// (not a payee desync), with a consistent split. And the converse — a block
// paying only the OWNER script — is NOT what dashd pays for this state: the
// cross-check is exact script equality, never "any script of this MN".
TEST(DashOperatorSplit, Pass3FullOperatorSplitDistinctScriptPaysOperatorOnly) {
    for (size_t rot = 0; rot < 3; ++rot) {
        MnStateMachine m;
        m.load(std::vector<std::pair<uint256, MNState>>{
                   {raw256(0x01),
                    split_mn(10000, K_OWNER_SCRIPT, K_OPER_SCRIPT)}},
               /*as_of_height=*/999);
        auto blk = mainnet_shaped_block(K_MINER_SCRIPT, K_2549648_MINER,
                                        {{K_OPER_SCRIPT, K_2549648_MN}}, rot);
        auto r = m.apply_block(blk, 1000);
        EXPECT_FALSE(r.payee_desync)
            << "rot=" << rot << ": the coinbase pays exactly the output dashd"
               " derives for this masternode (operator script, whole share)";
        EXPECT_EQ(r.paid, 1u) << "rot=" << rot;
        EXPECT_EQ(r.split_desync, 0u) << "rot=" << rot;
        const auto& st = m.entries().at(raw256(0x01));
        EXPECT_EQ(st.payoutSplitProvenance, MNState::SPLIT_KNOWN) << "rot=" << rot;
        EXPECT_EQ(st.nLastPaidHeight, 1000u) << "rot=" << rot;
    }
    // Converse: owner-only payment of a full-operator state is not dashd's
    // output set → payee desync, nothing attributed.
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{
               {raw256(0x01), split_mn(10000, K_OWNER_SCRIPT, K_OPER_SCRIPT)}},
           /*as_of_height=*/999);
    auto blk = mainnet_shaped_block(K_MINER_SCRIPT, K_2549648_MINER,
                                    {{K_OWNER_SCRIPT, K_2549648_MN}});
    auto r = m.apply_block(blk, 1000);
    EXPECT_TRUE(r.payee_desync)
        << "an owner-only coinbase cannot have been built by dashd from a"
           " bps=10000 state with an operator script";
    EXPECT_EQ(r.paid, 0u);
}

// (b') the SML ban-recovery walk accepts a runner-up by the SAME rule: a
// full-operator runner-up is "paid" when the coinbase carries its operator
// script (walk_to_paid_candidate).
TEST(DashOperatorSplit, SmlBanRecoveryAcceptsFullOperatorRunnerUp) {
    const std::vector<unsigned char> head_script =
        hex_bytes("76a914000102030405060708090a0b0c0d0e0f1011121388ac");
    MNState a = split_mn(0, head_script, {});
    a.nLastPaidHeight = 2'300'001;                 // head of the queue
    MNState b = split_mn(10000, K_OWNER_SCRIPT, K_OPER_SCRIPT);
    b.nLastPaidHeight = 2'300'002;                 // runner-up
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{
               {raw256(0x01), a}, {raw256(0x02), b}},
           /*as_of_height=*/2'300'010);
    const uint256 ha = raw256(0x01), hb = raw256(0x02);
    m.set_sml_validity_fn([ha, hb](const uint256& h) -> std::optional<bool> {
        if (h == ha) return false;     // head attested PoSe-banned
        if (h == hb) return true;
        return std::nullopt;
    });
    m.set_sml_recovery_cap(4);

    auto blk = mainnet_shaped_block(K_MINER_SCRIPT, K_2549648_MINER,
                                    {{K_OPER_SCRIPT, K_2549648_MN}});
    auto r = m.apply_block(blk, 2'300'011);
    ASSERT_TRUE(r.projected_payee.has_value());
    EXPECT_EQ(*r.projected_payee, ha);
    EXPECT_FALSE(r.payee_desync)
        << "the runner-up's operator script IS the output dashd pays it";
    EXPECT_EQ(r.paid, 1u);
    EXPECT_EQ(r.sml_recovered, 1u);
    EXPECT_EQ(m.entries().at(hb).nLastPaidHeight, 2'300'011u);
    EXPECT_FALSE(m.entries().at(ha).isValid);
}

// (c) builder pin, same-script sibling of
// BuilderFullOperatorSplitOmitsZeroOwnerOutput: exactly ONE MN packed
// payment, to the shared script, for the whole share.
TEST(DashOperatorSplit, BuilderFullOperatorSplitSameScriptSingleOutput) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);

    auto mnstates =
        machine_with(split_mn(10000, K_FULLOP_SCRIPT, K_FULLOP_SCRIPT));
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);

    const auto mn_outs = mn_payments(w);
    ASSERT_EQ(mn_outs.size(), 1u)
        << "dashd emits no zero-value owner output (payments.cpp:74)";
    EXPECT_EQ(mn_outs[0].payee, K_FULLOP_ADDR);
    EXPECT_EQ(mn_outs[0].amount, w.m_payment_amount);
    ASSERT_GT(w.m_payment_amount, 0u);
}

// (c) the pre-emit structural re-derivation must ACCEPT the correct
// full-operator template. Before the fix it demanded an owner output of
// amount 0 (owner=0-MISSING) — the next starvation once (a) was fixed.
TEST(DashOperatorSplit, EmitGateAcceptsFullOperatorSplitTemplate) {
    struct Case { const char* name; std::vector<unsigned char> owner, oper; };
    const std::vector<Case> cases = {
        {"same-script", K_FULLOP_SCRIPT, K_FULLOP_SCRIPT},
        {"distinct-script", K_OWNER_SCRIPT, K_OPER_SCRIPT},
    };
    for (const auto& c : cases) {
        NodeCoinState st;
        st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
                               {raw256(0x01), split_mn(10000, c.owner, c.oper)}},
                           H - 1);
        arm_emit_gate(st, raw256(0xAB));
        st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
                   DASH_PUBKEY_VER, DASH_P2SH_VER);

        UTXOViewCache utxo(nullptr);
        Mempool mp;
        mp.set_utxo(&utxo);
        auto w = build_embedded_workdata(
            H - 1, raw256(0xAB), st.mnstates(), mp,
            0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);
        ASSERT_EQ(mn_payments(w).size(), 1u) << c.name;
        // Commit the armed SML/quorum roots so the split re-derivation is the
        // only thing this template could fail on.
        w.m_coinbase_payload = dash::coin::encode_cbtx(
            dash::coin::build_embedded_cbtx(H - 1, st.sml(), st.qmgr(), 0,
                                            dash::coin::k_zero_cl_sig, 0,
                                            nullptr));

        dash::coin::DeclineReport why;
        const bool ok = st.embedded_template_emit_ok(w, &why);
        EXPECT_NE(why.cause, std::string("emit-mn-payout-split-drift"))
            << c.name << ": value=" << why.value
            << " — dashd emits no owner output when the owner remainder is 0";
        EXPECT_NE(why.cause, std::string("emit-mn-payout-split-unprovable"))
            << c.name;
        EXPECT_TRUE(ok) << c.name << ": cause=" << why.cause
                        << " value=" << why.value;
    }

    // The gate still bites on a full-operator template that LOST its
    // operator output (the operator amount stays mandatory).
    NodeCoinState st;
    st.mnstates().load(std::vector<std::pair<uint256, MNState>>{
                           {raw256(0x01),
                            split_mn(10000, K_OWNER_SCRIPT, K_OPER_SCRIPT)}},
                       H - 1);
    arm_emit_gate(st, raw256(0xAB));
    st.set_tip(H - 1, raw256(0xAB), 0x1b104be3u, 1'700'000'000u,
               DASH_PUBKEY_VER, DASH_P2SH_VER);
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), st.mnstates(), mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);
    std::vector<PackedPayment> burn_only;
    for (const auto& p : w.m_packed_payments)
        if (p.payee == "!6a") burn_only.push_back(p);
    DashWorkData lost = w;
    lost.m_packed_payments = burn_only;
    dash::coin::DeclineReport why;
    EXPECT_FALSE(st.embedded_template_emit_ok(lost, &why));
    EXPECT_EQ(why.cause, std::string("emit-mn-payout-split-drift"));
    EXPECT_NE(why.value.find("operator=" + std::to_string(w.m_payment_amount)
                             + "-MISSING"),
              std::string::npos)
        << why.value;
}

// (d) the floor-zero edge: floor(share * bps / 10000) == 0 → dashd emits NO
// operator output (payments.cpp:77) and the owner output carries the whole
// share. Unreachable at today's reward; pinned so a falling subsidy cannot
// turn it into a false demotion — and the pair check must not loosen.
TEST(DashOperatorSplit, OperatorFloorZeroEdge) {
    // Builder: a far-future height where the MN share itself is < 10000
    // duffs, so bps=1 floors the operator amount to 0.
    {
        constexpr uint32_t kFarH = 28'000'000;
        const int64_t reward   = compute_dash_block_reward_post_v20(kFarH);
        const int64_t platform = compute_dash_platform_reward_post_v20_mn_rr(kFarH);
        const int64_t share    = compute_dash_mn_payment_post_v20(reward) - platform;
        ASSERT_GT(share, 0);
        ASSERT_LT(share, 10'000) << "kFarH no longer reaches the floor-zero edge";
        MNState s = split_mn(1, K_OWNER_SCRIPT, K_OPER_SCRIPT);
        ASSERT_EQ(s.operator_payment_of(share), 0);

        UTXOViewCache utxo(nullptr);
        Mempool mp;
        mp.set_utxo(&utxo);
        auto mnstates = machine_with(s);
        auto w = build_embedded_workdata(
            kFarH - 1, raw256(0xAB), mnstates, mp,
            0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);
        ASSERT_EQ(w.m_payment_amount, static_cast<uint64_t>(share));
        const auto mn_outs = mn_payments(w);
        ASSERT_EQ(mn_outs.size(), 1u)
            << "an operator amount that floors to 0 emits no operator output";
        EXPECT_EQ(mn_outs[0].payee, "XoDo3w4ZUqn93uL3FeRNb9fgfXvgg7BvDC");
        EXPECT_EQ(mn_outs[0].amount, static_cast<uint64_t>(share));
    }
    // Detector: KNOWN bps=1, coinbase pays the owner 9'999 duffs only —
    // dashd's exact set for that share. Distinct and shared scripts alike.
    struct Case { const char* name; std::vector<unsigned char> owner, oper; };
    const std::vector<Case> cases = {
        {"distinct-script", K_OWNER_SCRIPT, K_OPER_SCRIPT},
        {"same-script", K_OWNER_SCRIPT, K_OWNER_SCRIPT},
    };
    for (const auto& c : cases) {
        MnStateMachine m;
        m.load(std::vector<std::pair<uint256, MNState>>{
                   {raw256(0x01), split_mn(1, c.owner, c.oper)}},
               /*as_of_height=*/999);
        auto blk = mainnet_shaped_block(K_MINER_SCRIPT, K_2549648_MINER,
                                        {{c.owner, 9'999}}, 1);
        auto r = m.apply_block(blk, 1000);
        EXPECT_EQ(r.paid, 1u) << c.name;
        EXPECT_EQ(r.split_desync, 0u)
            << c.name << ": floor(9999 * 1 / 10000) == 0 — dashd pays no"
               " operator output, so its absence is not a desync";
        EXPECT_EQ(m.entries().at(raw256(0x01)).payoutSplitProvenance,
                  MNState::SPLIT_KNOWN) << c.name;
    }
    // ...and NOT loosened: one duff more (10'000 → operator amount 1 due) with
    // no operator output is still a contradicted split.
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{
               {raw256(0x01), split_mn(1, K_OWNER_SCRIPT, K_OPER_SCRIPT)}},
           /*as_of_height=*/999);
    auto blk = mainnet_shaped_block(K_MINER_SCRIPT, K_2549648_MINER,
                                    {{K_OWNER_SCRIPT, 10'000}}, 1);
    auto r = m.apply_block(blk, 1000);
    EXPECT_EQ(r.paid, 1u);
    EXPECT_EQ(r.split_desync, 1u)
        << "floor(10000 * 1 / 10000) == 1: an operator output was due";
    EXPECT_EQ(m.entries().at(raw256(0x01)).payoutSplitProvenance,
              MNState::SPLIT_UNKNOWN);
}

// (e) REAL BYTES: the dashd-accepted coinbase of mainnet block 2549648,
// against the SHIPPED anchor's own row for the masternode it paid.
namespace {
const char* const kShippedMainnetAnchorForSplit =
#include <impl/dash/coin/checkpoints/dash_mn_checkpoint_mainnet.inc>
    ;
}  // namespace

TEST(DashOperatorSplit, RealBytesH2549648Coinbase) {
    // The coinbase, byte-exact, round-trips to its on-chain txid.
    MutableTransaction cb;
    {
        auto raw = hex_bytes(K_2549648_COINBASE_HEX);
        ::PackStream ps(raw);
        ps >> cb;
    }
    ASSERT_EQ(dash::coin::dash_txid(cb), uint256S(K_2549648_COINBASE_TXID));
    ASSERT_EQ(cb.type, 5);
    ASSERT_EQ(cb.vout.size(), 3u);
    EXPECT_EQ(cb.vout[0].value, K_2549648_MINER);
    EXPECT_EQ(cb.vout[1].value, K_2549648_BURN);
    EXPECT_EQ(cb.vout[2].value, K_2549648_MN);
    EXPECT_EQ(cb.vout[2].scriptPubKey.m_data, K_FULLOP_SCRIPT);

    // The shipped anchor's row for the masternode this block paid.
    auto cp = dash::coin::parse_mn_checkpoint(kShippedMainnetAnchorForSplit,
                                              "mainnet");
    ASSERT_TRUE(cp.ok) << cp.error;
    const uint256 protx = uint256S(K_FULLOP_PROTX);
    std::optional<MNState> row;
    size_t full_operator_rows = 0;
    for (const auto& [h, st] : cp.entries) {
        if (h == protx) row = st;
        if (st.nOperatorReward == 10000) ++full_operator_rows;
    }
    ASSERT_TRUE(row.has_value()) << "anchor h=" << cp.height
                                 << " no longer carries " << K_FULLOP_PROTX;
    ASSERT_EQ(row->nOperatorReward, 10000);
    ASSERT_EQ(row->scriptPayout.m_data, K_FULLOP_SCRIPT);
    ASSERT_EQ(row->scriptOperatorPayout.m_data, K_FULLOP_SCRIPT);
    ASSERT_EQ(row->payoutSplitProvenance, MNState::SPLIT_KNOWN);
    ASSERT_TRUE(row->isValid);
    EXPECT_GE(full_operator_rows, 1u);

    // dashd's arithmetic on the real share: the operator takes all of it.
    EXPECT_EQ(row->operator_payment_of(K_2549648_MN), K_2549648_MN);
    EXPECT_EQ(K_2549648_MN - row->operator_payment_of(K_2549648_MN), 0);

    // Pass 3 on the real coinbase: paid, consistent, still KNOWN.
    dash::coin::BlockType blk;
    blk.m_txs.push_back(cb);
    MnStateMachine m;
    m.load(std::vector<std::pair<uint256, MNState>>{{protx, *row}},
           /*as_of_height=*/2'549'647);
    auto r = m.apply_block(blk, 2'549'648);
    ASSERT_TRUE(r.projected_payee.has_value());
    EXPECT_EQ(*r.projected_payee, protx);
    EXPECT_FALSE(r.payee_desync);
    EXPECT_EQ(r.paid, 1u);
    EXPECT_EQ(r.split_desync, 0u)
        << "the real 2549648 coinbase is dashd's exact output set for this"
           " masternode; demoting it is the 2026-10-28 incident";
    EXPECT_EQ(m.entries().at(protx).payoutSplitProvenance, MNState::SPLIT_KNOWN);
    EXPECT_EQ(m.entries().at(protx).nLastPaidHeight, 2'549'648u);

    // The builder, from the same row, emits the same single output.
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    MnStateMachine bm;
    bm.load(std::vector<std::pair<uint256, MNState>>{{protx, *row}},
            2'549'647);
    auto w = build_embedded_workdata(
        2'549'647, raw256(0xAB), bm, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);
    const auto mn_outs = mn_payments(w);
    ASSERT_EQ(mn_outs.size(), 1u);
    EXPECT_EQ(mn_outs[0].payee, K_FULLOP_ADDR);
    EXPECT_EQ(mn_outs[0].amount, w.m_payment_amount);
}

// (g) pins. Adoption is NOT a recovery path on mainnet: every real coinbase
// pays a miner too, so an UNKNOWN entry is never re-proven by it.
TEST(DashOperatorSplit, Pass3MainnetShapedCoinbaseNeverAdopts) {
    for (size_t rot = 0; rot < 3; ++rot) {
        MnStateMachine m;
        m.load(std::vector<std::pair<uint256, MNState>>{
                   {raw256(0x01),
                    split_mn(10000, K_FULLOP_SCRIPT, K_FULLOP_SCRIPT,
                             MNState::SPLIT_UNKNOWN)}},
               /*as_of_height=*/999);
        auto blk = mainnet_shaped_block(K_MINER_SCRIPT, K_2549648_MINER,
                                        {{K_FULLOP_SCRIPT, K_2549648_MN}}, rot);
        auto r = m.apply_block(blk, 1000);
        EXPECT_EQ(r.paid, 1u) << "rot=" << rot;
        EXPECT_EQ(r.split_adopted, 0u) << "rot=" << rot;
        const auto& st = m.entries().at(raw256(0x01));
        EXPECT_EQ(st.payoutSplitProvenance, MNState::SPLIT_UNKNOWN) << "rot=" << rot;
        EXPECT_EQ(st.nOperatorReward, 10000) << "rot=" << rot;
        EXPECT_EQ(st.scriptOperatorPayout.m_data, K_FULLOP_SCRIPT) << "rot=" << rot;
    }
}

// (g) dashd emits TWO outputs with the same script for a partial split whose
// operator script equals the owner script — nothing downstream may coalesce
// them.
TEST(DashOperatorSplit, BuilderSameScriptPartialSplitEmitsTwoOutputs) {
    UTXOViewCache utxo(nullptr);
    Mempool mp;
    mp.set_utxo(&utxo);
    auto mnstates = machine_with(split_mn(K_BPS, K_FULLOP_SCRIPT, K_FULLOP_SCRIPT));
    auto w = build_embedded_workdata(
        H - 1, raw256(0xAB), mnstates, mp,
        0x1b104be3u, 1'700'000'000u, DASH_PUBKEY_VER, DASH_P2SH_VER);
    const int64_t mn_payment = static_cast<int64_t>(w.m_payment_amount);
    const int64_t op_due = (mn_payment * K_BPS) / 10000;
    const auto mn_outs = mn_payments(w);
    ASSERT_EQ(mn_outs.size(), 2u);
    EXPECT_EQ(mn_outs[0].payee, K_FULLOP_ADDR);
    EXPECT_EQ(mn_outs[1].payee, K_FULLOP_ADDR);
    EXPECT_EQ(mn_outs[0].amount, static_cast<uint64_t>(mn_payment - op_due));
    EXPECT_EQ(mn_outs[1].amount, static_cast<uint64_t>(op_due));
}

// ════════════════════════════════════════════════════════════════════════
// Parity surface: the shadow field digests the full payout SET, fee-invariant
// ════════════════════════════════════════════════════════════════════════

TEST(DashOperatorSplit, ShadowSplitShapeIsFeeInvariant) {
    using dash::coin::mn_payout_split_shape_str;
    // Same MN, same split, DIFFERENT fee totals on the two sides (embedded
    // vs dashd selected different tx sets) — the shape must be EQUAL.
    auto side = [](int64_t mn_share) {
        std::vector<PackedPayment> pps;
        PackedPayment burn;  burn.payee = "!6a"; burn.amount = 1'000;
        PackedPayment owner; owner.payee = "Xowner";
        PackedPayment oper;  oper.payee = "Xoper";
        const int64_t op = (mn_share * K_BPS) / 10000;
        owner.amount = static_cast<uint64_t>(mn_share - op);
        oper.amount  = static_cast<uint64_t>(op);
        pps.push_back(burn); pps.push_back(owner); pps.push_back(oper);
        return pps;
    };
    const auto a = mn_payout_split_shape_str(side(K_MN_SHARE));       // canonical fees
    const auto b = mn_payout_split_shape_str(side(82'979'299));       // OUR fees (incident)
    EXPECT_EQ(a, b);
    EXPECT_EQ(a, "n=2;owner=Xowner;operator=Xoper;bps=800");
    // And the h=2516595 defect shape (owner-only) is DIFFERENT — the
    // owner-address-only compare could never see this.
    std::vector<PackedPayment> defect;
    PackedPayment owner_all; owner_all.payee = "Xowner";
    owner_all.amount = static_cast<uint64_t>(K_MN_SHARE);
    defect.push_back(owner_all);
    EXPECT_NE(mn_payout_split_shape_str(defect), a);
}
